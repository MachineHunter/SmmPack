#include "SmmPackImpl.h"


/**
 
 This function sets requestUse bit of TPM_ACCESS_x register (TPM_ACCESS_x[1]).
 Just a wrapper function that calls the function defined in Tpm2DeviceLib

**/
EFI_STATUS
TpmRequestUse (
    VOID
    )
{
  return Tpm2RequestUseTpm();
}



/**
 
 This function starts Policy session of TPM.
 sessionHandle needs to be specified in each command related to this session.
 
 @param[out]  sessionHandle  Returns a handle for this session
 
**/
EFI_STATUS
TpmStartAuthSession (
    OUT TPM_HANDLE *sessionHandle
    )
{
  EFI_STATUS                     Status;
  UINT16                         res;
  TPM2_STARTAUTHSESSION_COMMAND  CmdBuffer;
  UINT32                         CmdBufferSize;
  TPM2_STARTAUTHSESSION_RESPONSE RecvBuffer;
  UINT32                         RecvBufferSize;

  ORIG_TPM2B_NONCE nonceCaller;
  nonceCaller.size = SwapBytes16(20);
  ORIG_TPMT_SYM_DEF symmetric;
  symmetric.algorithmNull = SwapBytes16(TPM_ALG_NULL);

  // set send parameters
  CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_NO_SESSIONS);
  CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_StartAuthSession);
  CmdBuffer.tpmKey             = SwapBytes32(TPM_RH_NULL);
  CmdBuffer.bind               = SwapBytes32(TPM_RH_NULL);
  CmdBuffer.nonceCaller        = nonceCaller;
  CmdBuffer.encryptedSaltZero  = SwapBytes16(0);
  CmdBuffer.sessionType        = TPM_SE_POLICY;
  CmdBuffer.symmetric          = symmetric;
  CmdBuffer.authHash           = SwapBytes16(TPM_ALG_SHA256);
  CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.tpmKey) + sizeof(CmdBuffer.bind) + sizeof(CmdBuffer.nonceCaller) + sizeof(CmdBuffer.encryptedSaltZero) + sizeof(CmdBuffer.sessionType) + sizeof(CmdBuffer.symmetric) + sizeof(CmdBuffer.authHash);
  CmdBuffer.Header.paramSize = SwapBytes32(CmdBufferSize);

  // send TPM command
  RecvBufferSize = sizeof(RecvBuffer);
  Status = Tpm2SubmitCommand(
      CmdBufferSize,
      (UINT8*)&CmdBuffer,
      &RecvBufferSize,
      (UINT8*)&RecvBuffer
      );
  if(EFI_ERROR(Status)) {
    return Status;
  }
  
  // parse response
  res = SwapBytes32(RecvBuffer.Header.responseCode);
  if(res!=0) {
    return EFI_INVALID_PARAMETER;
  }

  *sessionHandle = SwapBytes32(RecvBuffer.sessionHandle);
  return EFI_SUCCESS;
}



/**
 
 This function reads pcr value specified.
 PCR bank is specified by AlgId because bank are seperated by the hash algorithm.
 PcrId is the index for PCR[PcrId]. PCRs are seperated by what types of info to store.
 Further information are explained in my article https://dev.to/machinehunter/reading-pcr-value-from-uefi-4a82.
 
 @param[in]   AlgId       Hash algorithm which specifies bank of PCR
 @param[in]   PcrId       PCR number to use (only one PCR can be read by this func)
 @param[out]  Digest      PCR value read
 @param[out]  DigestSize  Size of Digest
 
**/
EFI_STATUS
TpmPcrRead (
    IN  TPM_ALG_ID AlgId,
    IN  UINT32     PcrId,
    OUT BYTE       *Digest,
    OUT UINT16     *DigestSize
    )
{
  EFI_STATUS Status;
  UINT16     res;

  ORIG_TPML_PCR_SELECTION pcrSelectionIn;
  pcrSelectionIn.count                         = SwapBytes32(1);
  pcrSelectionIn.pcrSelections[0].hash         = SwapBytes16(AlgId);
  pcrSelectionIn.pcrSelections[0].sizeofSelect = PCR_SELECT_MIN;

  UINT32 i;
  for(i=0; i<PCR_SELECT_MIN; i++)
    pcrSelectionIn.pcrSelections[0].pcrSelect[i] = 0;

  UINT32 pcrId;
  for(pcrId=0; pcrId<PLATFORM_PCR; pcrId++) {
    if(pcrId==PcrId)
      pcrSelectionIn.pcrSelections[0].pcrSelect[pcrId/8] |= (1<<(pcrId%8));
  }

  TPM2_PCR_READ_COMMAND  CmdBuffer;
  UINT32                 CmdBufferSize;
  TPM2_PCR_READ_RESPONSE RecvBuffer;
  UINT32                 RecvBufferSize;

  CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_NO_SESSIONS);
  CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_PCR_Read);
  CmdBuffer.pcrSelectionIn     = pcrSelectionIn;
  CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.pcrSelectionIn);
  CmdBuffer.Header.paramSize = SwapBytes32(CmdBufferSize);

  RecvBufferSize = sizeof(RecvBuffer);
  Status = Tpm2SubmitCommand(
      CmdBufferSize,
      (UINT8*)&CmdBuffer,
      &RecvBufferSize,
      (UINT8*)&RecvBuffer
      );
  if(EFI_ERROR(Status)) {
    return Status;
  }
  
  // parse response
  res = SwapBytes32(RecvBuffer.Header.responseCode);
  if(res!=0) {
    return EFI_INVALID_PARAMETER;
  }

  UINT32 cntDigest = SwapBytes32(RecvBuffer.pcrValues.count);
  if(cntDigest!=1) {
    return EFI_ACCESS_DENIED;
  }

  TPM2B_DIGEST* digests = (TPM2B_DIGEST*)RecvBuffer.pcrValues.digests;
  *DigestSize = SwapBytes16(digests[0].size);
  CopyMem(Digest, digests[0].buffer, *DigestSize);

  return EFI_SUCCESS;
}



/**
 
 This function makes session require/use PCR evaluation.
 This requires PCR[PcrId] value of AlgId hash algorithm to match
 the value specified when sealing the key by SealKeyDxe.
 
 @param[in]   sessionHandle  Handle of the session made by StartAuthSession
 @param[in]   AlgId          Hash algorithm which specifies bank of PCR
 @param[in]   PcrId          PCR number to use (only one PCR can be read by this func)
 
**/
EFI_STATUS
TpmPolicyPCR (
    IN TPM_HANDLE *sessionHandle,
    IN TPM_ALG_ID AlgId,
    IN UINT32     PcrId
    )
{
  EFI_STATUS              Status;
  UINT16                  res;
  TPM2_POLICYPCR_COMMAND  CmdBuffer;
  UINT32                  CmdBufferSize;
  TPM2_POLICYPCR_RESPONSE RecvBuffer;
  UINT32                  RecvBufferSize;

  ORIG_TPML_PCR_SELECTION pcrs;
  pcrs.count                         = SwapBytes32(1);
  pcrs.pcrSelections[0].hash         = SwapBytes16(TPM_ALG_SHA256);
  pcrs.pcrSelections[0].sizeofSelect = PCR_SELECT_MIN;

  UINT32 i;
  for(i=0; i<PCR_SELECT_MIN; i++)
    pcrs.pcrSelections[0].pcrSelect[i] = 0;

  UINT32 pcrId;
  for(pcrId=0; pcrId<PLATFORM_PCR; pcrId++) {
    if(pcrId==PcrId)
      pcrs.pcrSelections[0].pcrSelect[pcrId/8] |= (1<<(pcrId%8));
  }

  // set send parameters
  CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_NO_SESSIONS);
  CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_PolicyPCR);
  CmdBuffer.policySession      = SwapBytes32(*sessionHandle);
  CmdBuffer.pcrDigestZero      = SwapBytes16(0);
  CmdBuffer.pcrs               = pcrs;
  CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.policySession) + sizeof(CmdBuffer.pcrDigestZero) + sizeof(CmdBuffer.pcrs);
  CmdBuffer.Header.paramSize = SwapBytes32(CmdBufferSize);

  // send TPM command
  RecvBufferSize = sizeof(RecvBuffer);
  Status = Tpm2SubmitCommand(
      CmdBufferSize,
      (UINT8*)&CmdBuffer,
      &RecvBufferSize,
      (UINT8*)&RecvBuffer
      );
  if(EFI_ERROR(Status)) {
    return Status;
  }
  
  // parse response
  res = SwapBytes32(RecvBuffer.Header.responseCode);
  if(res!=0) {
    /*return EFI_INVALID_PARAMETER;*/
    return res;
  }

  return EFI_SUCCESS;
}



/**
 
 This function reads key from TPM NV space.
 Authorization occurs at this timing comparing current PCR value selected by PolicyPCR
 and the value specified when Seal (SealKeyDxe).
 
 @param[in]   KeyNvIndex     Index of TPM NV space where key is stored
 @param[in]   KeyLength      Size to read from KeyNvIndex which will be the size of the key
 @param[in]   sessionHandle  Handle of the session made by StartAuthSession
 @param[out]  Key            Returns key value read from TPM (byte swapped inside this func)
 
**/
EFI_STATUS
TpmNVRead (
    IN  TPMI_RH_NV_INDEX KeyNvIndex,
    IN  UINT16           KeyLength,
    IN  TPM_HANDLE       *sessionHandle,
    OUT BYTE             *Key
    )
{
  EFI_STATUS Status;
  UINT16     res;

  // Auth Area
  UINT32 authSize;
  ORIG_AUTH_AREA authArea;
  authArea.sessionHandle = SwapBytes32(*sessionHandle);
  authArea.nonceSizeZero = SwapBytes16(0);
  authArea.sessionAttributes.continueSession = 0;
  authArea.sessionAttributes.auditExclusive  = 0;
  authArea.sessionAttributes.auditReset      = 0;
  authArea.sessionAttributes.reserved3_4     = 0;
  authArea.sessionAttributes.decrypt         = 0;
  authArea.sessionAttributes.encrypt         = 0;
  authArea.sessionAttributes.audit           = 0;
  authArea.hmacSizeZero = SwapBytes16(0);
  authSize = sizeof(authArea);

  TPM2_NV_READ_COMMAND  CmdBuffer;
  UINT32                CmdBufferSize;
  TPM2_NV_READ_RESPONSE RecvBuffer;
  UINT32                RecvBufferSize;

  // set send parameters
  CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_SESSIONS);
  CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_NV_Read);
  CmdBuffer.authHandle         = SwapBytes32(KeyNvIndex);
  CmdBuffer.nvIndex            = SwapBytes32(KeyNvIndex);
  CmdBuffer.authSize           = SwapBytes32(authSize);
  CmdBuffer.authArea           = authArea;
  CmdBuffer.size               = SwapBytes16(KeyLength);
  CmdBuffer.offset             = SwapBytes16(0);
  CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.authHandle) + sizeof(CmdBuffer.nvIndex) + sizeof(CmdBuffer.authSize) + sizeof(CmdBuffer.authArea) + sizeof(CmdBuffer.size) + sizeof(CmdBuffer.offset);
  CmdBuffer.Header.paramSize = SwapBytes32(CmdBufferSize);

  // send TPM command
  RecvBufferSize = sizeof(RecvBuffer);
  Status = Tpm2SubmitCommand(
      CmdBufferSize,
      (UINT8*)&CmdBuffer,
      &RecvBufferSize,
      (UINT8*)&RecvBuffer
      );
  if(EFI_ERROR(Status)) {
    return Status;
  }
  
  // parse response
  res = SwapBytes32(RecvBuffer.Header.responseCode);
  if(res!=0) {
    return res;
  }

  UINT16 readDataSize = SwapBytes16(RecvBuffer.data.size);

  UINT16 i;
  for(i=0; i<readDataSize; i++) {
    Key[i] = RecvBuffer.data.buffer[readDataSize-i-1];
  }

  return EFI_SUCCESS;
}



/**
 
 This function ends session.
 (somehow doesn't work... not much a problem though)
 
 @param[in]  sessionHandle  Handle of the session made by StartAuthSession
 
**/
EFI_STATUS
TpmFlushContext (
    IN  TPM_HANDLE *sessionHandle
    )
{
  EFI_STATUS                 Status;
  UINT16                     res;
  TPM2_FLUSHCONTEXT_COMMAND  CmdBuffer;
  UINT32                     CmdBufferSize;
  TPM2_FLUSHCONTEXT_RESPONSE RecvBuffer;
  UINT32                     RecvBufferSize;

  // set send parameters
  CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_NO_SESSIONS);
  CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_FlushContext);
  CmdBuffer.flushHandle        = SwapBytes32(*sessionHandle);
  CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.flushHandle);
  CmdBuffer.Header.paramSize = SwapBytes32(CmdBufferSize);

  // send TPM command
  RecvBufferSize = sizeof(RecvBuffer);
  Status = Tpm2SubmitCommand(
      CmdBufferSize,
      (UINT8*)&CmdBuffer,
      &RecvBufferSize,
      (UINT8*)&RecvBuffer
      );
  if(EFI_ERROR(Status)) {
    return Status;
  }
  
  // parse response
  res = SwapBytes32(RecvBuffer.Header.responseCode);
  if(res!=0) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}
