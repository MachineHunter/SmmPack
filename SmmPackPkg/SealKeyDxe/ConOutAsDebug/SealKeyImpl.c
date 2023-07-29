#include "SealKeyImpl.h"


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
 
 This function starts Trial session of TPM.
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
  CmdBuffer.sessionType        = TPM_SE_TRIAL;
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



EFI_STATUS
TpmPolicyPCR (
    IN TPM_HANDLE *sessionHandle,
    IN TPM_ALG_ID AlgId,
    IN UINT32     PcrId,
    IN BYTE       *ExpectedPcrVal,
    IN UINT32     ExpectedPcrValSize
    )
{
  EFI_STATUS              Status;
  UINT16                  res;
  TPM2_POLICYPCR_COMMAND  CmdBuffer;
  UINT32                  CmdBufferSize;
  TPM2_POLICYPCR_RESPONSE RecvBuffer;
  UINT32                  RecvBufferSize;

  ORIG_TPM2B_DIGEST pcrDigest;
  pcrDigest.size = SwapBytes16(32);

  CopyMem(pcrDigest.buffer, ExpectedPcrVal, ExpectedPcrValSize);

  ORIG_TPML_PCR_SELECTION pcrs;
  pcrs.count                         = SwapBytes32(1);
  pcrs.pcrSelections[0].hash         = SwapBytes16(AlgId);
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
  CmdBuffer.pcrDigest          = pcrDigest;
  CmdBuffer.pcrs               = pcrs;
  CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.policySession) + sizeof(CmdBuffer.pcrDigest) + sizeof(CmdBuffer.pcrs);
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



/**
 
 This function gets digest of current policy (session).
 Digest is used in TpmNvDefineSpace to restrict NV Index access by this policy.
 
 @param[in]   sessionHandle  Handle of the session made by StartAuthSession
 @param[out]  DigestSize     Return the size of Digest
 @param[out]  Digest         Return digest value of current policy (session)
 
**/
EFI_STATUS
TpmPolicyGetDigest (
    IN  TPM_HANDLE *sessionHandle,
    OUT UINT16     *DigestSize,
    OUT BYTE       *Digest
    )
{
  EFI_STATUS                    Status;
  UINT16                        res;
  TPM2_POLICYGETDIGEST_COMMAND  CmdBuffer;
  UINT32                        CmdBufferSize;
  TPM2_POLICYGETDIGEST_RESPONSE RecvBuffer;
  UINT32                        RecvBufferSize;

  // set send parameters
  CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_NO_SESSIONS);
  CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_PolicyGetDigest);
  CmdBuffer.policySession      = SwapBytes32(*sessionHandle);
  CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.policySession);
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

  *DigestSize = SwapBytes16(RecvBuffer.policyDigest.size);
  CopyMem(Digest, RecvBuffer.policyDigest.buffer, *DigestSize);

  return EFI_SUCCESS;
}



/**
 
 This function generates TPM key used when packing.
 Key made by TPM's (T)RNG makes it more secure than using OS RNG.
 
 @param[in]   KeyLength  Size of the Key to generate
 @param[out]  Key        Return value of the Key (byte in BIG ENDIAN due to TPM's endian)
 
**/
EFI_STATUS
TpmGetRandom (
    IN  UINT16  KeyLength,
    OUT BYTE    *Key
    )
{
  EFI_STATUS               Status;
  UINT16                   res;
  TPM2_GET_RANDOM_COMMAND  CmdBuffer;
  UINT32                   CmdBufferSize;
  TPM2_GET_RANDOM_RESPONSE RecvBuffer;
  UINT32                   RecvBufferSize;

  // set send parameters
  CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_NO_SESSIONS);
  CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_GetRandom);
  CmdBuffer.bytesRequested     = SwapBytes16(KeyLength);
  CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.bytesRequested);
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

  CopyMem(Key, RecvBuffer.randomBytes.buffer, KeyLength);

  return EFI_SUCCESS;
}



/**
 
 This function define NV Index to store key.
 This restricts reads towards the index by digest retrieved by TpmPolicyGetDigest
 meaning the index becomes readable when policy rules described above are satisfied.
 
 @param[in]  KeyNvIndex  NV Index to allocate the key
 @param[in]  KeyLength   Size of NV Index to allocate which equals the size of the key
 @param[in]  DigestSize  Size of Digest
 @param[in]  Digest      Policy digest retrieved by TpmPolicyGetDigest
 
**/
EFI_STATUS TpmNVDefineSpace (
    IN TPMI_RH_NV_INDEX KeyNvIndex,
    IN UINT16           KeyLength,
    IN UINT16           DigestSize,
    IN BYTE             *Digest
    )
{
  EFI_STATUS Status;
  UINT16     res;

  // Auth Area
  UINT32 authSize;
  ORIG_AUTH_AREA authArea;
  authArea.sessionHandle = SwapBytes32(TPM_RS_PW);
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

  // publicInfo area
  ORIG_NV_PUBLIC publicInfo;
  publicInfo.nvIndex = SwapBytes32(KeyNvIndex);
  publicInfo.nameAlg = SwapBytes16(TPM_ALG_SHA256);
  /*
   *TPMA_NV attributes;
   *attributes.TPMA_NV_PPWRITE        = 1;
   *attributes.TPMA_NV_OWNERWRITE     = 1;
   *attributes.TPMA_NV_AUTHWRITE      = 1; // write without policy session is allowed for the ease
   *attributes.TPMA_NV_POLICYWRITE    = 1;
   *attributes.TPMA_NV_COUNTER        = 0;
   *attributes.TPMA_NV_BITS           = 0;
   *attributes.TPMA_NV_EXTEND         = 0;
   *attributes.reserved7_9            = 000;
   *attributes.TPMA_NV_POLICY_DELETE  = 0;
   *attributes.TPMA_NV_WRITELOCKED    = 0;
   *attributes.TPMA_NV_WRITEALL       = 1;
   *attributes.TPMA_NV_WRITEDEFINE    = 0;
   *attributes.TPMA_NV_WRITE_STCLEAR  = 1;
   *attributes.TPMA_NV_GLOBALLOCK     = 0;
   *attributes.TPMA_NV_PPREAD         = 1;
   *attributes.TPMA_NV_OWNERREAD      = 1;
   *attributes.TPMA_NV_AUTHREAD       = 0; // restricts read without policy session
   *attributes.TPMA_NV_POLICYREAD     = 1; // allow read using policy session
   *attributes.reserved20_24          = 00000;
   *attributes.TPMA_NV_NO_DA          = 1;
   *attributes.TPMA_NV_ORDERLY        = 0;
   *attributes.TPMA_NV_CLEAR_STCLEAR  = 0;
   *attributes.TPMA_NV_READLOCKED     = 0;
   *attributes.TPMA_NV_WRITTEN        = 0;
   *attributes.TPMA_NV_PLATFORMCREATE = 0;
   *attributes.TPMA_NV_READ_STCLEAR   = 0;
   * => 00000010000010110101000000001111
   * => 0x20b500f
   */
  publicInfo.attributes = SwapBytes32(0x20b500f);
  publicInfo.authPolicy.size = SwapBytes16(DigestSize);
  CopyMem(publicInfo.authPolicy.buffer, Digest, DigestSize);
  publicInfo.dataSize = SwapBytes16(KeyLength);
  publicInfo.size = SwapBytes16(sizeof(publicInfo) - sizeof(publicInfo.size));


  TPM2_NV_DEFINE_SPACE_COMMAND CmdBuffer;
  UINT32 CmdBufferSize;
  TPM2_NV_DEFINE_SPACE_RESPONSE RecvBuffer;
  UINT32 RecvBufferSize;

  // set send parameters
  CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_SESSIONS);
  CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_NV_DefineSpace);
  CmdBuffer.authHandle         = SwapBytes32(TPM_RH_OWNER);
  CmdBuffer.authSize           = SwapBytes32(authSize);
  CmdBuffer.authArea           = authArea;
  /*CmdBuffer.auth               = auth;*/
  CmdBuffer.authSizeZero       = SwapBytes16(0);
  CmdBuffer.publicInfo         = publicInfo;
  CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.authHandle) + sizeof(CmdBuffer.authSize) + sizeof(CmdBuffer.authArea) + sizeof(CmdBuffer.authSizeZero) + sizeof(CmdBuffer.publicInfo);
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
  if(res==332) {
    Print(L"[332] NV Index or persistent object already defined\r\n");
    return EFI_WRITE_PROTECTED;
  }
  else if(res!=0) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}



/**
 
 This function writes the key to the NV Index defined above.
 PCR authorization doesn't occur here because we didn't set TPMA_NV_AUTHWRITE to 0.
 
 @param[in]  KeyNvIndex  NV Index to write the key
 @param[in]  KeyLength   Size of Key
 @param[in]  Key         Key generated by TpmGetRandom
 
**/
EFI_STATUS
TpmNVWrite (
    IN TPMI_RH_NV_INDEX KeyNvIndex,
    IN UINT16           KeyLength,
    IN BYTE             *Key
    )
{
  EFI_STATUS             Status;
  UINT16                 res;
  TPM2_NV_WRITE_COMMAND  CmdBuffer;
  UINT32                 CmdBufferSize;
  TPM2_NV_WRITE_RESPONSE RecvBuffer;
  UINT32                 RecvBufferSize;

  ORIG_MAX_NV_BUFFER data;
  data.size = SwapBytes16(KeyLength);
  CopyMem(data.buffer, Key, KeyLength);

  // Auth Area
  UINT32 authSize;
  ORIG_AUTH_AREA authArea;
  authArea.sessionHandle = SwapBytes32(TPM_RS_PW);
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

  // set send parameters
  CmdBuffer.Header.tag         = SwapBytes16(TPM_ST_SESSIONS);
  CmdBuffer.Header.commandCode = SwapBytes32(TPM_CC_NV_Write);
  CmdBuffer.authHandle         = SwapBytes32(KeyNvIndex);
  CmdBuffer.nvIndex            = SwapBytes32(KeyNvIndex);
  CmdBuffer.authSize           = SwapBytes32(authSize);
  CmdBuffer.authArea           = authArea;
  CmdBuffer.data               = data;
  CmdBuffer.offset             = SwapBytes16(0);
  CmdBufferSize = sizeof(CmdBuffer.Header) + sizeof(CmdBuffer.authHandle) + sizeof(CmdBuffer.nvIndex) + sizeof(CmdBuffer.authSize) + sizeof(CmdBuffer.authArea) + sizeof(CmdBuffer.data) + sizeof(CmdBuffer.offset);
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



/**
 
 This function ends the trial session.
 
 @param[in]  sessionHandle  Handle of the session made by StartAuthSession
 
**/
EFI_STATUS
TpmFlushContext (
    IN TPM_HANDLE *sessionHandle
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
