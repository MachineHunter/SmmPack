#include <SealKeyImpl.h>


/**
 
 Driver's entry point.
 This seals key using TPM command and each command's detail is written in SealKeyImpl.

 @param[in]  ImageHandle  The firmware allocated handle for the EFI image
 @param[in]  SystemTable  A pointer to the EFI System Table.

**/
EFI_STATUS EFIAPI DriverEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
  TPMI_RH_NV_INDEX KeyNvIndex = NV_INDEX_FIRST+1;  // this is the nvIndex to store AES key. in this case, NV_INDEX_FIRST+1
  UINT16   KeyLength          = 16;                // AES-128 key so 128bit=16bytes
  BYTE     Key[16]            = {0};               // REMEMBER when changing KeyLength, change ORIG_MAX_NV_BUFFER in typedef too!
  
  //
  // Only Dxe driver running when PCR digest value is below can read this key.
  // PCR value can be read by TpmPcrRead in UefiPackDxe.
  //
  // BE CAREFUL that this value is not PCR value but is the digest value calculated by below func.
  //  ExpectedPcrVal = HashOfSession(PCR val | PCR val | PCR val ...)
  // HashOfSession is the TPM_ALG_ID specified in the authHash parameter of StartAuthSession.
  // Also, if multiple PCR values needs to be specified, concatenate every PCR value and hash them.
  //
  UINT32 ExpectedPcrValSize = 32;
  BYTE ExpectedPcrVal[32]   = { 
    0x6d, 0xfc, 0x5a, 0xb5, 0x2b, 0x0f, 0xf6, 0x23,
    0xbd, 0xcc, 0x83, 0x80, 0x4f, 0xc4, 0xd7, 0xbc,
    0x1d, 0xb8, 0xdf, 0xe7, 0x48, 0xc9, 0xf2, 0x54,
    0xb7, 0xb2, 0xe1, 0x36, 0x77, 0x55, 0xd2, 0xc6
  };
  
  EFI_STATUS Status;
  TPM_HANDLE sessionHandle;
  UINT16     DigestSize;
  BYTE       Digest[32] = {0};


  //
  // This sets requestUse bit of TPM_ACCESS_x register (TPM_ACCESS_x[1])
  //
  Status = TpmRequestUse();
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SealKeyDxe] TpmRequestUse Failed with EFI_STATUS: %d\r\n", Status));
    ASSERT_EFI_ERROR(Status);
  }

  //
  // Start Trial session
  //
  Status = TpmStartAuthSession(&sessionHandle);
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SealKeyDxe] TpmStartAuthSession Failed with EFI_STATUS: %d\r\n", Status));
    ASSERT_EFI_ERROR(Status);
  }

  //
  // Specify PCR values to allow for this session
  //
  Status = TpmPolicyPCR(
      &sessionHandle,
      TPM_ALG_SHA256,
      0,
      ExpectedPcrVal,
      ExpectedPcrValSize
      );
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SealKeyDxe] TpmPolicyPCR Failed with EFI_STATUS: %d\r\n", Status));
    ASSERT_EFI_ERROR(Status);
  }

  //
  // Get digest of this policy (used at TpmNvDefineSpace)
  //
  Status = TpmPolicyGetDigest(
      &sessionHandle,
      &DigestSize,
      Digest
      );
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SealKeyDxe] TpmPolicyGetDigest Failed with EFI_STATUS: %d\r\n", Status));
    ASSERT_EFI_ERROR(Status);
  }

  //
  // Generate key
  //
  Status = TpmGetRandom(
      KeyLength,
      Key
      );
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SealKeyDxe] TpmGetRadom Failed with EFI_STATUS: %d\r\n", Status));
    ASSERT_EFI_ERROR(Status);
  }

  //
  // Allocate space for AES key in NV space (policy digest used here)
  //
  Status = TpmNVDefineSpace(
      KeyNvIndex,
      KeyLength,
      DigestSize,
      Digest
      );
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SealKeyDxe] TpmNVDefineSpace Failed with EFI_STATUS: %d\r\n", Status));
    ASSERT_EFI_ERROR(Status);
  }

  //
  // Write the Key
  //
  Status = TpmNVWrite(
      KeyNvIndex,
      KeyLength,
      Key
      );
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SealKeyDxe] TpmNVWrite Failed with EFI_STATUS: %d\r\n", Status));
    ASSERT_EFI_ERROR(Status);
  }

  //
  // End session
  //
  Status = TpmFlushContext(&sessionHandle);
  if(EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SealKeyDxe] TpmFlushContext Failed with EFI_STATUS: %d\r\n", Status));
    ASSERT_EFI_ERROR(Status);
  }


  //
  // Output results
  //
  DEBUG((DEBUG_INFO, "[SealKeyDxe] Key stored success fully!!!\r\n"));
  DEBUG((DEBUG_INFO, "             - NV Index: %d\r\n", KeyNvIndex));
  DEBUG((DEBUG_INFO, "             - Key: ", KeyNvIndex));
  UINT32 i;
  for(i=0; i<KeyLength; i++)
    DEBUG((DEBUG_INFO, "%02X", Key[i]));
  DEBUG((DEBUG_INFO, "\r\n"));

  return EFI_SUCCESS;
}
