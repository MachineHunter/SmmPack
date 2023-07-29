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
  UINT32   myvarSize          = 30;
  CHAR8    myvarValue[30]     = {0};
  CHAR16   myvarName[30]      = L"MyDxeStatus";
  EFI_GUID myvarGUID          = { 0xeefbd379, 0x9f5c, 0x4a92, { 0xa1, 0x57, 0xae, 0x40, 0x79, 0xeb, 0x14, 0x48 }}; // eefbd379-9f5c-4a92-a157-ae4079eb1448
  
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
  // UefiPackSmm
  BYTE ExpectedPcrVal[32]   = { 
    0x0E, 0x29, 0x7A, 0xB9, 0x5D, 0x3A, 0x5E, 0x22,
    0xFC, 0x04, 0x7C, 0x27, 0xF9, 0x8B, 0x51, 0x0B,
    0x09, 0xB6, 0x52, 0xFB, 0x15, 0xCB, 0xF7, 0x86,
    0x3A, 0xD0, 0x2F, 0xFC, 0xAB, 0x2A, 0x04, 0x67
  };
  // UefiPackDxe
  /*
   *BYTE ExpectedPcrVal[32]   = { 
   *  0x6d, 0xfc, 0x5a, 0xb5, 0x2b, 0x0f, 0xf6, 0x23,
   *  0xbd, 0xcc, 0x83, 0x80, 0x4f, 0xc4, 0xd7, 0xbc,
   *  0x1d, 0xb8, 0xdf, 0xe7, 0x48, 0xc9, 0xf2, 0x54,
   *  0xb7, 0xb2, 0xe1, 0x36, 0x77, 0x55, 0xd2, 0xc6
   *};
   */
  
  EFI_STATUS Status;
  TPM_HANDLE sessionHandle;
  UINT16     DigestSize;
  BYTE       Digest[32] = {0};


  //
  // This sets requestUse bit of TPM_ACCESS_x register (TPM_ACCESS_x[1])
  //
  Status = TpmRequestUse();
  if(EFI_ERROR(Status)) {
    myvarValue[0] = 1;
    CopyMem(myvarValue+1, &Status, sizeof(EFI_STATUS));
    goto End;
  }

  //
  // Start Trial session
  //
  Status = TpmStartAuthSession(&sessionHandle);
  if(EFI_ERROR(Status)) {
    myvarValue[0] = 2;
    CopyMem(myvarValue+1, &Status, sizeof(EFI_STATUS));
    goto End;
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
    myvarValue[0] = 3;
    CopyMem(myvarValue+1, &Status, sizeof(EFI_STATUS));
    goto End;
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
    myvarValue[0] = 4;
    CopyMem(myvarValue+1, &Status, sizeof(EFI_STATUS));
    goto End;
  }

  //
  // Generate key
  //
  Status = TpmGetRandom(
      KeyLength,
      Key
      );
  if(EFI_ERROR(Status)) {
    myvarValue[0] = 5;
    CopyMem(myvarValue+1, &Status, sizeof(EFI_STATUS));
    goto End;
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
    myvarValue[0] = 6;
    CopyMem(myvarValue+1, &Status, sizeof(EFI_STATUS));
    goto End;
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
    myvarValue[0] = 7;
    CopyMem(myvarValue+1, &Status, sizeof(EFI_STATUS));
    goto End;
  }

  //
  // End session
  //
  Status = TpmFlushContext(&sessionHandle);
  if(EFI_ERROR(Status)) {
    myvarValue[0] = 8;
    CopyMem(myvarValue+1, &Status, sizeof(EFI_STATUS));
    goto End;
  }


  //
  // Store results or error message inside UEFI variable
  // (because my environment can't use ConOut and display output...)
  //
  myvarValue[0] = 9;
  CopyMem(myvarValue+1, Key, KeyLength);

End:
  gRT->SetVariable(
      myvarName,
      &myvarGUID,
      EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
      myvarSize,
      myvarValue);

  return EFI_SUCCESS;
}
