#include <SmmPackImpl.h>
#include <Measure.h>


UINT16 KeyLength = 16;   // AES-128 key so 128bit=16bytes
BYTE   Key[16]   = {0};  // REMEMBER when changing KeyLength, change ORIG_MAX_NV_BUFFER in typedef too!
BYTE   IV[16]    = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

int i,j;


Measure tEntry  = {0};
Measure tUnpack = {0};
Measure tGetKey = {0};


/**
 
 Unpack function of SmmPackProtocol.
 This decrypts DataSize-sized data starting from DataAddr by AES-128
 using Key defined above (which is the key retrieved from TPM).

 @param[in]  DataAddr  .text section base address of packed Smm module
 @param[in]  DataSize  .text section size of packed Smm module

**/
EFI_STATUS
EFIAPI
Unpack (
    IN VOID   *DataAddr,
    IN UINT32 DataSize
    )
{
  struct AES_ctx ctx;

  MeasureStart(&tUnpack);

  AES_init_ctx_iv(&ctx, Key, IV);
  AES_CBC_decrypt_buffer(&ctx, (UINT8*)DataAddr, DataSize);

  MeasureEnd(&tUnpack);
  UartPrint("DataAddr: 0x%16X, DataSize: %d(%x)\r\n", (UINT64)DataAddr, DataSize, DataSize);
  UartPrint("\ttUnpack: %lld\r\n", tUnpack.cycles);

  return EFI_SUCCESS;
}

EFI_HANDLE mSmmPackHandle = NULL;
EFI_SMM_PACK_PROTOCOL mSmmPack = {
  Unpack
};



/**
 
 Function to get the Key from TPM.

 @param[out]  Key        Returns key read from TPM
 @param[in]   KeyLength  Size of Key

 Note:
   Key is defined as argument even though it's global variable
   to make it compatible when I changed the way to store Key.

**/
EFI_STATUS
GetTpmKey (
    OUT BYTE             *Key,
    IN  UINT16           KeyLength
    ) 
{
  EFI_STATUS Status;
  TPM_HANDLE sessionHandle;
  UINT16     DigestSize = 32;
  BYTE       Digest[32] = {0};

  TPMI_RH_NV_INDEX KeyNvIndex = NV_INDEX_FIRST+1; 

  //
  // This sets requestUse bit of TPM_ACCESS_x register (TPM_ACCESS_x[1])
  //
  Status = TpmRequestUse();
  if(EFI_ERROR(Status)) {
    UartPrint("TpmRequestUse error with %d\r\n", Status);
    return EFI_DEVICE_ERROR;
  }

  //
  // Start Policy session
  //
  Status = TpmStartAuthSession(&sessionHandle);
  if(EFI_ERROR(Status)) {
    UartPrint("TpmStartAuthSession error with %d\r\n", Status);
    return EFI_DEVICE_ERROR;
  }

  //
  // This is just for reading PCR value of SmmPackSmm's execution phase
  //
  Status = TpmPcrRead(
      TPM_ALG_SHA256,
      0,
      Digest,
      &DigestSize
      );
  if(EFI_ERROR(Status)) {
    UartPrint("TpmPcrRead error with %d\r\n", Status);
    return EFI_DEVICE_ERROR;
  }
  /*
   *UartPrint("Digest:\r\n");
   *for(i=0; i<DigestSize; i++) {
   *  UartPrint("%02X", Digest[i]);
   *}
   *UartPrint("\r\n\r\n");
   */
  
  /*
   *UartPrint("Digest(pretty):\r\n");
   *for(i=0; i<32; i+=8) {
   *  for(j=0; j<8; j++) {
   *    UartPrint("0x%02X, ", Digest[i+j]);
   *  }
   *  UartPrint("\r\n");
   *}
   *UartPrint("\r\n");
   */

  //
  // Select PCR to use for authorization
  //
  Status = TpmPolicyPCR(
      &sessionHandle,
      TPM_ALG_SHA256,
      0
      );
  if(Status!=EFI_SUCCESS) {
    UartPrint("TpmPolicyPCR error with %d\r\n", Status);
    return EFI_DEVICE_ERROR;
  }

  //
  // Read key from TPM NV space (pcr authorization runs here)
  //
  Status = TpmNVRead(
      KeyNvIndex,
      KeyLength,
      &sessionHandle,
      Key
      );
  if(Status!=EFI_SUCCESS) {
    UartPrint("TpmNVRead error with %d\r\n", Status);
    return EFI_DEVICE_ERROR;
  }

  //
  // End session (somehow error occurs so disabling it for now)
  //
  /*
   *Status = TpmFlushContext(&sessionHandle);
   *if(EFI_ERROR(Status)) {
   *  DebugVarLog(5, 1, &Status, sizeof(EFI_STATUS));
   *  return EFI_DEVICE_ERROR;
   *}
   */

  /*
   *UartPrint("Key:\r\n");
   *for(i=0; i<KeyLength; i++)
   *  UartPrint("%02X", Key[i]);
   *UartPrint("\r\n");
   */

  return EFI_SUCCESS;
}



/**
 
 Driver's entry point.
 This first reads key from TPM and stores it in global variable.
 Then, installs SmmPackProtocol for other SMM mods to use when unpacking them self.

 @param[in]  ImageHandle  The firmware allocated handle for the EFI image
 @param[in]  SystemTable  A pointer to the EFI System Table.

**/
EFI_STATUS
EFIAPI
SmmEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status;
  UartPrint(">>> SmmPackSmm Entry\r\n");

  MeasureStart(&tEntry);
  MeasureStart(&tGetKey);

  //
  // 1: Read and set Key as a global variable
  //    (just return success to continue execution for debug)
  //
  Status = GetTpmKey(Key, KeyLength);
  if(EFI_ERROR(Status)) {
    UartPrint("GetTpmKey error with %d\r\n", Status);
    return EFI_SUCCESS;
  }

  MeasureEnd(&tGetKey);

  // 
  // 2: Install SmmPackProtocol
  //
  Status = gSmst->SmmInstallProtocolInterface(
      &mSmmPackHandle,
      &gEfiSmmPackProtocolGuid,
      EFI_NATIVE_INTERFACE,
      &mSmmPack
      );

  if(Status!=EFI_SUCCESS) {
    UartPrint("SmmInstallProtocolInterface failed with %d\r\n", Status);
  }
  
  MeasureEnd(&tEntry);

  UartPrint("Clock cycles [cycles]:\r\n");
  UartPrint("\ttEntry:  %lld\r\n", tEntry.cycles);
  UartPrint("\ttGetKey: %lld\r\n", tGetKey.cycles);

  UartPrint("<<< SmmPackSmm Ended\r\n");
  return EFI_SUCCESS;
}
