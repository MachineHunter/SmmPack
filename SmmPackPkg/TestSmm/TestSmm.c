#include "TestSmm.h"

EFI_STATUS
EFIAPI
TestSmmPrint () {
  UartPrint("TestSmmPrint called!!\n");
  return EFI_SUCCESS;
}

EFI_HANDLE mTestHandle = NULL;
EFI_TEST_SMM_PROTOCOL mTest = {
  TestSmmPrint
};


EFI_MM_CPU_IO_PROTOCOL *mMmCpuIo;
EFI_SMM_SYSTEM_TABLE2  *Smst;



EFI_STATUS
EFIAPI
MySmiHandler (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID* RegisterContext,
  IN OUT VOID*   CommBuffer,
  IN OUT UINTN*  CommBufferSize
  )
{
  EFI_STATUS Status;
  UINT8 cmdNumber;

  Status = mMmCpuIo->Io.Read(
      mMmCpuIo,
      MM_IO_UINT8,
      0xB2,
      1,
      &cmdNumber
      );
  if(Status!=EFI_SUCCESS)
    UartPrint("mMmCpuIo->Io.Read error %d\r\n", Status);

  if(cmdNumber == 0xff)
    goto Exit;

  UartPrint("[MySmiHandler] SMI 0x%02x\r\n", cmdNumber);

Exit:
  return EFI_WARN_INTERRUPT_SOURCE_QUIESCED;
}



EFI_STATUS
EFIAPI
SmmEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  int i;
  EFI_STATUS Status;
  BYTE buf[0x10] = {0};
  for(i=0; i<0x10; i++)
    buf[i] = i;

  UartPrint("\r\n>>> TestSmm Entry\r\n");


  // 
  // 1: Get SMST
  //
  EFI_SMM_BASE2_PROTOCOL *SmmBase2Protocol;
  Status = SystemTable->BootServices->LocateProtocol(
      &gEfiSmmBase2ProtocolGuid,
      0x0,
      (VOID**)&SmmBase2Protocol
      );
  if(Status!=EFI_SUCCESS)
    UartPrint("LocateProtocol error %d\r\n", Status);

  Status = SmmBase2Protocol->GetSmstLocation(
      SmmBase2Protocol,
      &Smst
      );
  if(Status!=EFI_SUCCESS)
    UartPrint("GetSmstLocation error %d\r\n", Status);


  // 
  // 2: Use SmmPackProtocol
  //
  EFI_SMM_PACK_PROTOCOL *SmmPackProtocol;
  Status = Smst->SmmLocateProtocol(
      &gEfiSmmPackProtocolGuid,
      NULL,
      (VOID**)&SmmPackProtocol
      );
  if(Status!=EFI_SUCCESS)
    UartPrint("SmmLocateProtocol (SmmPackProtocol) error %d\r\n", Status);

  Status = SmmPackProtocol->Unpack(
      buf,
      0x10
      );
  UartPrint("buf: ");
  for(i=0; i<0x10; i++)
    UartPrint("%02X",buf[i]);
  UartPrint("\r\n");


  // 
  // 3: Check if is inside SMRAM
  //
  BOOLEAN InSmram = 0;
  Status = SmmBase2Protocol->InSmm(
      SmmBase2Protocol,
      &InSmram
      );
  if(Status!=EFI_SUCCESS)
    UartPrint("SmmBase2InSmram error %d\r\n", Status);
  if(InSmram)
    UartPrint("It is inside SMRAM\r\n");
  else
    UartPrint("It is outside SMRAM\r\n");


  // 
  // 4: Register SMI handler
  //
  EFI_HANDLE hMySmiHandle;
  Status = Smst->SmmLocateProtocol(
      &gEfiMmCpuIoProtocolGuid,
      NULL,
      (VOID **)&mMmCpuIo
      );
  if(Status!=EFI_SUCCESS)
    UartPrint("SmmLocateProtocol (CpuIoProtocol) error %d\r\n", Status);

  Status = Smst->SmiHandlerRegister(
      MySmiHandler,
      NULL,
      &hMySmiHandle
      );
  if(Status!=EFI_SUCCESS)
    UartPrint("SmiHandlerRegister error %d\r\n", Status);


  //
  // 5: Register test SMM protocol
  //
  Status = Smst->SmmInstallProtocolInterface(
      &mTestHandle,
      &gEfiTestSmmProtocolGuid,
      EFI_NATIVE_INTERFACE,
      &mTest
      );
  if(Status!=EFI_SUCCESS) {
    UartPrint("SmmInstallProtocolInterface failed with %d\r\n", Status);
  }


  UartPrint("<<< TestSmm Ended\r\n");
  return EFI_SUCCESS;
}
