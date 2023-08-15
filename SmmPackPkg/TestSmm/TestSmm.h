#include <Protocol/SmmBase2.h>
#include <SmmPackSmm/SmmPackSmm.h>
#include <Library/SmmServicesTableLib.h>

// 39659a89-fb54-4cb6-980a-d3aada21b60c
#define EFI_TEST_SMM_PROTOCOL_GUID \
  { 0x39659a89, 0xfb54, 0x4cb6, { 0x98, 0x0a, 0xd3, 0xaa, 0xda, 0x21, 0xb6, 0x0c } }

typedef EFI_STATUS (EFIAPI *TESTSMMPRINT)();

typedef struct _EFI_TEST_SMM_PROTOCOL {
  TESTSMMPRINT TestSmmPrint;
} EFI_TEST_SMM_PROTOCOL;

extern EFI_GUID gEfiTestSmmProtocolGuid;
