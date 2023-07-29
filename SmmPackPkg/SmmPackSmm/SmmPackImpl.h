#include <SmmPackSmm.h>


/**
 
 Define wrapper functions for TPM command
 used when retrieving key from TPM.

**/

EFI_STATUS
TpmRequestUse (
    VOID
    );

EFI_STATUS
TpmStartAuthSession (
    OUT TPM_HANDLE *sessionHandle
    );

EFI_STATUS
TpmPcrRead (
    IN  TPM_ALG_ID AlgId,
    IN  UINT32     PcrId,
    OUT BYTE       *Digest,
    OUT UINT16     *DigestSize
    );

EFI_STATUS
TpmPolicyPCR (
    IN TPM_HANDLE *sessionHandle,
    IN TPM_ALG_ID AlgId,
    IN UINT32     PcrId
    );

EFI_STATUS
TpmNVRead (
    IN  TPMI_RH_NV_INDEX KeyNvIndex,
    IN  UINT16           KeyLength,
    IN  TPM_HANDLE       *sessionHandle,
    OUT BYTE             *Key
    );
  
EFI_STATUS
TpmFlushContext (
    IN  TPM_HANDLE *sessionHandle
    );
