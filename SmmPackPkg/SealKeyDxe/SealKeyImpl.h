#include <SealKeyDxe.h>


/**
 
 Define wrapper functions for TPM command
 used when sealing key from TPM.

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
TpmPolicyPCR (
    IN TPM_HANDLE *sessionHandle,
    IN TPM_ALG_ID AlgId,
    IN UINT32     PcrId,
    IN BYTE       *ExpectedPcrVal,
    IN UINT32     ExpectedPcrValSize
    );

EFI_STATUS
TpmPolicyGetDigest (
    IN  TPM_HANDLE *sessionHandle,
    OUT UINT16     *DigestSize,
    OUT BYTE       *Digest
    );


EFI_STATUS
TpmGetRandom (
    IN  UINT16  KeyLength,
    OUT BYTE    *Key
    );


EFI_STATUS TpmNVDefineSpace (
    IN TPMI_RH_NV_INDEX KeyNvIndex,
    IN UINT16           KeyLength,
    IN UINT16           DigestSize,
    IN BYTE             *Digest
    );


EFI_STATUS
TpmNVWrite (
    IN TPMI_RH_NV_INDEX KeyNvIndex,
    IN UINT16           KeyLength,
    IN BYTE             *Key
    );


EFI_STATUS
TpmFlushContext (
    IN TPM_HANDLE *sessionHandle
    );
