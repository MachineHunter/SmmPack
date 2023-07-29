#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/SmmServicesTableLib.h>
#include <UartPrint.h>

#include "tiny-AES-c/aes.h"


/**
 
  Define SmmPackProtocol's general information.

**/

// 78fe40fb-fd3e-45bb-8fff-f35d78383db9
#define EFI_SMM_PACK_PROTOCOL_GUID \
  { 0x78fe40fb, 0xfd3e, 0x45bb, { 0x8f, 0xff, 0xf3, 0x5d, 0x78, 0x38, 0x3d, 0xb9 } }

extern EFI_GUID gEfiSmmPackProtocolGuid;

typedef EFI_STATUS (EFIAPI *UNPACK)(
    IN VOID *DataAddr,
    IN UINT32 DataSize
    );

typedef struct _EFI_SMM_PACK_PROTOCOL {
  UNPACK Unpack;
} EFI_SMM_PACK_PROTOCOL;



/**
 
  Define TPM structures used when retrieving key.

  TPM has canonicalization mechanism which requires us
  to redefine structure that has "sized buffer".

**/
#pragma pack(1)
  typedef struct _ORIG_TPM2B_NONCE {
    UINT16 size;
    BYTE buffer[20];
  } ORIG_TPM2B_NONCE;

  typedef struct _ORIG_TPMT_SYM_DEF {
    TPMI_ALG_SYM algorithmNull;
  } ORIG_TPMT_SYM_DEF;

  typedef struct _ORIG_TPM2B_DIGEST {
    UINT16 size;
    BYTE buffer[32];
  } ORIG_TPM2B_DIGEST;

  typedef struct _TPM2_STARTAUTHSESSION_COMMAND {
    TPM2_COMMAND_HEADER Header;
    TPMI_DH_OBJECT tpmKey;
    TPMI_DH_ENTITY bind;
    /*TPM2B_NONCE nonceCaller;*/
    ORIG_TPM2B_NONCE nonceCaller;
    /*TPM2B_ENCRYPTED_SECRET encryptedSalt;*/
    UINT16 encryptedSaltZero;
    TPM_SE sessionType;
    /*TPMT_SYM_DEF symmetric;*/
    ORIG_TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH authHash;
  } TPM2_STARTAUTHSESSION_COMMAND;

  typedef struct _TPM2_STARTAUTHSESSION_RESPONSE {
    TPM2_RESPONSE_HEADER Header;
    TPMI_SH_AUTH_SESSION sessionHandle;
    /*TPM2B_NONCE nonceTPM;*/
    ORIG_TPM2B_NONCE nonceTPM;
  } TPM2_STARTAUTHSESSION_RESPONSE;

  typedef struct _ORIG_TPML_PCR_SELECTION {
    UINT32 count;
    TPMS_PCR_SELECTION pcrSelections[1];
  } ORIG_TPML_PCR_SELECTION;

  typedef struct _TPM2_POLICYPCR_COMMAND {
    TPM2_COMMAND_HEADER Header;
    TPMI_SH_POLICY policySession;
    /*TPM2B_DIGEST pcrDigest;*/
    //ORIG_TPM2B_DIGEST pcrDigest;
    UINT16 pcrDigestZero;
    /*TPML_PCR_SELECTION pcrs;*/
    ORIG_TPML_PCR_SELECTION pcrs;
  } TPM2_POLICYPCR_COMMAND;

  typedef struct _TPM2_POLICYPCR_RESPONSE {
    TPM2_RESPONSE_HEADER Header;
  } TPM2_POLICYPCR_RESPONSE;

  typedef struct _TPM2_PCR_READ_COMMAND {
    TPM2_COMMAND_HEADER Header;
    ORIG_TPML_PCR_SELECTION pcrSelectionIn;
  } TPM2_PCR_READ_COMMAND;

  typedef struct _TPM2_PCR_READ_RESPONSE {
    TPM2_RESPONSE_HEADER Header;
    UINT32 pcrUpdateCounter;
    ORIG_TPML_PCR_SELECTION pcrSelectionOut;
    TPML_DIGEST pcrValues;
  } TPM2_PCR_READ_RESPONSE;

  typedef struct _TPM2_FLUSHCONTEXT_COMMAND {
    TPM2_COMMAND_HEADER Header;
    TPMI_DH_CONTEXT flushHandle;
  } TPM2_FLUSHCONTEXT_COMMAND;

  typedef struct _TPM2_FLUSHCONTEXT_RESPONSE {
    TPM2_RESPONSE_HEADER Header;
  } TPM2_FLUSHCONTEXT_RESPONSE;


  typedef struct _ORIG_AUTH_AREA {
    TPMI_SH_AUTH_SESSION sessionHandle;
    UINT16 nonceSizeZero;
    TPMA_SESSION sessionAttributes;
    UINT16 hmacSizeZero;
  } ORIG_AUTH_AREA;

  typedef struct _TPM2_NV_READ_COMMAND {
    TPM2_COMMAND_HEADER Header;
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    UINT32 authSize;
    ORIG_AUTH_AREA authArea;
    UINT16 size;
    UINT16 offset;
  } TPM2_NV_READ_COMMAND;

  typedef struct _TPM2_NV_READ_RESPONSE {
    TPM2_RESPONSE_HEADER Header;
    UINT32 parameterSize;
    TPM2B_MAX_NV_BUFFER data;
  } TPM2_NV_READ_RESPONSE;

#pragma pack()
