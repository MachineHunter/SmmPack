#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/DebugLib.h>

/**
 
  Define TPM structures used when sealing key.

  TPM has canonicalization mechanism which requires us
  to redefine structure that has "sized buffer".

**/
#pragma pack(1)
  typedef struct {
    UINT16 size;
    BYTE buffer[20];
  } ORIG_TPM2B_NONCE;

  typedef struct {
    TPMI_ALG_SYM algorithmNull;
  } ORIG_TPMT_SYM_DEF;

  typedef struct {
    UINT16 size;
    BYTE buffer[32];
  } ORIG_TPM2B_DIGEST;

  typedef struct {
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

  typedef struct {
    TPM2_RESPONSE_HEADER Header;
    TPMI_SH_AUTH_SESSION sessionHandle;
    /*TPM2B_NONCE nonceTPM;*/
    ORIG_TPM2B_NONCE nonceTPM;
  } TPM2_STARTAUTHSESSION_RESPONSE;

  typedef struct {
    UINT32 count;
    TPMS_PCR_SELECTION pcrSelections[1];
  } ORIG_TPML_PCR_SELECTION;

  typedef struct {
    TPM2_COMMAND_HEADER Header;
    TPMI_SH_POLICY policySession;
    /*TPM2B_DIGEST pcrDigest;*/
    ORIG_TPM2B_DIGEST pcrDigest;
    /*TPML_PCR_SELECTION pcrs;*/
    ORIG_TPML_PCR_SELECTION pcrs;
  } TPM2_POLICYPCR_COMMAND;

  typedef struct {
    TPM2_RESPONSE_HEADER Header;
  } TPM2_POLICYPCR_RESPONSE;

  typedef struct {
    TPM2_COMMAND_HEADER Header;
    TPMI_SH_POLICY policySession;
  } TPM2_POLICYGETDIGEST_COMMAND;

  typedef struct {
    TPM2_RESPONSE_HEADER Header;
    TPM2B_DIGEST policyDigest;
  } TPM2_POLICYGETDIGEST_RESPONSE;

  typedef struct {
    TPM2_COMMAND_HEADER Header;
    TPMI_DH_CONTEXT flushHandle;
  } TPM2_FLUSHCONTEXT_COMMAND;

  typedef struct {
    TPM2_RESPONSE_HEADER Header;
  } TPM2_FLUSHCONTEXT_RESPONSE;

  typedef struct {
    TPM2_COMMAND_HEADER Header;
    UINT16 bytesRequested;
  } TPM2_GET_RANDOM_COMMAND;

  typedef struct {
    TPM2_RESPONSE_HEADER Header;
    TPM2B_DIGEST randomBytes;
  } TPM2_GET_RANDOM_RESPONSE;


  typedef struct {
    TPMI_SH_AUTH_SESSION sessionHandle;
    UINT16 nonceSizeZero;
    TPMA_SESSION sessionAttributes;
    UINT16 hmacSizeZero;
  } ORIG_AUTH_AREA;

  typedef struct {
    UINT16 size;
    TPMI_RH_NV_INDEX nvIndex;
    TPMI_ALG_HASH nameAlg;
    /*TPMA_NV attributes;*/
    UINT32 attributes;
    /*TPM2B_DIGEST authPolicy;*/
    ORIG_TPM2B_DIGEST authPolicy;
    UINT16 dataSize;
  } ORIG_NV_PUBLIC;

  typedef struct {
    UINT16 size;
    BYTE buffer[9];
  } ORIG_AUTH;

  typedef struct {
    TPM2_COMMAND_HEADER Header;
    TPMI_RH_PROVISION authHandle;
    UINT32 authSize;
    ORIG_AUTH_AREA authArea;
    /*TPM2B_AUTH auth;*/
    /*ORIG_AUTH auth;*/
    UINT16 authSizeZero;
    /*TPM2B_NV_PUBLIC publicInfo;*/
    ORIG_NV_PUBLIC publicInfo;
  } TPM2_NV_DEFINE_SPACE_COMMAND;

  typedef struct {
    TPM2_RESPONSE_HEADER Header;
    BYTE auth_area_buf[200];
  } TPM2_NV_DEFINE_SPACE_RESPONSE;


  typedef struct {
    UINT16 size;
    BYTE buffer[16]; 
  } ORIG_MAX_NV_BUFFER;

  typedef struct {
    TPM2_COMMAND_HEADER Header;
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    UINT32 authSize;
    ORIG_AUTH_AREA authArea;
    /*TPM2B_MAX_NV_BUFFER data;*/
    ORIG_MAX_NV_BUFFER data;
    UINT16 offset;
  } TPM2_NV_WRITE_COMMAND;

  typedef struct {
    TPM2_RESPONSE_HEADER Header;
    BYTE auth_area_buf[200];
  } TPM2_NV_WRITE_RESPONSE;
#pragma pack()
