#ifndef __SM_CALL_H__
#define __SM_CALL_H__

#include <stddef.h>
#include <stdint.h>

// BKE (Berkeley Zion Enclave)
#define SBI_EXT_EXPERIMENTAL_ZION_ENCLAVE 0x08424b45

#define SBI_SET_TIMER 0
#define SBI_CONSOLE_PUTCHAR 1
#define SBI_CONSOLE_GETCHAR 2

/* Legacy range retained for CVM/host system calls. */
#define FID_RANGE_DEPRECATED      1999
#define SBI_SM_RESERVE_MEM      1014
/* 2000-2999 are called by host */
#define SBI_SM_CREATE_ENCLAVE    2001
#define SBI_SM_DESTROY_ENCLAVE   2002
#define SBI_SM_RUN_ENCLAVE       2003
#define SBI_SM_RESUME_ENCLAVE    2005
#define FID_RANGE_HOST           2999

/* CREATE returns an opaque canonical 32-bit handle. Callers must preserve the
 * full value and must not interpret it as a reusable enclave array index. */
#define SBI_SM_ENCLAVE_HANDLE_MAX UINT32_MAX

/* 3000-3999 are called by enclave */
#define SBI_SM_RANDOM            3001
#define SBI_SM_ATTEST_ENCLAVE    3002
#define SBI_SM_GET_SEALING_KEY   3003
#define SBI_SM_STOP_ENCLAVE      3004
#define SBI_SM_EXIT_ENCLAVE      3006
#define SBI_SM_GET_SEALING_KEY_V1 3007
#define FID_RANGE_ENCLAVE        3999

/* 4000-4999 are experimental */
#define SBI_SM_CALL_PLUGIN        4000
#define FID_RANGE_CUSTOM          4999

/* Sealing response ABI. Function 3003 returns the legacy structure; 3007
 * returns v1 with signed format metadata. */
#define SBI_SM_SEALING_KEY_SIZE             128
#define SBI_SM_SIGNATURE_SIZE                64
#define SBI_SM_SEALING_KEY_RESPONSE_SIZE    192
#define SBI_SM_SEALING_KEY_V1_SIGNED_SIZE   136
#define SBI_SM_SEALING_KEY_V1_RESPONSE_SIZE 200

struct zion_sbi_sealing_key {
  uint8_t key[SBI_SM_SEALING_KEY_SIZE];
  uint8_t signature[SBI_SM_SIGNATURE_SIZE];
};

struct zion_sbi_sealing_key_v1 {
  uint8_t key[SBI_SM_SEALING_KEY_SIZE];
  uint32_t kdf_version;
  uint32_t reserved;
  uint8_t signature[SBI_SM_SIGNATURE_SIZE];
};

typedef char zion_sealing_key_abi_size_check[
  sizeof(struct zion_sbi_sealing_key) ==
  SBI_SM_SEALING_KEY_RESPONSE_SIZE ? 1 : -1];
typedef char zion_sealing_key_v1_abi_size_check[
  sizeof(struct zion_sbi_sealing_key_v1) ==
  SBI_SM_SEALING_KEY_V1_RESPONSE_SIZE ? 1 : -1];

/* Plugin IDs and Call IDs */
#define SM_MULTIMEM_PLUGIN_ID   0x01
#define SM_MULTIMEM_CALL_GET_SIZE 0x01
#define SM_MULTIMEM_CALL_GET_ADDR 0x02

/* Enclave stop reasons requested */
#define STOP_TIMER_INTERRUPT  0
#define STOP_EDGE_CALL_HOST   1
#define STOP_EXIT_ENCLAVE     2

/* Structs for interfacing into the SM */
struct runtime_params_t {
  uintptr_t dram_base;
  uintptr_t dram_size;
  uintptr_t runtime_base;
  uintptr_t user_base;
  uintptr_t free_base;
  uintptr_t untrusted_base;
  uintptr_t untrusted_size;
  uintptr_t free_requested; // for attestation
};

struct zion_sbi_pregion_t {
  uintptr_t paddr;
  size_t size;
};

struct zion_sbi_create_t {
  struct zion_sbi_pregion_t epm_region;
  struct zion_sbi_pregion_t utm_region;

  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;
  uintptr_t free_requested;
};

#endif  // __SM_CALL_H__
