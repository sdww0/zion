/*
 * Zion platform hooks.
 */
#include "enclave.h"
#include "pmp.h"
#include <sbi/sbi_string.h>
#include <sbi/sbi_console.h>
#include <sbi/riscv_asm.h>

unsigned long platform_init_global_once(void)
{
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long platform_init_global(void)
{
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void platform_init_enclave(struct enclave *enclave) {}
void platform_destroy_enclave(struct enclave *enclave) {}

unsigned long platform_create_enclave(struct enclave *enclave)
{
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void platform_switch_to_enclave(struct enclave *enclave) {}
void platform_switch_from_enclave(struct enclave *enclave) {}

uint64_t platform_random(void)
{
	unsigned long cycles;
	asm volatile("rdcycle %0" : "=r"(cycles));
	cycles ^= cycles >> 12;
	cycles ^= cycles << 25;
	cycles ^= cycles >> 27;
	return cycles * 0x2545F4914F6CDD1DUL;
}

/*
 * sm_copy_key: fills the global key arrays defined in sm.c.
 */
#include "test_dev_key.h"

static const byte test_sm_hash[MDSIZE] = {
	0x4b, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x6e, 0x65,
	0x20, 0x53, 0x4d, 0x20, 0x74, 0x65, 0x73, 0x74,
};

static const byte test_sm_private_key[PRIVATE_KEY_SIZE] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
};

static const byte test_sm_public_key[PUBLIC_KEY_SIZE] = {
	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
	0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
	0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
};

extern byte sm_hash[MDSIZE];
extern byte sm_signature[SIGNATURE_SIZE];
extern byte sm_public_key[PUBLIC_KEY_SIZE];
extern byte sm_private_key[PRIVATE_KEY_SIZE];
extern byte dev_public_key[PUBLIC_KEY_SIZE];

void sm_copy_key(void)
{
	sbi_memcpy(sm_hash, test_sm_hash, MDSIZE);
	sbi_memcpy(sm_private_key, test_sm_private_key, PRIVATE_KEY_SIZE);
	sbi_memcpy(sm_public_key, test_sm_public_key, PUBLIC_KEY_SIZE);
	sbi_memcpy(dev_public_key, _sanctum_dev_public_key, PUBLIC_KEY_SIZE);
	sbi_printf("[SM] Test attestation keys loaded\n");
}
