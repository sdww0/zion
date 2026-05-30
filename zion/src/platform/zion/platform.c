/*
 * Zion platform hooks for Keystone SM.
 *
 * sm.c already defines the global key variables (sm_hash, etc.)
 * and registers the ecall extension. We just provide platform hooks
 * and sm_copy_key() which fills in the key globals.
 */
#include "enclave.h"
#include "pmp.h"
#include "tee-mem.h"
#include <sbi/sbi_string.h>
#include <sbi/sbi_console.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_hfence.h>

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

/* Saved host hgatp — restored when returning from enclave */
static unsigned long host_hgatp;

unsigned long platform_create_enclave(struct enclave *enclave)
{
	/*
	 * Build G-stage page tables for the enclave using tee-mem.
	 *
	 * Enclave regions: [0] = EPM, [1] = UTM (set by keystone create_enclave).
	 * We map GPA=HPA (identity) so the enclave runtime sees correct addresses.
	 */
	uintptr_t epm_base = get_enclave_region_base(enclave->eid, 0);
	size_t    epm_size = get_enclave_region_size(enclave->eid, 0);
	uintptr_t utm_base = get_enclave_region_base(enclave->eid, 1);
	size_t    utm_size = get_enclave_region_size(enclave->eid, 1);

	if (!epm_base || !epm_size) {
		sbi_printf("[SM] platform_create_enclave: eid=%d no EPM\n",
			   enclave->eid);
		return SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
	}

	/* Store memory info for demand paging */
	enclave->mem_info.epm_base = epm_base;
	enclave->mem_info.epm_size = epm_size;
	enclave->mem_info.utm_base = utm_base;
	enclave->mem_info.utm_size = utm_size;

	/* Reset the page table sub-pool for this enclave */
	reset_enclave_pt_pool(&g_mem_pool, (uint32_t)enclave->eid);

	/* Map EPM: GPA=epm_base → HPA=epm_base (identity) */
	int enc_cvm_id = CVM_NUM + enclave->eid;
	int ret = map_gpa_to_hpa(&g_mem_pool, enc_cvm_id,
				 epm_base, epm_base, epm_size, false, false);
	if (ret) {
		sbi_printf("[SM] platform_create_enclave: eid=%d EPM map failed\n",
			   enclave->eid);
		return SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
	}

	/* Map UTM if present */
	if (utm_base && utm_size) {
		ret = map_gpa_to_hpa(&g_mem_pool, enc_cvm_id,
				     utm_base, utm_base, utm_size, false, false);
		if (ret) {
			sbi_printf("[SM] platform_create_enclave: eid=%d UTM map failed\n",
				   enclave->eid);
			return SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
		}
	}

	/* Compute hgatp value */
	void *root_pt = get_enclave_root_pt(&g_mem_pool, (uint32_t)enclave->eid);
	if (!root_pt) {
		sbi_printf("[SM] platform_create_enclave: eid=%d no root PT\n",
			   enclave->eid);
		return SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
	}
	enclave->hgatp = ((unsigned long)root_pt >> PAGE_SHIFT) |
			 (HGATP_MODE_SV39X4 << HGATP_MODE_SHIFT);

	sbi_printf("[SM] platform_create_enclave: eid=%d G-stage ready, hgatp=0x%lx\n",
		   enclave->eid, enclave->hgatp);

	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void platform_switch_to_enclave(struct enclave *enclave)
{
	/* Save host hgatp, load enclave's G-stage page table */
	host_hgatp = csr_read(CSR_HGATP);
	csr_write(CSR_HGATP, enclave->hgatp);
	__sbi_hfence_gvma_all();
}

void platform_switch_from_enclave(struct enclave *enclave)
{
	/* Restore host hgatp and flush TLB */
	csr_write(CSR_HGATP, host_hgatp);
	__sbi_hfence_gvma_all();
}

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
 *
 * In production, these come from the bootrom. For testing,
 * we use embedded test values.
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

/* These are extern in sm.h — defined in sm.c */
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
