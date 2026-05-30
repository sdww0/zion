#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/riscv_barrier.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include "sm.h"

static int zion_init_done = 0;

void zion_init(bool cold_boot)
{
	if (cold_boot) {
		sbi_printf("[SBI] Zion TEE (Keystone SM) initializing ... hart [%lx]\n",
			   csr_read(mhartid));

		/* sm_init() registers the ecall extension, inits PMP,
		 * copies attestation keys, and inits enclave metadata. */
		sm_init(cold_boot);

		zion_init_done = 1;
		mb();
	}

	/* wait until cold-boot hart finishes */
	while (!zion_init_done)
		mb();

	/*
	 * Disable sstc on every hart: clear menvcfg.STCE.
	 * Forces kernel to use SBI-based timer instead of direct vstimecmp.
	 */
	csr_clear(CSR_MENVCFG, ENVCFG_STCE);
	if (cold_boot)
		sbi_printf("[SBI] sstc disabled on all harts\n");

	/* Enable counters */
	csr_write(CSR_MCOUNTINHIBIT, 0);
	csr_write(CSR_MCOUNTEREN, 0x7);
	csr_write(CSR_SCOUNTEREN, 0x7);

	if (cold_boot)
		sbi_printf("[SBI] Zion TEE initialized (Keystone SM)\n");
}

/*
 * Stub for tee_security_check — called by OpenSBI's sbi_trap.c
 * on load/store access faults. Was part of Zion CVM code.
 * No-op for Keystone-only mode.
 */
void tee_security_check(unsigned long addr, unsigned long cause,
			unsigned long priv)
{
	(void)addr;
	(void)cause;
	(void)priv;
}
