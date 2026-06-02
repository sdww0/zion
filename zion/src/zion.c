#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/riscv_barrier.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include "enclave.h"
#include "tee.h"
#include "sm.h"
#include "pmp.h"
#include "platform-hook.h"

static int zion_init_done = 0;

/* Defined in tee-sbi-opensbi.c — unified CVM + Enclave handler */
extern struct sbi_ecall_extension ecall_zion_tee;

void zion_init(bool cold_boot)
{
	if (cold_boot) {
		sbi_printf("[SBI] Zion TEE initializing ... hart [%lx]\n",
			   csr_read(mhartid));

		/* Register unified TEE SBI extension (CVM + Enclave) */
		sbi_ecall_register_extension(&ecall_zion_tee);

		/* Load attestation keys (platform-specific) */
		sm_copy_key();

		/* Initialize enclave metadata array */
		enclave_init_metadata();

		/* Platform one-time init */
		platform_init_global_once();

		zion_init_done = 1;
		mb();
	}

	/* wait until cold-boot hart finishes */
	while (!zion_init_done)
		mb();

	/* All harts: init PMP and platform */
	pmp_init();
	platform_init_global();

	/* Initialize host thread state for this hart.
	 * tee_threads[mhartid] is the host thread. Its state.mode must be REE
	 * so that switch_trap_deleg() uses REE delegation values (not CVM). */
	unsigned long hart = csr_read(mhartid);
	tee_threads[hart].state.mode = REE;

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
		sbi_printf("[SBI] Zion TEE initialized\n");
}

void zion_enable_counters(void)
{
	csr_write(CSR_MCOUNTINHIBIT, 0);
	csr_write(CSR_MCOUNTEREN, 0x7);
	csr_write(CSR_SCOUNTEREN, 0x7);
}
