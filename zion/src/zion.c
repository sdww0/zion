#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/riscv_barrier.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_csr_detect.h>
#include "enclave.h"
#include "tee.h"
#include "sm.h"
#include "pmp.h"
#include "platform-hook.h"

static int zion_init_done = 0;
unsigned long csr_support = 0b11111;

/* Defined in tee-sbi-opensbi.c — unified CVM + Enclave handler */
extern struct sbi_ecall_extension ecall_zion_tee;

void debug_check_csr_supported(){
	// Check SCR_HSTATUS, CSR_MEDELEG, CSR_HEDELEG, CSR_HENVCFG, CSR_MENVCFG are supported
	struct sbi_trap_info trap = {0};
	unsigned long val = 0;

	val = csr_read_allowed(CSR_MENVCFG, (ulong)&trap);
	if (trap.cause)
		csr_support &= ~CSR_MENVCFG_SUPPORT;
	
	trap.cause = 0;

	val = csr_read_allowed(CSR_HENVCFG, (ulong)&trap);
	if (trap.cause)
		csr_support &= ~CSR_HENVCFG_SUPPORT;
	
	trap.cause = 0;

	val = csr_read_allowed(CSR_HEDELEG, (ulong)&trap);
	if (trap.cause)
		csr_support &= ~CSR_HEDELEG_SUPPORT;
	trap.cause = 0;

	val = csr_read_allowed(CSR_MEDELEG, (ulong)&trap);
	if (trap.cause)	
		csr_support &= ~CSR_MEDELEG_SUPPORT;
	trap.cause = 0;

	val = csr_read_allowed(CSR_HSTATUS, (ulong)&trap);
	if (trap.cause)
		csr_support &= ~CSR_HSTATUS_SUPPORT;
	trap.cause = 0;

	sbi_printf("[SBI] CSR support check: HSTATUS=%d, MEDELEG=%d, HEDELEG=%d, HENVCFG=%d, MENVCFG=%d\n",
		(csr_support & CSR_HSTATUS_SUPPORT) != 0,
		(csr_support & CSR_MEDELEG_SUPPORT) != 0,
		(csr_support & CSR_HEDELEG_SUPPORT) != 0,
		(csr_support & CSR_HENVCFG_SUPPORT) != 0,
		(csr_support & CSR_MENVCFG_SUPPORT) != 0);

}

void zion_init(bool cold_boot)
{
	if (cold_boot) {
		debug_check_csr_supported();

		tee_log("[SBI] Zion TEE initializing ... hart [%lx]\n",
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
		sbi_printf("[SBI] Zion TEE initialized on hart [%lx]\n",
			   csr_read(mhartid));
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
	 * 
	 * Needs to check whether CSR_MENVCFG is supported (Not supported in Milkv megrez)
	 */
	if (csr_support & CSR_MENVCFG_SUPPORT) {
		csr_clear(CSR_MENVCFG, ENVCFG_STCE);
		if (cold_boot)
			tee_log("[SBI] sstc disabled on all harts\n");
	}

	/* Enable counters (skip mcountinhibit — not supported by QEMU) */
	csr_write(CSR_MCOUNTEREN, 0x7);
	csr_write(CSR_SCOUNTEREN, 0x7);
	sbi_printf("[SBI] mcounteren=0x%lx scounteren=0x%lx\n",
		   csr_read(CSR_MCOUNTEREN), csr_read(CSR_SCOUNTEREN));
	if (cold_boot)
		tee_log("[SBI] Zion TEE initialized\n");
}

void zion_enable_counters(void)
{
	/* mcountinhibit CSR (0x320) is optional and not supported by QEMU */
	csr_write(CSR_MCOUNTEREN, 0x7);
	csr_write(CSR_SCOUNTEREN, 0x7);
}
