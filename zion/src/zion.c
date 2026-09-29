#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_hart.h>
#include <sbi/riscv_barrier.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include "enclave.h"
#include "tee.h"
#include "tee-mem.h"
#include "ree.h"
#include "sm.h"
#include "pmp.h"
#include "platform-hook.h"

#ifndef TARGET_PLATFORM_HEADER
#error "Zion requires a target platform header"
#endif
#include TARGET_PLATFORM_HEADER

enum zion_init_state {
	ZION_INIT_PENDING = 0,
	ZION_INIT_READY = 1,
	ZION_INIT_DISABLED = -1,
};

static int zion_init_done = ZION_INIT_PENDING;
#ifndef ZION_DYNAMIC_PMP
static int sm_region_id = -1;
static int os_region_id = -1;
#endif
#ifdef ZION_MEGREZ_ACTIVATE
static int sm_alias_region_id = -1;
static int aclint_region_id = -1;
static int high_addr_guard_region_id = -1;
#endif

/* Defined in tee-sbi-opensbi.c — unified CVM + Enclave handler */
extern struct sbi_ecall_extension ecall_zion_tee;

void zion_init(bool cold_boot)
{
	if (cold_boot) {
#ifdef ZION_MEGREZ_ACTIVATE
		uintptr_t alias = 0;
#endif
		tee_log("[SBI] Zion TEE initializing ... hart [%lx]\n",
			   csr_read(mhartid));

		/* Board builds validate H/PMP capabilities before registering an SBI
		 * ABI or modifying PMP state. A failed bring-up probe disables Zion but
		 * intentionally leaves the ordinary OpenSBI -> U-Boot/Linux path alive. */
		if (platform_security_preflight() !=
		    SBI_ERR_SM_ENCLAVE_SUCCESS) {
			zion_init_done = ZION_INIT_DISABLED;
			mb();
			return;
		}
		if (platform_init_global_once() !=
		    SBI_ERR_SM_ENCLAVE_SUCCESS) {
			sm_error("[SM] Zion disabled: platform initialization failed\n");
			zion_init_done = ZION_INIT_DISABLED;
			mb();
			return;
		}

		/* Register unified TEE SBI extension (CVM + Enclave) */
		sbi_ecall_register_extension(&ecall_zion_tee);

		/* Load attestation keys (platform-specific) */
		sm_copy_key();

		/* Initialize enclave metadata array */
		enclave_init_metadata();

		/* Initialize the host/CVM context graph as well.  Enclave-only
		 * bring-up used tee_threads[hart] directly, but CVM SBI helpers
		 * resolve their target through ree.harts[].current_state. */
		ree_metadata_init();
		tee_metadata_init();

		/* Reserve the highest-priority entry for the monitor and a
		 * lowest-priority catch-all entry for normal S/U-mode memory.
		 * Besides isolating the monitor, this ensures a later unaligned
		 * CVM pool is represented by a two-entry TOR range instead of an
		 * entry-zero TOR range starting at physical address zero. */
#ifndef ZION_DYNAMIC_PMP
		if (pmp_region_init_atomic(SMM_BASE, SMM_SIZE, PMP_PRI_TOP,
					   &sm_region_id, 0) ||
#ifdef ZION_MEGREZ_ACTIVATE
		    !platform_security_alias(SMM_BASE, SMM_SIZE, &alias) ||
		    pmp_region_init_atomic(alias, SMM_SIZE, PMP_PRI_ANY,
					   &sm_alias_region_id, 0) ||
		    pmp_region_init_atomic(0x02000000UL, 0x10000UL,
					   PMP_PRI_ANY, &aclint_region_id, 0) ||
		    /* Keep the vendor EIC7700X high-address guard.  The CPU's
		     * hardware prefetcher can speculatively issue cache-line reads
		     * into this unmapped aperture.  Without the guard those reads
		     * reach the system NoC's default NPU error target and raise a
		     * stream of mcput_snoc_mp -> snoc_npu decode interrupts.
		     *
		     * The range is deliberately represented as one two-entry TOR
		     * region, matching the stock OpenSBI policy.  Entries 5 and 6
		     * remain available for the fixed trusted pool and its system-port
		     * alias after the baseline policy is installed. */
		    pmp_region_init_atomic(0x1000000000UL, 0x7000000000UL,
					   PMP_PRI_ANY, &high_addr_guard_region_id,
					   0) ||
#endif
		    pmp_region_init_atomic(0, -1UL, PMP_PRI_BOTTOM,
					   &os_region_id, 1)) {
			sm_error("[SM] fatal: baseline memory protection initialization failed\n");
			sbi_hart_hang();
		}
#endif

		zion_init_done = ZION_INIT_READY;
		mb();
	}

	/* wait until cold-boot hart finishes */
	while (!zion_init_done)
		mb();
	if (zion_init_done == ZION_INIT_DISABLED)
		return;

	/* OpenSBI installs its root-domain PMP table after final_init().  This
	 * early application is needed on secondary-hart paths; the post-domain
	 * hook calls the same routine again after OpenSBI's table is complete. */
	zion_pmp_reconfigure();
	platform_init_global();

	/* Initialize host thread state for this hart.
	 * tee_threads[hart_index] is the host thread. Its state.mode must be REE
	 * so that switch_trap_deleg() uses REE delegation values (not CVM). */
	unsigned int hart_index = zion_current_hart_index();
	tee_threads[hart_index].state.mode = REE;

	/* Disable sstc when menvcfg exists.  Priv v1.11/H v0.6 platforms do
	 * not implement this CSR and continue to use their native timer path. */
	platform_menvcfg_clear(ENVCFG_STCE);
	if (cold_boot) {
		if (platform_has_menvcfg())
			tee_log("[SBI] sstc disabled on all harts\n");
		else
			tee_log("[SBI] menvcfg unavailable; sstc control skipped\n");
	}

	/* Enable counters (skip mcountinhibit — not supported by QEMU) */
	csr_write(CSR_MCOUNTEREN, 0x7);
	csr_write(CSR_SCOUNTEREN, 0x7);

	if (cold_boot)
		tee_log("[SBI] Zion TEE initialized\n");
}

void zion_pmp_reconfigure(void)
{
	int ret = 0;

	if (zion_init_done != ZION_INIT_READY)
		return;

#ifdef ZION_DYNAMIC_PMP
	/* OpenSBI owns the board PMP layout.  A late-starting or resumed hart
	 * only needs the persistent CVM-pool deny replayed after that layout. */
	if (tee_region_id >= 0)
		ret = pmp_set_zion(tee_region_id, PMP_NO_PERM);
#else
	pmp_init();
	ret |= pmp_set_zion(sm_region_id, PMP_NO_PERM);
#ifdef ZION_MEGREZ_ACTIVATE
	ret |= pmp_set_zion(sm_alias_region_id, PMP_NO_PERM);
	ret |= pmp_set_zion(aclint_region_id, PMP_NO_PERM);
	ret |= pmp_set_zion(high_addr_guard_region_id, PMP_NO_PERM);
#endif
	ret |= pmp_set_zion(os_region_id, PMP_ALL_PERM);
	/* A hart started after a secure-pool broadcast must receive all persistent
	 * host-deny regions locally, including the Megrez system-port alias. */
	if (tee_region_id >= 0) {
		ret |= tee_mem_replay_local_pmp_permissions(PMP_NO_PERM);
		if (tee_alias_region_id >= 0)
			ret |= pmp_set_zion(tee_alias_region_id, PMP_NO_PERM);
	}
	pmp_dump_hart();
#endif
	if (ret) {
		sm_error("[SM] fatal: failed to install final Zion PMP policy on hart %u\n",
			 current_hartid());
		sbi_hart_hang();
	}
}

void zion_pmp_finalize(void)
{
#ifdef ZION_MEGREZ_ACTIVATE
	/* The EIC7700X prefetch path can issue transactions with M-mode access
	 * attributes, so an unlocked S/U deny entry is insufficient.  Add PMP_L
	 * only after OpenSBI has installed its root-domain table; locking earlier
	 * would prevent that table from being replaced by Zion's final layout. */
	if (zion_init_done != ZION_INIT_READY)
		return;
	if (pmp_lock_zion(high_addr_guard_region_id, PMP_NO_PERM)) {
		sm_error("[SM] fatal: failed to lock the Megrez high-address guard on hart %u\n",
			 current_hartid());
		sbi_hart_hang();
	}
	pmp_dump_hart();
#endif
}

void zion_enable_counters(void)
{
	/* mcountinhibit CSR (0x320) is optional and not supported by QEMU */
	csr_write(CSR_MCOUNTEREN, 0x7);
	csr_write(CSR_SCOUNTEREN, 0x7);
}
