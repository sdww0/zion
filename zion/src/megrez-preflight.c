/*
 * Minimal, non-activating Milk-V Megrez hardware probe.
 *
 * This file is the only Zion object linked when
 * ZION_MEGREZ_MINIMAL_PREFLIGHT=1.  It deliberately has no monitor state,
 * SBI extension registration, key material, PMP programming, CVM support, or
 * enclave support.  Power-off or reset discards the Recovery-loaded image.
 */
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_csr_detect.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_tlb.h>
#include <sbi/sbi_trap.h>

#include "zion.h"

#define MEGREZ_REQUIRED_PMP_COUNT 8
#define MEGREZ_MAX_PMP_GRANULARITY 12
#define MEGREZ_REQUIRED_PMP_ADDR_BITS 39

/* The recovered OpenSBI core has Zion hooks in its generic TLB and access
 * fault paths.  Phase 0 has no protected memory or Zion-specific PMP IPI
 * messages, so both hooks are intentionally inert in this minimal image. */
void sbi_pmp_ipi_local_update(struct sbi_tlb_info *info)
{
	(void)info;
}

void tee_security_check(unsigned long mtval, unsigned long mcause,
			unsigned long mtval2)
{
	(void)mtval;
	(void)mcause;
	(void)mtval2;
}

void zion_init(bool cold_boot)
{
	struct sbi_scratch *scratch;
	struct sbi_trap_info trap = { 0 };
	unsigned int pmp_count;
	unsigned int pmp_gran;
	unsigned int pmp_addr_bits;
	unsigned long pmpcfg0 = 0;
	unsigned long old_hgatp = 0;
	unsigned long probe_hgatp;
	unsigned long read_hgatp = 0;
	bool h_extension;
	bool hgatp_read_failed = false;
	bool hgatp_restore_failed = false;
	bool ok = true;
	unsigned int i;

	if (!cold_boot)
		return;

	scratch = sbi_scratch_thishart_ptr();
	pmp_count = sbi_hart_pmp_count(scratch);
	pmp_gran = sbi_hart_pmp_log2gran(scratch);
	pmp_addr_bits = sbi_hart_pmp_addrbits(scratch);
	h_extension = misa_extension('H');

	sbi_printf("[ZION-PREFLIGHT] Milk-V Megrez minimal hardware contract\n");
	sbi_printf("[ZION-PREFLIGHT] H=%s PMP=%u granule=%lu bytes PA=%u bits\n",
		   h_extension ? "yes" : "no", pmp_count,
		   pmp_gran < __riscv_xlen ? 1UL << pmp_gran : 0,
		   pmp_addr_bits);
	sbi_printf("[ZION-PREFLIGHT] menvcfg=no henvcfg=no (compiled out)\n");

	if (!h_extension) {
		sbi_printf("[ZION-PREFLIGHT] FAIL: hypervisor extension is absent\n");
		ok = false;
	}
	if (pmp_count < MEGREZ_REQUIRED_PMP_COUNT) {
		sbi_printf("[ZION-PREFLIGHT] FAIL: Zion needs at least %u PMP entries\n",
			   MEGREZ_REQUIRED_PMP_COUNT);
		ok = false;
	}
	if (pmp_gran > MEGREZ_MAX_PMP_GRANULARITY) {
		sbi_printf("[ZION-PREFLIGHT] FAIL: PMP granularity exceeds 4 KiB\n");
		ok = false;
	}
	if (pmp_addr_bits < MEGREZ_REQUIRED_PMP_ADDR_BITS) {
		sbi_printf("[ZION-PREFLIGHT] FAIL: PMP cannot cover the Megrez DDR map\n");
		ok = false;
	}

	if (pmp_count) {
		pmpcfg0 = csr_read_allowed(CSR_PMPCFG0, (ulong)&trap);
		if (trap.cause) {
			sbi_printf("[ZION-PREFLIGHT] FAIL: pmpcfg0 read trapped (cause=%lu)\n",
				   trap.cause);
			ok = false;
		} else {
			for (i = 0; i < pmp_count && i < MEGREZ_REQUIRED_PMP_COUNT; i++) {
				if (pmpcfg0 & (PMP_L << (i * 8))) {
					sbi_printf("[ZION-PREFLIGHT] FAIL: pmp%u is locked by an earlier stage\n",
						   i);
					ok = false;
				}
			}
		}
	}

	if (h_extension) {
		trap.cause = 0;
		old_hgatp = csr_read_allowed(CSR_HGATP, (ulong)&trap);
		if (trap.cause) {
			sbi_printf("[ZION-PREFLIGHT] FAIL: hgatp read trapped (cause=%lu)\n",
				   trap.cause);
			ok = false;
		} else {
			probe_hgatp = HGATP_MODE_SV48X4 << HGATP_MODE_SHIFT;
			trap.cause = 0;
			csr_write_allowed(CSR_HGATP, (ulong)&trap, probe_hgatp);
			if (trap.cause) {
				sbi_printf("[ZION-PREFLIGHT] FAIL: hgatp write trapped (cause=%lu)\n",
					   trap.cause);
				ok = false;
			} else {
				trap.cause = 0;
				read_hgatp = csr_read_allowed(CSR_HGATP, (ulong)&trap);
				hgatp_read_failed = !!trap.cause;
				if (hgatp_read_failed) {
					sbi_printf("[ZION-PREFLIGHT] FAIL: hgatp verification read trapped (cause=%lu)\n",
						   trap.cause);
					ok = false;
				}

				trap.cause = 0;
				csr_write_allowed(CSR_HGATP, (ulong)&trap, old_hgatp);
				hgatp_restore_failed = !!trap.cause;
				if (hgatp_restore_failed) {
					sbi_printf("[ZION-PREFLIGHT] FAIL: hgatp restore trapped (cause=%lu)\n",
						   trap.cause);
					ok = false;
				}

				sbi_printf("[ZION-PREFLIGHT] hgatp Sv48x4 WARL=%s (read=0x%lx)\n",
					   !hgatp_read_failed && !hgatp_restore_failed &&
					   (read_hgatp & (_UL(0xf) << HGATP_MODE_SHIFT)) ==
						   probe_hgatp ? "pass" : "fail",
					   read_hgatp);
				if ((read_hgatp & (_UL(0xf) << HGATP_MODE_SHIFT)) !=
				    probe_hgatp)
					ok = false;
			}
		}
	}

	sbi_printf("[ZION-PREFLIGHT] %s (CSR-level only; VS-mode test still required)\n",
		   ok ? "PASS" : "FAIL");
	sbi_printf("[ZION-PREFLIGHT] Zion remains disabled; full monitor is not linked\n");
}
