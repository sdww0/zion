#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_hfence.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_illegal_insn.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_pmu.h>
#include <sbi/sbi_sse.h>
#include <sbi/sbi_timer.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_trap_ldst.h>
#include <sbi/sbi_unpriv.h>
#include <sbi/sbi_bitops.h>
#include "zion.h"
#include "cvm.h"
#include "enclave.h"
#include "tee-mem.h"

#define CVM_SHARED_MEM_FAULT_ADDR_BASE 0x4000000000ULL

/* Enclave path debug logging — comment out to silence */
#define ENCLAVE_LOG
#ifdef ENCLAVE_LOG
#define encl_printf(...) tee_log(__VA_ARGS__)
#else
#define encl_printf(...) do {} while (0)
#endif

static void sbi_trap_error(const char *msg, int rc, ulong mcause, ulong mtval,
			   ulong mtval2, ulong mtinst,
			   struct sbi_trap_regs *regs)
{
	u32 hartid = current_hartid();

	tee_log("[SBI] sbi_trap_error()!!!\n");

	tee_log("%s: hart%d: %s (error %d)\n", __func__, hartid, msg, rc);
	tee_log("%s: hart%d: mcause=0x%" PRILX " mtval=0x%" PRILX "\n",
		   __func__, hartid, mcause, mtval);
	if (misa_extension('H')) {
		tee_log("%s: hart%d: mtval2=0x%" PRILX " mtinst=0x%" PRILX
			   "\n",
			   __func__, hartid, mtval2, mtinst);
	}
	tee_log("%s: hart%d: mepc=0x%" PRILX " mstatus=0x%" PRILX "\n",
		   __func__, hartid, regs->mepc, regs->mstatus);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "ra", regs->ra, "sp", regs->sp);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "gp", regs->gp, "tp", regs->tp);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s0", regs->s0, "s1", regs->s1);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a0", regs->a0, "a1", regs->a1);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a2", regs->a2, "a3", regs->a3);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a4", regs->a4, "a5", regs->a5);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a6", regs->a6, "a7", regs->a7);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s2", regs->s2, "s3", regs->s3);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s4", regs->s4, "s5", regs->s5);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s6", regs->s6, "s7", regs->s7);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s8", regs->s8, "s9", regs->s9);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s10", regs->s10, "s11", regs->s11);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "t0", regs->t0, "t1", regs->t1);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "t2", regs->t2, "t3", regs->t3);
	tee_log("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "t4", regs->t4, "t5", regs->t5);
	tee_log("%s: hart%d: %s=0x%" PRILX "\n", __func__, hartid, "t6",
		   regs->t6);

	sbi_hart_hang();
}

static inline bool is_zion_sbi(unsigned long extid)
{
	if (extid == SBI_EXT_EXPERIMENTAL_zion)
		return true;
	return false;
}

/*
 * dump_translation - Walk VS-stage + G-stage page tables for a VA.
 *
 * Given a VS-mode virtual address, walks the VS-stage page table
 * (VSATP) to find the GPA, then walks the G-stage page table (HGATP)
 * to find the HPA. Prints the full translation chain for debugging.
 *
 * Also dumps the VS-stage PTE at each level so we can see exactly
 * where the translation breaks.
 */
static void dump_translation(uintptr_t va)
{
	uintptr_t vsatp = csr_read(CSR_VSATP);
	uintptr_t hgatp = csr_read(CSR_HGATP);

	sbi_printf("[SM] === Translation dump for VA 0x%lx ===\n", va);
	sbi_printf("[SM]   VSATP=0x%lx HGATP=0x%lx\n", vsatp, hgatp);

	/* ---- Walk VS-stage (Sv39) ---- */
	uintptr_t vs_mode = (vsatp >> 60) & 0xf;
	uintptr_t vs_root_ppn = vsatp & 0xFFFFFFFFFFFUL;
	uintptr_t vs_root_pa = vs_root_ppn << 12;

	if (vs_mode == 0) {
		sbi_printf("[SM]   VSATP mode=BARE (no VS-stage translation)\n");
		sbi_printf("[SM]   VA==GPA: 0x%lx\n", va);
	} else {
		sbi_printf("[SM]   VSATP mode=Sv%lu root=0x%lx\n",
			   (vs_mode == 8) ? 39UL : (vs_mode == 9) ? 48UL : 0UL,
			   vs_root_pa);

		/* Sv39: 3 levels (2,1,0), 9-bit index each */
		pte_t *pt = (pte_t *)vs_root_pa;
		uintptr_t gpa = 0;
		int ok = 0;
		for (int lvl = 2; lvl >= 0; lvl--) {
			uint64_t idx = (va >> (12 + lvl * 9)) & 0x1FF;
			pte_t pte = pt[idx];
			sbi_printf("[SM]   VS L%d[%lu] @ 0x%lx = 0x%lx",
				   lvl, idx, (uintptr_t)&pt[idx], (unsigned long)pte);
			if (!(pte & PTE_V)) {
				sbi_printf(" INVALID\n");
				break;
			}
			uintptr_t ppn = (pte >> 10) & 0xFFFFFFFFFFFUL;
			uintptr_t pa  = ppn << 12;
			if (pte & (PTE_R | PTE_W | PTE_X)) {
				/* Leaf */
				uintptr_t page_size = 1UL << (12 + lvl * 9);
				uintptr_t mask = page_size - 1;
				gpa = (pa & ~mask) | (va & mask);
				sbi_printf(" LEAF → GPA=0x%lx\n", gpa);
				ok = 1;
				break;
			}
			sbi_printf(" → next=0x%lx\n", pa);
			pt = (pte_t *)pa;
		}
		if (!ok) {
			sbi_printf("[SM]   VS-stage: no valid translation for VA 0x%lx\n", va);
			sbi_printf("[SM] === End translation dump ===\n");
			return;
		}

		/* ---- Walk G-stage (Sv48x4) ---- */
		uintptr_t g_root_ppn = hgatp & 0xFFFFFFFFFFFUL;
		uintptr_t g_root_pa  = g_root_ppn << 12;
		/* Sv48x4: 4 levels (3,2,1,0), level-3 index is 2 extra bits (bits 47:39 → 11 bits) */
		pt = (pte_t *)g_root_pa;
		uintptr_t hpa = 0;
		ok = 0;
		for (int lvl = 3; lvl >= 0; lvl--) {
			uint64_t idx;
			if (lvl == 3)
				idx = (gpa >> 39) & 0x7FF; /* 11 bits for level 3 */
			else
				idx = (gpa >> (12 + lvl * 9)) & 0x1FF;
			pte_t pte = pt[idx];
			sbi_printf("[SM]   G  L%d[%lu] @ 0x%lx = 0x%lx",
				   lvl, idx, (uintptr_t)&pt[idx], (unsigned long)pte);
			if (!(pte & PTE_V)) {
				sbi_printf(" INVALID\n");
				break;
			}
			uintptr_t ppn = (pte >> 10) & 0xFFFFFFFFFFFUL;
			uintptr_t pa  = ppn << 12;
			if (pte & (PTE_R | PTE_W | PTE_X)) {
				uintptr_t page_size = (lvl == 1) ? (1UL << 21) :
						      (lvl == 2) ? (1UL << 30) :
						      (1UL << 12);
				uintptr_t mask = page_size - 1;
				hpa = (pa & ~mask) | (gpa & mask);
				sbi_printf(" LEAF → HPA=0x%lx\n", hpa);
				ok = 1;
				break;
			}
			sbi_printf(" → next=0x%lx\n", pa);
			pt = (pte_t *)pa;
		}
		if (!ok)
			sbi_printf("[SM]   G-stage: no valid translation for GPA 0x%lx\n", gpa);
		else
			sbi_printf("[SM]   VA 0x%lx → GPA 0x%lx → HPA 0x%lx\n",
				   va, gpa, hpa);
	}
	sbi_printf("[SM] === End translation dump ===\n");
}

static inline void deliver_trap_to_ree(ulong mepc, ulong mcause,
				       struct sbi_trap_info *trap)
{
	csr_write(CSR_HTVAL, trap->tval2);
	csr_write(CSR_HTINST, trap->tinst);
	csr_write(CSR_STVAL, trap->tval);
	csr_write(CSR_SEPC, mepc);
	csr_write(CSR_SCAUSE, mcause);
}

unsigned long tee_trap_records[TEE_TRAP_STAT_SLOTS];
unsigned long tee_trap_cycles[TEE_TRAP_STAT_SLOTS];

static inline unsigned int decode_mmio_store_rs2_offset(unsigned long insn,
							 unsigned long insn_len)
{
	if (insn_len == 2) {
		if (((insn & INSN_MASK_C_SWSP) == INSN_MATCH_C_SWSP) ||
		    ((insn & INSN_MASK_C_SDSP) == INSN_MATCH_C_SDSP))
			return RVC_RS2(insn);

		if (((insn & INSN_MASK_C_SW) == INSN_MATCH_C_SW) ||
		    ((insn & INSN_MASK_C_SD) == INSN_MATCH_C_SD))
			return RVC_RS2S(insn);
	}

	return RV_X(insn, SH_RS2, 5);
}

static inline unsigned int decode_mmio_load_rd_offset(unsigned long insn,
							unsigned long insn_len)
{
	if (insn_len == 2) {
		if (((insn & INSN_MASK_C_LWSP) == INSN_MATCH_C_LWSP) ||
		    ((insn & INSN_MASK_C_LDSP) == INSN_MATCH_C_LDSP))
			return RV_X(insn, SH_RD, 5);

		if (((insn & INSN_MASK_C_LW) == INSN_MATCH_C_LW) ||
		    ((insn & INSN_MASK_C_LD) == INSN_MATCH_C_LD))
			return RVC_RS2S(insn);
	}

	return RV_X(insn, SH_RD, 5);
}

static int handle_cvm_interrupt(struct sbi_trap_regs *regs,
				struct sbi_trap_info *trap, ulong mcause,
				unsigned int rtid, unsigned int ttid,
				const char **msg)
{
	ulong interrupt_mask = 1UL << (__riscv_xlen - 1);
	ulong interrupt_cause = mcause & ~interrupt_mask;

	switch (interrupt_cause) {
	case IRQ_M_TIMER:
		sbi_timer_process();
		return 0;
	case IRQ_S_TIMER:
		deliver_trap_to_ree(regs->mepc, IRQ_S_TIMER | interrupt_mask,
				    trap);
		return sbi_sm_exit_cvm(regs, rtid, ttid, CVM_EXIT_INTERRUPT,
				       NULL, NULL);
	case IRQ_M_SOFT:
		sbi_ipi_process();
		return 0;
	case IRQ_S_SOFT:
	case IRQ_S_EXT:
		deliver_trap_to_ree(regs->mepc, interrupt_cause | interrupt_mask,
				    trap);
		return sbi_sm_exit_cvm(regs, rtid, ttid, CVM_EXIT_INTERRUPT,
				       NULL, NULL);
	default:
		*msg = "unhandled external interrupt";
		return SBI_ENOTSUPP;
	}
}

static int handle_access_or_vs_ecall(struct sbi_trap_context *tcntx,
				     ulong mcause, unsigned int rtid,
				     unsigned int ttid)
{
	struct sbi_trap_regs *regs = &tcntx->regs;
	struct sbi_trap_info *trap = &tcntx->trap;

	if (mcause == CAUSE_LOAD_ACCESS || mcause == CAUSE_STORE_ACCESS) {
		sbi_pmu_ctr_incr_fw(mcause == CAUSE_LOAD_ACCESS
					    ? SBI_PMU_FW_ACCESS_LOAD
					    : SBI_PMU_FW_ACCESS_STORE);
	}

	if (is_zion_sbi(regs->a7) &&
	    regs->a6 != SBI_SM_REGISTER_SHARED_MEM_WITH_REE &&
	    regs->a6 != SBI_SM_FREE_SHARED_MEM_WITH_REE)
		return sbi_ecall_handler(tcntx);

	if (regs->a7 == SBI_EXT_DBCN &&
	    regs->a6 == SBI_EXT_DBCN_CONSOLE_WRITE_BYTE) {
		tee_log("%c", (char)regs->a0);
	}

	deliver_trap_to_ree(regs->mepc, mcause, trap);
	return sbi_sm_exit_cvm(regs, rtid, ttid, CVM_EXIT_SBI_CALL, NULL,
			       NULL);
}

static int fetch_guest_fault_insn(struct sbi_trap_regs *regs,
				  struct sbi_trap_info *trap,
				  unsigned long *insn,
				  unsigned long *insn_len)
{
	if (trap->tinst & 0x1) {
		/*
		 * Bit[0] == 1 implies trapped instruction value is a
		 * transformed instruction or a custom instruction.
		 */
		*insn = trap->tinst | INSN_16BIT_MASK;
		*insn_len = (trap->tinst & 0x2) ? INSN_LEN(*insn) : 2;
		return 0;
	}

	/*
	 * Bit[0] == 0 implies trapped instruction value is zero or a
	 * special value, so fetch the original instruction.
	 */
	struct sbi_trap_info utrap = { 0 };
	*insn = sbi_get_insn(regs->mepc, &utrap);
	*insn_len = INSN_LEN(*insn);
	if (utrap.cause) {
		tee_log(
			"[SM] cvm_trap_handler: cannot get the insn, cause: %lu, insn: 0x%lx\n",
			utrap.cause, *insn);
		return SBI_ENOTSUPP;
	}

	return 0;
}

static void fill_mmio_exit_reg(struct exit_mmio_reg *exit_mmio_reg,
			       tee_quit_cause exit_cause, unsigned long insn,
			       unsigned long insn_len)
{
	exit_mmio_reg->rs2_offset = 0;
	exit_mmio_reg->rd_offset  = 0;

	if (exit_cause == CVM_EXIT_MMIO_STORE) {
		exit_mmio_reg->rs2_offset =
			decode_mmio_store_rs2_offset(insn, insn_len);
	} else if (exit_cause == CVM_EXIT_MMIO_LOAD) {
		exit_mmio_reg->rd_offset =
			decode_mmio_load_rd_offset(insn, insn_len);
	} else {
		tee_log("[SM] MMIO FAULT: insn=%lx, insn_len=%lx\n", insn,
			   insn_len);
	}
}

static int handle_guest_page_fault(struct sbi_trap_regs *regs,
				   struct sbi_trap_info *trap, ulong mcause,
				   unsigned int rtid, unsigned int ttid,
				   struct cvm_extra_trap_info *extra_trap)
{
	unsigned long insn = 0;
	unsigned long insn_len = 0;
	unsigned long fault_addr = (trap->tval2 << 2) | (trap->tval & 0x3);

	if (fault_addr >= CVM_SHARED_MEM_FAULT_ADDR_BASE) {
		deliver_trap_to_ree(regs->mepc, mcause, trap);
		return sbi_sm_exit_cvm(regs, rtid, ttid,
				       CVM_EXIT_SHARED_MEM_PAGE_FAULT, NULL,
				       NULL);
	}

	zion_printf(
		"[SBI] guest-pf: addr=0x%lx mcause=0x%lx\n",
		fault_addr, mcause);

	struct cvm_mem_info *cvm_mem_info = &cvms[rtid].mem_info;
	if (fault_addr >= cvm_mem_info->guest_phys_addr &&
	    fault_addr < cvm_mem_info->guest_phys_addr +
				 cvm_mem_info->memory_size) {
		if (map_gpa_to_hpa(&g_mem_pool, rtid, fault_addr, 0, BLOCK_SIZE,
				   IS_HUGE_PAGE, false)) {
			tee_log(
				"[SBI] cvm_trap_handler(): Failed to map 2MB block\n");
			tee_log(
				"[SBI] cvm_trap_handler(): rtid=%u, fault_addr=0x%lx\n",
				rtid, fault_addr);
			tee_log("memory pool info: total_count=%d, free_count=%d\n",
				   g_mem_pool.data_pool.total_count,
				   g_mem_pool.data_pool.free_count);
			return -1;
		}

		/*
		 * The CVM G-stage mapping was updated in M-mode, so flush any
		 * stale guest-physical translation before we resume the guest.
		 */
		__sbi_hfence_gvma_all();

		return 0;
	}

	if (fetch_guest_fault_insn(regs, trap, &insn, &insn_len) != 0)
		return SBI_ENOTSUPP;

	extra_trap->htinst	  = insn;
	extra_trap->htinst_len = insn_len;

	tee_quit_cause exit_cause =
		(mcause == CAUSE_STORE_GUEST_PAGE_FAULT ? CVM_EXIT_MMIO_STORE :
							  CVM_EXIT_MMIO_LOAD);
	struct exit_mmio_reg *exit_mmio_reg =
		&cvms[rtid].vcpus[ttid].exit_mmio_reg;

	fill_mmio_exit_reg(exit_mmio_reg, exit_cause, insn, insn_len);

	zion_printf(
		"[SBI] guest-pf: exit=%d insn=0x%lx rs2=%u rd=%u\n",
		exit_cause, insn, exit_mmio_reg->rs2_offset,
		exit_mmio_reg->rd_offset);

	deliver_trap_to_ree(regs->mepc, mcause, trap);
	return sbi_sm_exit_cvm(regs, rtid, ttid, exit_cause, NULL,
			       extra_trap);
}

static int handle_virtual_inst_fault(struct sbi_trap_regs *regs,
				     struct sbi_trap_info *trap,
				     unsigned int rtid, unsigned int ttid,
				     struct cvm_extra_trap_info *extra_trap)
{
	if (trap->tval == 0) {
		struct sbi_trap_info utrap = { 0 };
		unsigned long insn = sbi_get_insn(regs->mepc, &utrap);

		if (utrap.cause) {
			tee_log(
				"[SM] cvm_trap_handler: CAUSE_VIRTUAL_INST_FAULT, cause: %lu\n",
				utrap.cause);
			return SBI_ENOTSUPP;
		}
		trap->tval  = insn;
		trap->tinst = insn;
	}

	extra_trap->htinst	  = trap->tval;
	extra_trap->htinst_len = trap->tinst;

	deliver_trap_to_ree(regs->mepc, CAUSE_VIRTUAL_INST_FAULT, trap);
	return sbi_sm_exit_cvm(regs, rtid, ttid, CVM_EXIT_VIRT_INST, NULL,
			       extra_trap);
}

struct sbi_trap_context *cvm_trap_handler(struct sbi_trap_context *tcntx)
{
	int rc			    = SBI_ENOTSUPP;
	const char *msg		    = "trap handler failed";
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();
	struct sbi_trap_info *trap  = &tcntx->trap;
	struct sbi_trap_regs *regs  = &tcntx->regs;
	ulong mcause		    = tcntx->trap.cause;

	/* Update trap context pointer */
	tcntx->prev_context = sbi_trap_get_context(scratch);
	sbi_trap_set_context(scratch, tcntx);

	if (!(regs->mstatus & MSTATUS_MPV)) {
		/* Previous privilege level is not in virtualization mode. */
		tee_log(
			"[SM] !!!ERROR!!! cvm_trap: mepc=%lx mcause=%lx mstatus=%lx\n",
			regs->mepc, mcause, regs->mstatus);
		sbi_trap_error(msg, rc, mcause, trap->tval, trap->tval2,
			       trap->tinst, regs);
		sbi_hart_hang();
	}

	unsigned int rtid = hart_get_caller_rtid();
	unsigned int ttid = hart_get_caller_ttid();

	if (mcause & (1UL << (__riscv_xlen - 1))) {
		rc = handle_cvm_interrupt(regs, trap, mcause, rtid, ttid, &msg);
		goto trap_done;
	}

	struct cvm_extra_trap_info extra_trap;

	switch (mcause) {
	case CAUSE_ILLEGAL_INSTRUCTION:
		rc  = sbi_illegal_insn_handler(tcntx);
		msg = "illegal instruction handler failed";
		break;
	case CAUSE_MISALIGNED_LOAD:
		rc  = sbi_misaligned_load_handler(tcntx);
		msg = "misaligned load handler failed";
		break;
	case CAUSE_MISALIGNED_STORE:
		rc  = sbi_misaligned_store_handler(tcntx);
		msg = "misaligned store handler failed";
		break;
	case CAUSE_LOAD_ACCESS:
	case CAUSE_STORE_ACCESS:
	case CAUSE_VIRTUAL_SUPERVISOR_ECALL:
		rc = handle_access_or_vs_ecall(tcntx, mcause, rtid, ttid);
		msg = "vs-ecall failed";
		break;
	case CAUSE_FETCH_GUEST_PAGE_FAULT:
	case CAUSE_LOAD_GUEST_PAGE_FAULT:
	case CAUSE_STORE_GUEST_PAGE_FAULT:
		rc = handle_guest_page_fault(regs, trap, mcause, rtid, ttid,
					     &extra_trap);
		break;
	case CAUSE_VIRTUAL_INST_FAULT:
		rc = handle_virtual_inst_fault(regs, trap, rtid, ttid,
					       &extra_trap);
		break;
	default:
		rc  = -1;
		msg = "unhandled excpetion";
		goto trap_done;
	}

trap_done:
	if (rc)
		sbi_trap_error(msg, rc, mcause, trap->tval, trap->tval2,
			       trap->tinst, regs);

	if (((regs->mstatus & MSTATUS_MPP) >> MSTATUS_MPP_SHIFT) != PRV_M)
		sbi_sse_process_pending_events(regs);

	sbi_trap_set_context(scratch, tcntx->prev_context);
	return tcntx;
}

/*
 * enclave_trap_handler - Handle traps from Eyrie runtime (VS-mode enclave).
 *
 * Similar to cvm_trap_handler but dispatches enclave exit instead of
 * CVM exit. Eyrie's VS-mode ecall (CAUSE_VIRTUAL_SUPERVISOR_ECALL)
 * is the primary exit mechanism.
 */
struct sbi_trap_context *enclave_trap_handler(struct sbi_trap_context *tcntx)
{
	int rc			    = SBI_ENOTSUPP;
	const char *msg		    = "enclave trap handler failed";
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();
	struct sbi_trap_info *trap  = &tcntx->trap;
	struct sbi_trap_regs *regs  = &tcntx->regs;
	ulong mcause		    = tcntx->trap.cause;
	ulong interrupt_mask	    = 1UL << (__riscv_xlen - 1);

	/* encl_printf("  trap: cause=0x%lx mepc=0x%lx\n", mcause, regs->mepc); */

	/* Update trap context pointer */
	tcntx->prev_context = sbi_trap_get_context(scratch);
	sbi_trap_set_context(scratch, tcntx);

	unsigned int eid = hart_get_caller_rtid();

	/*
	 * Handle interrupts before the MPV check.  S-mode timer interrupts
	 * delivered to M-mode may not preserve MPV in the saved mstatus
	 * (hardware clears it on certain trap transitions).  Interrupts
	 * have their own dispatch logic and do not require MPV=1.
	 */
	if (mcause & interrupt_mask) {
		ulong interrupt_cause = mcause & ~interrupt_mask;

		switch (interrupt_cause) {
		case IRQ_M_TIMER:
			/* M-timer during enclave: stop and return to host.
			 * This is the standard Keystone preemption mechanism. */
			stop_enclave(regs, STOP_TIMER_INTERRUPT, eid);
			regs->mepc += 4;
			regs->a0 = SBI_ERR_SM_ENCLAVE_INTERRUPTED;
			regs->a1 = 0;
			rc = 0;
			goto trap_done;
		case IRQ_S_TIMER:
			stop_enclave(regs, STOP_TIMER_INTERRUPT, eid);
			regs->mepc += 4;
			regs->a0 = SBI_ERR_SM_ENCLAVE_INTERRUPTED;
			regs->a1 = 0;
			rc = 0;
			goto trap_done;
		case IRQ_M_SOFT:
			sbi_ipi_process();
			rc = 0;
			goto trap_done;
		case IRQ_S_SOFT:
		case IRQ_S_EXT:
			stop_enclave(regs, STOP_TIMER_INTERRUPT, eid);
			regs->mepc += 4;
			regs->a0 = SBI_ERR_SM_ENCLAVE_INTERRUPTED;
			regs->a1 = 0;
			rc = 0;
			goto trap_done;
		default:
			msg = "unhandled enclave interrupt";
			rc = SBI_ENOTSUPP;
			goto trap_done;
		}
	}

	/* Exception handling.
	 *
	 * When exceptions are delegated via medeleg to S-mode (HS-mode)
	 * and then via hedeleg to VS-mode, the hardware does NOT set
	 * mstatus.MPV — it sets sstatus.SPV instead.  So we cannot
	 * rely on MPV to determine whether this exception came from
	 * the enclave.  Trust the caller_rtid/hart context instead.
	 *
	/* Log a warning if MPV is unexpectedly clear, but continue. */
	if (!(regs->mstatus & MSTATUS_MPV)) {
		encl_printf("[SM] encl_trap: MPV=0, mepc=0x%lx mcause=0x%lx "
			    "mstatus=0x%lx (delegated exception)\n",
			    regs->mepc, mcause, regs->mstatus);
	}

	switch (mcause) {
	case CAUSE_ILLEGAL_INSTRUCTION:
	{
		encl_printf("\n");
		encl_printf("[SM] ┌─────────────────────────────────────────┐\n");
		encl_printf("[SM] │  !! ILLEGAL INSTRUCTION — HANGING !!    │\n");
		encl_printf("[SM] ├─────────────────────────────────────────┤\n");
		encl_printf("[SM] │   mepc    = 0x%lx  mstatus = 0x%lx\n",
			    regs->mepc, regs->mstatus);
		encl_printf("[SM] │   mtval   = 0x%lx\n", csr_read(CSR_MTVAL));

		/* ---- G-stage page table walk diagnostic ---- */
		uintptr_t gpa = regs->mepc;
		uintptr_t hgatp_val = csr_read(CSR_HGATP);
		uintptr_t root_pt_pa = (hgatp_val & 0xFFFFFFFFFFFULL) << 12;
		encl_printf("[SM] │   hgatp   = 0x%lx  root_pt=0x%lx\n",
			    hgatp_val, root_pt_pa);

		/* Walk G-stage page table (Sv48x4, 4 levels, 9-bit index) */
		pte_t *pt = (pte_t *)root_pt_pa;
		for (int lvl = 3; lvl >= 0; lvl--) {
			uint64_t idx = (gpa >> (12 + lvl * 9)) & 0x1FF;
			pte_t pte = pt[idx];
			encl_printf("[SM] │   level[%d] idx=%lu pte=0x%lx",
				    lvl, (unsigned long)idx, (unsigned long)pte);
			if (!(pte & PTE_V)) {
				encl_printf(" INVALID\n");
				break;
			}
			uintptr_t next_pa = ((pte >> 10) << 12);
			if (lvl == 1 || lvl == 0) {
				/* Leaf PTE */
				uintptr_t hpa = next_pa + (gpa & ((1UL << (12 + lvl * 9)) - 1));
				encl_printf(" → HPA=0x%lx\n", hpa);
				/* Dump first 32 bytes of the HPA */
				uint32_t *code = (uint32_t *)hpa;
				encl_printf("[SM] │   [0x%lx] = %08x %08x %08x %08x\n",
					    hpa, code[0], code[1], code[2], code[3]);
				encl_printf("[SM] │   [0x%lx] = %08x %08x %08x %08x\n",
					    hpa + 16, code[4], code[5], code[6], code[7]);
				break;
			}
			encl_printf(" → next=0x%lx\n", next_pa);
			pt = (pte_t *)next_pa;
		}

		encl_printf("[SM] │   a0=0x%lx  a1=0x%lx  sp=0x%lx  ra=0x%lx\n",
			    regs->a0, regs->a1, regs->sp, regs->ra);
		encl_printf("[SM] │   hgatp   = 0x%lx  hstatus = 0x%lx\n",
			    csr_read(CSR_HGATP), csr_read(CSR_HSTATUS));
		encl_printf("[SM] │   vsatp   = 0x%lx  vstvec  = 0x%lx\n",
			    csr_read(CSR_VSATP), csr_read(CSR_VSTVEC));
		encl_printf("[SM] └─────────────────────────────────────────┘\n");
		while (1) { __asm__ volatile("wfi"); }
		break;
	}
	case CAUSE_MISALIGNED_LOAD:
		rc  = sbi_misaligned_load_handler(tcntx);
		msg = "misaligned load handler failed";
		break;
	case CAUSE_MISALIGNED_STORE:
		rc  = sbi_misaligned_store_handler(tcntx);
		msg = "misaligned store handler failed";
		break;
	case CAUSE_LOAD_ACCESS:
	case CAUSE_STORE_ACCESS:
		sbi_pmu_ctr_incr_fw(mcause == CAUSE_LOAD_ACCESS
					    ? SBI_PMU_FW_ACCESS_LOAD
					    : SBI_PMU_FW_ACCESS_STORE);
		/* Fall through to VS-mode ecall handling */
		/* fallthrough */
	case CAUSE_VIRTUAL_SUPERVISOR_ECALL:
		/* encl_printf("  → VS-ecall: a7=0x%lx a6=0x%lx\n",
			   regs->a7, regs->a6); */
		if (is_zion_sbi(regs->a7)) {
			/* sbi_ecall_handler advances mepc internally */
			rc = sbi_ecall_handler(tcntx);
		} else if (regs->a7 == SBI_EXT_0_1_CONSOLE_PUTCHAR) {
			/* Eyrie legacy putchar: a0 = character */
			tee_log("%c", (char)regs->a0);
			regs->mepc += 4;
			rc = 0;
		} else if (regs->a7 == SBI_EXT_DBCN &&
			   regs->a6 == SBI_EXT_DBCN_CONSOLE_WRITE_BYTE) {
			tee_log("%c", (char)regs->a0);
			regs->mepc += 4;
			rc = 0;
		} else if (regs->a7 == 1111) {
			/* Runtime not_implemented_fatal: a0 = scause of original fault.
			 * Read VSEPC/VSTVAL to get the original fault address
			 * (the runtime trap handler saved context but didn't
			 * modify these CSRs before doing ecall). */
			uintptr_t orig_sepc  = csr_read(CSR_VSEPC);
			uintptr_t orig_stval = csr_read(CSR_VSTVAL);
			sbi_printf("[SM] === Runtime FATAL: a7=1111 a0(scause)=0x%lx sepc=0x%lx ===\n",
				   regs->a0, regs->mepc);
			sbi_printf("[SM]   original fault: vsepc=0x%lx vstval=0x%lx vsatp=0x%lx\n",
				   orig_sepc, orig_stval, csr_read(CSR_VSATP));
			sbi_printf("[SM] Dumping translations for fault address:\n");
			dump_translation(orig_sepc);
			dump_translation(orig_stval);
			/* Also dump eapp code page for comparison */
			sbi_printf("[SM] Dumping eapp code page:\n");
			dump_translation(0x1000);
			dump_translation(0x2000);
			dump_translation(0x3000);
			sbi_printf("[SM] === End FATAL dump, exiting enclave ===\n");
			regs->mepc += 4;
			deliver_trap_to_ree(regs->mepc - 4, mcause, trap);
			rc = exit_enclave(regs, eid);
			regs->mepc += 4;
		} else {
			/* Forward standard SBI ecalls to OpenSBI handler.
			 * sbi_ecall_handler handles mepc internally. */
			tee_log("[SM] forwarding SBI ecall a7=0x%lx a6=0x%lx sepc=0x%lx a0=0x%lx\n",
				   regs->a7, regs->a6, regs->mepc, regs->a0);
			rc = sbi_ecall_handler(tcntx);
			if (rc) {
				tee_log("[SM] SBI ecall failed: a7=0x%lx rc=%ld, exit\n",
					   regs->a7, rc);
				/* Unknown/failed ecall: exit enclave to host */
				regs->mepc += 4;
				deliver_trap_to_ree(regs->mepc - 4, mcause, trap);
				rc = exit_enclave(regs, eid);
				/* After exit_enclave, regs has host context.
				 * host mepc = ecall PC (from run_enclave/resume_enclave).
				 * Must +4 to skip the host's ecall instruction. */
				regs->mepc += 4;
			}
		}
		break;
	case CAUSE_FETCH_GUEST_PAGE_FAULT:
	case CAUSE_LOAD_GUEST_PAGE_FAULT:
	case CAUSE_STORE_GUEST_PAGE_FAULT:
		/*
		 * G-stage page fault in enclave. If the fault address is in
		 * the EPM region, allocate a data block and map it (demand
		 * paging). Otherwise, exit to host.
		 */
		{
	unsigned long fault_addr = (trap->tval2 << 2) | (trap->tval & 0x3);
		struct enclave *enc = &enclaves[eid];

		encl_printf("  → page fault: addr=0x%lx mepc=0x%lx\n",
			   fault_addr, regs->mepc);

		if (enc->mem_info.epm_base &&
		    fault_addr >= enc->mem_info.epm_base &&
		    fault_addr < enc->mem_info.epm_base +
				 enc->mem_info.epm_size) {
				/* Demand-page: allocate 2MB block */
				uint64_t block = alloc_data_block(
					&g_mem_pool.data_pool, eid);
				if (block == (uint64_t)-1) {
					encl_printf("  → page fault: OOM\n");
					rc = -1;
					goto trap_done;
				}
				if (map_gpa_to_hpa(&g_mem_pool, eid + CVM_NUM,
						   fault_addr, block,
						   BLOCK_SIZE, IS_HUGE_PAGE,
						   false)) {
					encl_printf("  → page fault: map failed\n");
					rc = -1;
					goto trap_done;
				}
				__sbi_hfence_gvma_all();
				rc = 0;
			} else if (enc->mem_info.utm_base &&
				   fault_addr >= enc->mem_info.utm_base &&
				   fault_addr < enc->mem_info.utm_base +
						enc->mem_info.utm_size) {
				/* UTM fault: exit to host for setup */
				deliver_trap_to_ree(regs->mepc, mcause, trap);
				rc = exit_enclave(regs, eid);
				/* Skip host's ecall instruction */
				regs->mepc += 4;
		} else {
			/*
			 * Unmapped guest page fault — redirect to VS-mode
			 * so Eyrie's stvec handler can process it (demand-
			 * paging, COW, or clean exit via sbi_stop_enclave).
			 *
			 * Guest page faults (cause 20/21/23) are NOT in
			 * medeleg, so they always reach M-mode.  We inject
			 * them into VS-mode by writing the virtual exception
			 * CSRs and jumping to vstvec.
			 */
			uintptr_t vstvec = csr_read(CSR_VSTVEC);
			encl_printf("  → page fault: unmapped 0x%lx, "
				   "redirect to VS-mode (vstvec=0x%lx)\n",
				   fault_addr, vstvec);
			if (vstvec == 0) {
				encl_printf("  → page fault: no vstvec, "
					   "fatal\n");
				rc = -1;
				goto trap_done;
			}
			csr_write(CSR_VSEPC, regs->mepc);
			csr_write(CSR_VSCAUSE, mcause);
			csr_write(CSR_VSTVAL, fault_addr);
			regs->mepc = vstvec;
			rc = 0;
		}
		}
		break;
	default:
		rc  = -1;
		msg = "unhandled enclave exception";
		goto trap_done;
	}

trap_done:
	if (rc) {
		encl_printf("[SM] ENCLAVE TRAP ERROR: rc=%d mepc=0x%lx mcause=0x%lx mstatus=0x%lx\n",
			   rc, regs->mepc, mcause, regs->mstatus);
		encl_printf("[SM]   tval=0x%lx tval2=0x%lx tinst=0x%lx\n",
			   trap->tval, trap->tval2, trap->tinst);
		sbi_trap_error(msg, rc, mcause, trap->tval, trap->tval2,
			       trap->tinst, regs);
	}

	/* Do NOT call sbi_sse_process_pending_events(regs) here.
	 * After context_switch_from() (via stop_enclave), regs contains
	 * the HOST's return state.  If any SSE event is pending,
	 * sse_event_inject() overwrites regs->mepc and regs->mstatus,
	 * corrupting the host's ecall return address and privilege mode.
	 * This is the same clobber bug fixed in sbi_trap_handler with the
	 * tee_context_switch flag — but enclave_trap_handler has its own
	 * independent call site that was missed.  SSE events will be
	 * delivered to the host kernel on the next M-mode trap cycle. */

	sbi_trap_set_context(scratch, tcntx->prev_context);
	return tcntx;
}

/*
 * tee_dispatch_trap - Dispatch trap to CVM or Enclave handler based
 * on the current Zion mode.
 */
struct sbi_trap_context *tee_dispatch_trap(struct sbi_trap_context *tcntx)
{
	zion_mode mode = hart_get_mode();

	if (mode == ENCLAVE)
		return enclave_trap_handler(tcntx);
	else
		return cvm_trap_handler(tcntx);
}
