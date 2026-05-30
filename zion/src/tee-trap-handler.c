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

static void sbi_trap_error(const char *msg, int rc, ulong mcause, ulong mtval,
			   ulong mtval2, ulong mtinst,
			   struct sbi_trap_regs *regs)
{
	u32 hartid = current_hartid();

	sbi_printf("[SBI] sbi_trap_error()!!!\n");

	sbi_printf("%s: hart%d: %s (error %d)\n", __func__, hartid, msg, rc);
	sbi_printf("%s: hart%d: mcause=0x%" PRILX " mtval=0x%" PRILX "\n",
		   __func__, hartid, mcause, mtval);
	if (misa_extension('H')) {
		sbi_printf("%s: hart%d: mtval2=0x%" PRILX " mtinst=0x%" PRILX
			   "\n",
			   __func__, hartid, mtval2, mtinst);
	}
	sbi_printf("%s: hart%d: mepc=0x%" PRILX " mstatus=0x%" PRILX "\n",
		   __func__, hartid, regs->mepc, regs->mstatus);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "ra", regs->ra, "sp", regs->sp);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "gp", regs->gp, "tp", regs->tp);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s0", regs->s0, "s1", regs->s1);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a0", regs->a0, "a1", regs->a1);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a2", regs->a2, "a3", regs->a3);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a4", regs->a4, "a5", regs->a5);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a6", regs->a6, "a7", regs->a7);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s2", regs->s2, "s3", regs->s3);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s4", regs->s4, "s5", regs->s5);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s6", regs->s6, "s7", regs->s7);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s8", regs->s8, "s9", regs->s9);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s10", regs->s10, "s11", regs->s11);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "t0", regs->t0, "t1", regs->t1);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "t2", regs->t2, "t3", regs->t3);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "t4", regs->t4, "t5", regs->t5);
	sbi_printf("%s: hart%d: %s=0x%" PRILX "\n", __func__, hartid, "t6",
		   regs->t6);

	sbi_hart_hang();
}

static inline bool is_zion_sbi(unsigned long extid)
{
	if (extid == SBI_EXT_EXPERIMENTAL_zion)
		return true;
	return false;
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
		sbi_printf("%c", (char)regs->a0);
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
		sbi_printf(
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
		sbi_printf("[SM] MMIO FAULT: insn=%lx, insn_len=%lx\n", insn,
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
		"[SBI] cvm_trap_handler: guest page fault, fault_addr=0x%lx, mcause=0x%lx\n",
		fault_addr, mcause);

	struct cvm_mem_info *cvm_mem_info = &cvms[rtid].mem_info;
	if (fault_addr >= cvm_mem_info->guest_phys_addr &&
	    fault_addr < cvm_mem_info->guest_phys_addr +
				 cvm_mem_info->memory_size) {
		if (map_gpa_to_hpa(&g_mem_pool, rtid, fault_addr, 0, BLOCK_SIZE,
				   IS_HUGE_PAGE, false)) {
			sbi_printf(
				"[SBI] cvm_trap_handler(): Failed to map 2MB block\n");
			sbi_printf(
				"[SBI] cvm_trap_handler(): rtid=%u, fault_addr=0x%lx\n",
				rtid, fault_addr);
			sbi_printf("memory pool info: total_count=%d, free_count=%d\n",
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
		"[SBI] cvm_trap_handler: guest page fault, exit_cause=%d, insn=0x%lx, insn_len=%lu, rs2_offset=%u, rd_offset=%u\n",
		exit_cause, insn, insn_len, exit_mmio_reg->rs2_offset,
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
			sbi_printf(
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
		sbi_printf(
			"[SM] !!!ERROR!!! in cvm_trap_handler!!! mepc=%lx, mcause=%lx, mstatus=%lx\n",
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

	sbi_printf("[SM] enclave_trap_handler: mcause=0x%lx mepc=0x%lx mstatus=0x%lx\n",
		   mcause, regs->mepc, regs->mstatus);

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
			/*
			 * Keystone approach: M-timer fired during enclave execution
			 * (host kernel programmed mtimecmp via SBI). Stop the enclave
			 * (not destroy), return to host. Host kernel will service the
			 * timer and resume. This is the primary timer path when sstc
			 * is disabled.
			 */
			deliver_trap_to_ree(regs->mepc,
					    interrupt_cause | interrupt_mask,
					    trap);
			rc = stop_enclave(regs, STOP_TIMER_INTERRUPT, eid);
			goto trap_done;
		case IRQ_S_TIMER:
			/*
			 * S-timer fired during enclave execution (sstc was enabled
			 * by kernel before SM disabled it, or race condition).
			 * Same handling as M-timer: stop enclave, return to host.
			 */
			deliver_trap_to_ree(regs->mepc,
					    interrupt_cause | interrupt_mask,
					    trap);
			rc = stop_enclave(regs, STOP_TIMER_INTERRUPT, eid);
			goto trap_done;
		case IRQ_M_SOFT:
			sbi_ipi_process();
			rc = 0;
			goto trap_done;
		case IRQ_S_SOFT:
		case IRQ_S_EXT:
			deliver_trap_to_ree(regs->mepc,
					    interrupt_cause | interrupt_mask,
					    trap);
			rc = stop_enclave(regs, STOP_TIMER_INTERRUPT, eid);
			goto trap_done;
		default:
			msg = "unhandled enclave interrupt";
			rc = SBI_ENOTSUPP;
			goto trap_done;
		}
	}

	/* Exception handling -- require valid virtual-mode context */
	if (!(regs->mstatus & MSTATUS_MPV)) {
		sbi_printf(
			"[SM] !!!ERROR!!! in enclave_trap_handler!!! mepc=%lx, mcause=%lx, mstatus=%lx\n",
			regs->mepc, mcause, regs->mstatus);
		sbi_trap_error(msg, rc, mcause, trap->tval, trap->tval2,
			       trap->tinst, regs);
		sbi_hart_hang();
	}

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
		sbi_pmu_ctr_incr_fw(mcause == CAUSE_LOAD_ACCESS
					    ? SBI_PMU_FW_ACCESS_LOAD
					    : SBI_PMU_FW_ACCESS_STORE);
		/* Fall through to VS-mode ecall handling */
		/* fallthrough */
	case CAUSE_VIRTUAL_SUPERVISOR_ECALL:
		sbi_printf("[SM] enclave VS-ecall: a7=0x%lx a6=0x%lx a0=0x%lx\n",
			   regs->a7, regs->a6, regs->a0);
		if (is_zion_sbi(regs->a7)) {
			rc = sbi_ecall_handler(tcntx);
		} else if (regs->a7 == SBI_EXT_0_1_CONSOLE_PUTCHAR) {
			/* Eyrie legacy putchar: a0 = character */
			sbi_printf("%c", (char)regs->a0);
			rc = 0;
		} else if (regs->a7 == SBI_EXT_DBCN &&
			   regs->a6 == SBI_EXT_DBCN_CONSOLE_WRITE_BYTE) {
			sbi_printf("%c", (char)regs->a0);
			rc = 0;
		} else {
			/* Unknown ecall: exit enclave to host */
			deliver_trap_to_ree(regs->mepc, mcause, trap);
			rc = exit_enclave(regs, eid);
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
			unsigned long fault_addr =
				(trap->tval2 << 2) | (trap->tval & 0x3);
			struct enclave *enc = &enclaves[eid];

			if (enc->mem_info.epm_base &&
			    fault_addr >= enc->mem_info.epm_base &&
			    fault_addr < enc->mem_info.epm_base +
					 enc->mem_info.epm_size) {
				/* Demand-page: allocate 2MB block */
				uint64_t block = alloc_data_block(
					&g_mem_pool.data_pool, eid);
				if (block == (uint64_t)-1) {
					sbi_printf("[SM] enclave page fault: "
						   "out of data blocks, eid=%u\n",
						   eid);
					rc = -1;
					goto trap_done;
				}
				if (map_gpa_to_hpa(&g_mem_pool, eid + CVM_NUM,
						   fault_addr, block,
						   BLOCK_SIZE, IS_HUGE_PAGE,
						   false)) {
					sbi_printf("[SM] enclave page fault: "
						   "map failed, eid=%u, "
						   "addr=0x%lx\n",
						   eid, fault_addr);
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
			} else {
				sbi_printf("[SM] enclave page fault: "
					   "unmapped region, eid=%u, "
					   "addr=0x%lx\n",
					   eid, fault_addr);
				rc = -1;
			}
		}
		break;
	default:
		rc  = -1;
		msg = "unhandled enclave exception";
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
 * tee_dispatch_trap - Dispatch trap to CVM or Enclave handler based
 * on the current Zion mode.
 */
struct sbi_trap_context *tee_dispatch_trap(struct sbi_trap_context *tcntx)
{
	zion_mode mode = hart_get_mode();
	sbi_printf("[SM] tee_dispatch_trap: mode=%d mcause=0x%lx mepc=0x%lx mstatus=0x%lx\n",
		   mode, tcntx->trap.cause, tcntx->regs.mepc, tcntx->regs.mstatus);

	if (mode == ENCLAVE)
		return enclave_trap_handler(tcntx);
	else
		return cvm_trap_handler(tcntx);
}
