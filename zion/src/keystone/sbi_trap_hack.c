#include "enclave.h"
#include "zion.h"
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_trap_ldst.h>
#include <sbi/sbi_ipi.h>
/* sbi_trap_ldst.h already included above */
#include <sbi/sbi_timer.h>
#include <sbi/sbi_trap.h>

static void sbi_trap_error(const char *msg, int rc,
				      ulong mcause, ulong mtval, ulong mtval2,
				      ulong mtinst, struct sbi_trap_regs *regs)
{
	u32 hartid = current_hartid();

	tee_log("%s: hart%d: %s (error %d)\n", __func__, hartid, msg, rc);
	tee_log("%s: hart%d: mcause=0x%" PRILX " mtval=0x%" PRILX "\n",
		   __func__, hartid, mcause, mtval);
	if (misa_extension('H')) {
		tee_log("%s: hart%d: mtval2=0x%" PRILX
			   " mtinst=0x%" PRILX "\n",
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

  sbi_sm_exit_enclave(regs, rc);
}


/**
 * Handle trap/interrupt
 *
 * This function is called by firmware linked to OpenSBI
 * library for handling trap/interrupt. It expects the
 * following:
 * 1. The 'mscratch' CSR is pointing to sbi_scratch of current HART
 * 2. The 'mcause' CSR is having exception/interrupt cause
 * 3. The 'mtval' CSR is having additional trap information
 * 4. The 'mtval2' CSR is having additional trap information
 * 5. The 'mtinst' CSR is having decoded trap instruction
 * 6. Stack pointer (SP) is setup for current HART
 * 7. Interrupts are disabled in MSTATUS CSR
 *
 * @param regs pointer to register state
 */
void sbi_trap_handler_keystone_enclave(struct sbi_trap_regs *regs)
{
	int rc = SBI_ENOTSUPP;
	const char *msg = "trap handler failed";
	ulong mcause = csr_read(CSR_MCAUSE);
	ulong mtval = csr_read(CSR_MTVAL), mtval2 = 0, mtinst = 0;
	struct sbi_trap_info trap;

	/* Concise trap line — one per trap */
	const char *cause_str = "unknown";
	if (mcause & (1UL << (__riscv_xlen - 1))) {
		ulong irq = mcause & ~(1UL << (__riscv_xlen - 1));
		switch (irq) {
		case IRQ_M_TIMER: cause_str = "M-timer"; break;
		case IRQ_M_SOFT:  cause_str = "M-soft"; break;
		case IRQ_S_TIMER: cause_str = "S-timer"; break;
		case IRQ_S_EXT:   cause_str = "S-ext"; break;
		default: break;
		}
	} else {
		switch (mcause) {
		case 0:  cause_str = "insn-fetch"; break;
		case 1:  cause_str = "load-access"; break;
		case 2:  cause_str = "illegal-insn"; break;
		case 3:  cause_str = "breakpoint"; break;
		case 4:  cause_str = "load-align"; break;
		case 5:  cause_str = "store-access"; break;
		case 6:  cause_str = "store-align"; break;
		case 7:  cause_str = "ecall-U"; break;
		case 8:  cause_str = "ecall-S"; break;
		case 9:  cause_str = "ecall-VS"; break;
		case 11: cause_str = "ecall-M"; break;
		case 12: cause_str = "fetch-pf"; break;
		case 13: cause_str = "load-pf"; break;
		case 15: cause_str = "store-pf"; break;
		case 16: cause_str = "virt-insn"; break;
		case 20: cause_str = "inst-pf"; break;
		case 22: cause_str = "guest-pf"; break;
		case 23: cause_str = "store-guest-pf"; break;
		default: break;
		}
	}
	tee_log("[SM] trap: cause=%lu (%s) mepc=0x%lx tval=0x%lx\n",
		   mcause, cause_str, regs->mepc, mtval);

	if (regs->mepc == 0) {
		extern unsigned long csr_support;
		sbi_printf("[SM] FATAL: mepc=0, hanging. mcause=%lx mtval=%lx henvcfg=%lx hedeleg=%lx\n",
			   mcause, mtval, csr_support & 0b00010 ? csr_read(CSR_HENVCFG) : 0, csr_read(CSR_HEDELEG));
		while(1) { asm volatile("wfi"); }
	}

	if (misa_extension('H')) {
		mtval2 = csr_read(CSR_MTVAL2);
		mtinst = csr_read(CSR_MTINST);
	}

	if (mcause & (1UL << (__riscv_xlen - 1))) {
		mcause &= ~(1UL << (__riscv_xlen - 1));
		switch (mcause) {
		case IRQ_M_TIMER: {
      sm_debug("[SM]   → stop enclave (timer)\n");
      regs->mepc -= 4;
      sbi_sm_stop_enclave(regs, STOP_TIMER_INTERRUPT);
      regs->a0 = SBI_ERR_SM_ENCLAVE_INTERRUPTED;
      regs->mepc += 4;
			break;
                      }
		case IRQ_M_SOFT: {
      regs->mepc -= 4;
      sbi_sm_stop_enclave(regs, STOP_TIMER_INTERRUPT);
      regs->a0 = SBI_ERR_SM_ENCLAVE_INTERRUPTED;
      regs->mepc += 4;
			break;
                     }
		default:
			msg = "unhandled external interrupt";
			goto trap_error;
		};
		return;
	}

	switch (mcause) {
	case CAUSE_ILLEGAL_INSTRUCTION:
		{ struct sbi_trap_context _tc = { .regs = *regs, .trap = {CAUSE_ILLEGAL_INSTRUCTION, mtval} }; rc = sbi_illegal_insn_handler(&_tc); *regs = _tc.regs; }
		msg = "illegal instruction handler failed";
		break;
	case CAUSE_MISALIGNED_LOAD:
		{ struct sbi_trap_context _tc = { .regs = *regs, .trap = {CAUSE_MISALIGNED_LOAD, mtval, mtval2, mtinst} }; rc = sbi_misaligned_load_handler(&_tc); *regs = _tc.regs; }
		msg = "misaligned load handler failed";
		break;
	case CAUSE_MISALIGNED_STORE:
		{ struct sbi_trap_context _tc = { .regs = *regs, .trap = {CAUSE_MISALIGNED_STORE, mtval, mtval2, mtinst} }; rc = sbi_misaligned_store_handler(&_tc); *regs = _tc.regs; }
		msg = "misaligned store handler failed";
		break;
	case CAUSE_SUPERVISOR_ECALL:
	case CAUSE_VIRTUAL_SUPERVISOR_ECALL:
	case CAUSE_MACHINE_ECALL:
		sm_debug("[SM]   → ecall: a7=0x%lx a6=0x%lx\n", regs->a7, regs->a6);
		{ struct sbi_trap_context _tc = { .regs = *regs, .trap = {CAUSE_MACHINE_ECALL, 0} }; rc = sbi_ecall_handler(&_tc); *regs = _tc.regs; }
		msg = "ecall handler failed";
		break;
	case CAUSE_VIRTUAL_INST_FAULT:
		/* VS-mode virtualized instruction fault.
		 * QEMU doesn't populate mtinst for VIF, so read instruction from memory.
		 * M-mode direct read: PMP_ALL_PERM is set for enclave regions. */
		{
			/* Read instruction directly from mepc (M-mode physical access, PMP allows it) */
			ulong insn = *(volatile ulong *)regs->mepc;

			/* CSR read: opcode=1110011, funct3=010(CSRRS), rs1=x0 */
			if ((insn & 0x7f) == 0x73 && ((insn >> 12) & 0x7) == 2 &&
			    ((insn >> 15) & 0x1f) == 0) {
				uintptr_t csr = (insn >> 20) & 0xfff;
				uintptr_t rd = (insn >> 7) & 0x1f;
				uintptr_t val = 0;
				if (csr == 0xc01) {
					val = csr_read(CSR_MCYCLE);
				} else if (csr == 0xc02) {
					val = csr_read(CSR_MINSTRET);
				} else {
					sm_debug("[SM] unhandled VIF: csr=%lx insn=%lx\n", csr, insn);
					goto trap_error;
				}
				sm_debug("[SM]   → emulate csrr rd=x%ld csr=0x%lx val=0x%lx\n",
					   rd, csr, val);
				if (rd > 0)
					((uintptr_t*)regs)[rd] = val;
				regs->mepc += ((insn & 0x3) == 0x3) ? 4 : 2;
				return;
			}
			sm_debug("[SM] unhandled VIF: insn=%lx mepc=%lx\n", insn, regs->mepc);
			goto trap_error;
		}
		break;
	default:
		/* If the trap came from S or U mode, redirect it there */
		trap.cause = mcause;
		trap.tval = mtval;
		trap.tval2 = mtval2;
		trap.tinst = mtinst;
		rc = sbi_trap_redirect(regs, &trap);
		break;
	};

trap_error:
	if (rc)
		sbi_trap_error(msg, rc, mcause, mtval, mtval2, mtinst, regs);
}
