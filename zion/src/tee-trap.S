#include <sbi/sbi_trap.h>
#include <sbi/riscv_encoding.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_scratch.h>
#include <sbi/trap_macro.S>

  .option norvc
  .section .text.init,"ax",@progbits

.globl __trap_vector_tee
__trap_vector_tee:
	TRAP_SAVE_AND_SETUP_SP_T0

#if __riscv_xlen == 32
#else
	TRAP_SAVE_MEPC_MSTATUS 0
#endif

	TRAP_SAVE_GENERAL_REGS_EXCEPT_SP_T0

#if __riscv_xlen == 32
	TRAP_SAVE_INFO 1 1
#else
	TRAP_SAVE_INFO 0 1
#endif

    /* Call C routine - dispatches to CVM or Enclave handler */
    add    a0, sp, zero
    call    tee_dispatch_trap

	TRAP_RESTORE_GENERAL_REGS_EXCEPT_A0_T0

#if __riscv_xlen == 32
	TRAP_RESTORE_MEPC_MSTATUS 1
#else
	TRAP_RESTORE_MEPC_MSTATUS 0
#endif

	TRAP_RESTORE_A0_T0

    mret

/*
 * tee_mret(struct sbi_trap_regs *regs)
 *
 * Direct mret from SM. Bypasses OpenSBI's sbi_trap_exit entirely.
 * Restores ALL GPRs + mepc + mstatus from the trap regs, then mret.
 * The caller never returns — execution continues at regs->mepc.
 *
 * This is used after context_switch_to() has prepared the enclave's
 * GPRs, CSRs (hstatus, hgatp, etc.) and mstatus (with MPV=1).
 * We only need to restore the trap regs and do mret.
 */

/*
 * tee_mret(struct sbi_trap_regs *regs)
 *
 * Direct mret from SM. Bypasses OpenSBI sbi_trap_exit.
 * Restores GPRs + mepc + mstatus from regs, then mret.
 * Caller never returns.
 */
/*
 * tee_mret(struct sbi_trap_regs *regs)
 *
 * Direct mret from SM, bypasses OpenSBI sbi_trap_exit.
 * a0 = pointer to trap regs. Caller never returns.
 */
.globl tee_mret
tee_mret:
	REG_L	t0, SBI_TRAP_REGS_OFFSET(mepc)(a0)
	csrw	CSR_MEPC, t0
	REG_L	t0, SBI_TRAP_REGS_OFFSET(mstatus)(a0)
	csrw	CSR_MSTATUS, t0

	/* Restore GPRs — a0 and t0 done last */
	REG_L	ra,  SBI_TRAP_REGS_OFFSET(ra)(a0)
	REG_L	sp,  SBI_TRAP_REGS_OFFSET(sp)(a0)
	REG_L	gp,  SBI_TRAP_REGS_OFFSET(gp)(a0)
	REG_L	tp,  SBI_TRAP_REGS_OFFSET(tp)(a0)
	REG_L	t1,  SBI_TRAP_REGS_OFFSET(t1)(a0)
	REG_L	t2,  SBI_TRAP_REGS_OFFSET(t2)(a0)
	REG_L	s0,  SBI_TRAP_REGS_OFFSET(s0)(a0)
	REG_L	s1,  SBI_TRAP_REGS_OFFSET(s1)(a0)
	REG_L	a1,  SBI_TRAP_REGS_OFFSET(a1)(a0)
	REG_L	a2,  SBI_TRAP_REGS_OFFSET(a2)(a0)
	REG_L	a3,  SBI_TRAP_REGS_OFFSET(a3)(a0)
	REG_L	a4,  SBI_TRAP_REGS_OFFSET(a4)(a0)
	REG_L	a5,  SBI_TRAP_REGS_OFFSET(a5)(a0)
	REG_L	a6,  SBI_TRAP_REGS_OFFSET(a6)(a0)
	REG_L	a7,  SBI_TRAP_REGS_OFFSET(a7)(a0)
	REG_L	s2,  SBI_TRAP_REGS_OFFSET(s2)(a0)
	REG_L	s3,  SBI_TRAP_REGS_OFFSET(s3)(a0)
	REG_L	s4,  SBI_TRAP_REGS_OFFSET(s4)(a0)
	REG_L	s5,  SBI_TRAP_REGS_OFFSET(s5)(a0)
	REG_L	s6,  SBI_TRAP_REGS_OFFSET(s6)(a0)
	REG_L	s7,  SBI_TRAP_REGS_OFFSET(s7)(a0)
	REG_L	s8,  SBI_TRAP_REGS_OFFSET(s8)(a0)
	REG_L	s9,  SBI_TRAP_REGS_OFFSET(s9)(a0)
	REG_L	s10, SBI_TRAP_REGS_OFFSET(s10)(a0)
	REG_L	s11, SBI_TRAP_REGS_OFFSET(s11)(a0)
	REG_L	t3,  SBI_TRAP_REGS_OFFSET(t3)(a0)
	REG_L	t4,  SBI_TRAP_REGS_OFFSET(t4)(a0)
	REG_L	t5,  SBI_TRAP_REGS_OFFSET(t5)(a0)
	REG_L	t6,  SBI_TRAP_REGS_OFFSET(t6)(a0)
	REG_L	t0,  SBI_TRAP_REGS_OFFSET(t0)(a0)
	REG_L	a0,  SBI_TRAP_REGS_OFFSET(a0)(a0)

	mret
