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
