#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_trap.h>
#include "tee.h"

static int sbi_ecall_tee_handler(unsigned long extid, unsigned long funcid,
				 struct sbi_trap_regs *regs,
				 struct sbi_ecall_return *out)
{
	uintptr_t retval = -1;

	(void)extid;

	switch (funcid) {
	case SBI_SM_RESERVE_MEM:
		retval = sbi_sm_reserve_mem(regs, regs->a0, regs->a1,
					    regs->a2);
		break;
	case SBI_SM_CREATE_CVM:
		retval = sbi_sm_create_cvm(regs, out);
		break;
	case SBI_SM_INIT_CVM_VCPU:
		retval = sbi_sm_init_cvm_vcpu(regs, (unsigned int)regs->a0, out,
					      (struct kvm_vcpu_channel *)
						      regs->a1);
		break;
	case SBI_SM_ENTER_CVM:
		zion_printf("[SBI] SBI_SM_ENTER_CVM called\n");
		retval = sbi_sm_enter_cvm(regs, regs->a0, regs->a1);
		/* Resume with the context prepared by enter_cvm(). */
		if (!retval)
			out->skip_regs_update = true;
		break;
	case SBI_SM_EXIT_CVM:
		zion_printf("[SBI] SBI_SM_EXIT_CVM called\n");
		retval = sbi_sm_exit_cvm(regs, (unsigned int)regs->a0,
					 (unsigned int)regs->a1, regs->a2,
					 (struct sbi_trap_info *)regs->a3,
					 (struct cvm_extra_trap_info *)regs->a4);
		/* Resume with the REE context restored by exit_cvm(). */
		if (!retval)
			out->skip_regs_update = true;
		break;

	case SBI_SM_DESTROY_CVM:
		retval = sbi_sm_destroy_cvm(regs, (unsigned int)regs->a0);
		break;
	case SBI_SM_REGISTER_PT:
		sbi_printf("[SBI] SBI_SM_REGISTER_PT called\n");
		retval = sbi_sm_register_pt(regs, (unsigned int)regs->a0,
					    regs->a1);
		break;
	case SBI_SM_SYNC_PT:
		retval = sbi_sm_sync_pt(regs, (unsigned int)regs->a0, regs->a1,
					regs->a2);
		break;
	case SBI_SM_LOAD_PAGE:
		retval = -1;
		break;
	case SBI_SM_LOAD_MEM:
		zion_printf("[SBI] SBI_SM_LOAD_MEM called\n");
		retval = sbi_sm_load_mem(regs, regs->a0, regs->a1);
		break;
	case SBI_SM_SET_CVM_MEM_INFO:
		zion_printf("[SBI] SBI_SM_SET_CVM_MEM_INFO called\n");
		retval = sbi_sm_set_cvm_mem_info(regs, regs->a0, regs->a1);
		break;

	case SBI_SM_REGISTER_SHARED_MEM_WITH_REE:
		retval = sbi_sm_register_shared_mem_with_ree(regs, regs->a0);
		break;
	case SBI_SM_SHARE_MEM_TO:
		retval = -1;
		break;
	case SBI_SM_SHARE_MEM_FROM:
		retval = -1;
		break;

	case SBI_SM_SET_INITED:
		retval = sbi_sm_set_inited(regs->a0);
		break;

	case SBI_SM_CYCLE_BEGIN:
		retval = sbi_sm_cycle_begin();
		break;
	case SBI_SM_CYCLE_END:
		retval = sbi_sm_cycle_end();
		break;
	case SBI_SM_CLEAN_SEC_MEM:
		retval = sbi_sm_clean_sec_mem();
		break;
	default:
		retval = -1;
		sbi_printf("[SM] sbi_ecall_cvm_handler(): unknown SBI call\n");
		break;
	}

	return retval;
}

struct sbi_ecall_extension ecall_cvm = {
	.extid_start = SBI_EXT_EXPERIMENTAL_zion,
	.extid_end   = SBI_EXT_EXPERIMENTAL_zion,
	.handle	     = sbi_ecall_tee_handler,
};
