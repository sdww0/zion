/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Zion TEE
 *
 * SBI ecall handler for the Zion TEE extension (SBI_EXT_EXPERIMENTAL_zion).
 * Dispatches enclave management calls from enclave VS-mode.
 */

#include <sbi/sbi_ecall.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_console.h>
#include "sm-sbi.h"
#include "sm_call.h"
#include "tee.h"

static int sbi_ecall_tee_handler(unsigned long extid, unsigned long funcid,
				 struct sbi_trap_regs *regs,
				 struct sbi_ecall_return *out)
{
	int retval = 0;

	switch (funcid) {
	case SBI_SM_RESERVE_MEM:
		retval = reserve_mem(regs->a1, regs->a2);
		break;
	case SBI_SM_CREATE_ENCLAVE:
		retval = sbi_sm_create_enclave(&out->value,
					       (uintptr_t)regs->a0);
		break;
	case SBI_SM_DESTROY_ENCLAVE:
		retval = sbi_sm_destroy_enclave((uintptr_t)regs->a0);
		break;
	case SBI_SM_RUN_ENCLAVE:
		retval = sbi_sm_run_enclave(regs, (uintptr_t)regs->a0);
		__builtin_unreachable();
		break;
	case SBI_SM_RESUME_ENCLAVE:
		retval = sbi_sm_resume_enclave(regs, (uintptr_t)regs->a0);
		__builtin_unreachable();
		break;
	case SBI_SM_RANDOM:
		out->value = sbi_sm_random();
		retval = 0;
		break;
	case SBI_SM_ATTEST_ENCLAVE:
		retval = sbi_sm_attest_enclave(regs->a0, regs->a1, regs->a2);
		break;
	case SBI_SM_GET_SEALING_KEY:
		retval = sbi_sm_get_sealing_key(regs->a0, regs->a1, regs->a2);
		break;
	case SBI_SM_STOP_ENCLAVE:
		retval = sbi_sm_stop_enclave(regs, regs->a0);
		out->value = retval;
		break;
	case SBI_SM_EXIT_ENCLAVE:
		retval = sbi_sm_exit_enclave(regs, regs->a0);
		out->value = retval;   /* host reads enclave return value from a1 */
		retval = 0;            /* tell OpenSBI this ecall succeeded */
		break;
	case SBI_SM_CALL_PLUGIN:
		retval = sbi_sm_call_plugin(regs->a0, regs->a1, regs->a2, regs->a3);
		break;
		retval = -1;
		sbi_printf("[SM] sbi_ecall_tee_handler(): unknown funcid %lu\n",
			   funcid);
		break;
	}

	return retval;
}

struct sbi_ecall_extension ecall_zion_tee = {
	.extid_start = SBI_EXT_EXPERIMENTAL_zion,
	.extid_end   = SBI_EXT_EXPERIMENTAL_zion,
	.handle	     = sbi_ecall_tee_handler,
};
