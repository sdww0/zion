/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Zion TEE
 *
 * SBI ecall handler for the Zion TEE extension (SBI_EXT_EXPERIMENTAL_zion).
 * Dispatches enclave management calls from enclave VS-mode.
 *
 * Convention: SM error codes (100000+) are returned via retval (a0).
 * out->value (a1) carries the result (enclave ID, etc.).
 *
 * RUN/RESUME: set out->skip_regs_update = true on success so that
 *   sbi_ecall_handler doesn't overwrite regs (already switched to enclave).
 * EXIT/STOP: return normally; sbi_ecall_handler sets regs->a0/mepc.
 */

#include <sbi/sbi_ecall.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_timer.h>
#include "sm-sbi.h"
#include "sm_call.h"
#include "sm_err.h"
#include "tee.h"
#include "ree.h"
#include "cpu.h"

static bool ree_only_cvm_management_fid(unsigned long funcid)
{
	switch (funcid) {
	case SBI_SM_CREATE_CVM:
	case SBI_SM_INIT_CVM_VCPU:
	case SBI_SM_ENTER_CVM:
	case SBI_SM_DESTROY_CVM:
	case SBI_SM_SET_CVM_MEM_INFO:
	case SBI_SM_LOAD_PAGE:
	case SBI_SM_LOAD_MEM:
	case SBI_SM_REGISTER_PT:
	case SBI_SM_SYNC_PT:
		return true;
	default:
		return false;
	}
}

static int sbi_ecall_tee_handler(unsigned long extid, unsigned long funcid,
				 struct sbi_trap_regs *regs,
				 struct sbi_ecall_return *out)
{
	int retval = 0;
	bool enclave_context = cpu_is_enclave_context();
	bool enclave_mode = hart_get_mode() == ENCLAVE;
	bool enclave_fid = funcid > FID_RANGE_HOST &&
			    funcid <= FID_RANGE_ENCLAVE;

	/* The per-hart execution flag and context graph must agree. Enclaves may
	 * call only their 3000-range ABI and the enclave plugin entry; REE/CVM
	 * callers may call neither. */
	if (enclave_context != enclave_mode ||
	    (enclave_context && !enclave_fid &&
	     funcid != SBI_SM_CALL_PLUGIN) ||
	    (!enclave_context &&
	     (enclave_fid || funcid == SBI_SM_CALL_PLUGIN)))
		return SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED;
	if (hart_get_mode() != REE && ree_only_cvm_management_fid(funcid))
		return SBI_EDENIED;

	switch (funcid) {
	case SBI_SM_RESERVE_MEM:
		retval = hart_get_mode() == REE ? reserve_mem(regs->a1, regs->a2) :
			 SBI_EDENIED;
		break;
	case SBI_SM_EXTEND_MEM:
		retval = hart_get_mode() == REE ?
			extend_mem(regs->a0, regs->a1, &out->value) : SBI_EDENIED;
		break;
	case SBI_SM_REMOVE_MEM_EXTENT:
		retval = hart_get_mode() == REE ? remove_mem_extent(regs->a0) :
			 SBI_EDENIED;
		break;
	case SBI_SM_QUERY_MEM_EXTENT:
		retval = hart_get_mode() == REE ?
			query_mem_extent(regs->a0, regs->a1) : SBI_EDENIED;
		break;

	/* CVM host calls.  Keep these in the unified Zion extension so the
	 * Zion enclave and CVM ABIs can coexist. */
	case SBI_SM_CREATE_CVM:
		retval = sbi_sm_create_cvm(regs, out);
		break;
	case SBI_SM_INIT_CVM_VCPU:
		retval = sbi_sm_init_cvm_vcpu(
			regs, (unsigned int)regs->a0, out,
			(struct kvm_vcpu_channel *)regs->a1);
		break;
	case SBI_SM_ENTER_CVM:
		retval = sbi_sm_enter_cvm(regs, (unsigned int)regs->a0,
					      (unsigned int)regs->a1);
		if (!retval)
			out->skip_regs_update = true;
		break;
	case SBI_SM_EXIT_CVM:
		retval = sbi_sm_exit_cvm(
			regs, (unsigned int)regs->a0, (unsigned int)regs->a1,
			regs->a2, (struct sbi_trap_info *)regs->a3,
			(struct cvm_extra_trap_info *)regs->a4);
		if (!retval)
			out->skip_regs_update = true;
		break;
	case SBI_SM_DESTROY_CVM:
		retval = sbi_sm_destroy_cvm(regs, (unsigned int)regs->a0);
		break;
	case SBI_SM_SET_CVM_MEM_INFO:
		retval = sbi_sm_set_cvm_mem_info(regs, (unsigned int)regs->a0,
						  regs->a1);
		break;
	case SBI_SM_LOAD_PAGE:
		retval = SBI_ENOTSUPP;
		break;
	case SBI_SM_LOAD_MEM:
		retval = sbi_sm_load_mem(regs, (unsigned int)regs->a0,
					     regs->a1);
		break;
	case SBI_SM_REGISTER_PT:
		retval = sbi_sm_register_pt(regs, (unsigned int)regs->a0,
						regs->a1);
		break;
	case SBI_SM_SYNC_PT:
		retval = sbi_sm_sync_pt(regs, (unsigned int)regs->a0, regs->a1,
					     regs->a2);
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
	case SBI_SM_REGISTER_SHARED_MEM_WITH_REE:
		retval = sbi_sm_register_shared_mem_with_ree(regs, regs->a0);
		break;
	case SBI_SM_SHARE_MEM_TO:
	case SBI_SM_SHARE_MEM_FROM:
	case SBI_SM_FREE_SHARED_MEM_WITH_REE:
		retval = SBI_ENOTSUPP;
		break;

	/* Zion enclave calls. */
	case SBI_SM_CREATE_ENCLAVE:
		retval = sbi_sm_create_enclave(&out->value,
					       (uintptr_t)regs->a0);
		break;
	case SBI_SM_DESTROY_ENCLAVE:
		retval = sbi_sm_destroy_enclave((uintptr_t)regs->a0);
		break;
	case SBI_SM_RUN_ENCLAVE:
		retval = sbi_sm_run_enclave(regs, (uintptr_t)regs->a0);
		if (!retval)
			out->skip_regs_update = true;
		break;
	case SBI_SM_RESUME_ENCLAVE:
		retval = sbi_sm_resume_enclave(regs, (uintptr_t)regs->a0);
		if (!retval)
			out->skip_regs_update = true;
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
	case SBI_SM_GET_SEALING_KEY_V1:
		retval = sbi_sm_get_sealing_key_v1(regs->a0, regs->a1,
						regs->a2);
		break;
	case SBI_SM_GET_TIMEBASE_FREQ: {
		const struct sbi_timer_device *timer = sbi_timer_get_device();

		if (!timer || !timer->timer_freq) {
			retval = SBI_EFAIL;
			break;
		}
		out->value = timer->timer_freq;
		retval = 0;
		break;
	}
	case SBI_SM_STOP_ENCLAVE:
		retval = sbi_sm_stop_enclave(regs, regs->a0);
		break;
	case SBI_SM_EXIT_ENCLAVE: {
		/* Capture enclave retval before exit_enclave switches regs to host */
		unsigned long enclave_retval = regs->a0;
		retval = sbi_sm_exit_enclave(regs, enclave_retval);
		out->value = enclave_retval;
		break;
	}
	case SBI_SM_CALL_PLUGIN:
		retval = sbi_sm_call_plugin(regs->a0, regs->a1, regs->a2, regs->a3);
		break;
	default:
		retval = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
		tee_log("[SM] sbi_ecall_tee_handler(): unknown funcid %lu\n",
			   funcid);
		break;
	}

	return retval;
}

struct sbi_ecall_extension ecall_zion_tee = {
	.extid_start = SBI_EXT_EXPERIMENTAL_zion,
	.extid_end   = SBI_EXT_EXPERIMENTAL_zion,
	.handle	 = sbi_ecall_tee_handler,
};
