
#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include "zion.h"

typedef enum {
	REE_TO_CVM = 0,
	REE_TO_ENCLAVE,
	CVM_TO_ENCLAVE,
	CVM_TO_CVM,
} context_switch_to_mode;

typedef enum {
	REE_FROM_CVM = 0,
	REE_FROM_ENCLAVE,
	CVM_FROM_ENCLAVE,
	CVM_FROM_CVM,
} context_switch_from_mode;

struct sbi_trap_regs;
struct tee_thread;
struct exit_mmio_reg;
struct cvm_extra_trap_info;
struct kvm_vcpu_channel;

void context_switch_to(struct sbi_trap_regs *regs, struct tee_thread *s_tthread,
		       struct tee_thread *d_tthread,
		       context_switch_to_mode context_mode,
		       tee_quit_cause exit_cause,
		       struct exit_mmio_reg *exit_mmio_reg,
		       struct kvm_vcpu_channel *channel);
void context_switch_from(struct sbi_trap_regs *regs,
			 struct tee_thread *s_tthread,
			 struct tee_thread *d_tthread,
			 context_switch_from_mode context_mode,
			 tee_quit_cause exit_cause,
			 struct exit_mmio_reg *exit_mmio_reg,
			 struct cvm_extra_trap_info *extra_trap,
			 struct kvm_vcpu_channel *channel,
			 int return_on_resume);

#endif
