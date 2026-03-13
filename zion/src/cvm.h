#ifndef __CVM_H__
#define __CVM_H__

#include <sbi/sbi_types.h>
#include "zion.h"
#include "tee.h"
#include "ree.h"
#include "crypto.h"

struct cvm_extra_trap_info {
	unsigned long htinst;
	unsigned long htinst_len;
};

struct cvm_mem_info {
	unsigned int slot;
	unsigned int flags;
	unsigned long guest_phys_addr;
	unsigned long memory_size; /* bytes */
	/* start of the userspace allocated memory */
	unsigned long userspace_addr;
	unsigned int private;
};

struct exit_mmio_reg {
	unsigned int rs1_offset;
	unsigned int rs2_offset;
	unsigned int rd_offset;
};

struct cvm_vcpu {
	void *master;
	struct tee_thread *tthread;

	struct kvm_vcpu_channel channel;

	tee_quit_cause exit_cause;
	struct exit_mmio_reg exit_mmio_reg;
};

struct cvm {

	unsigned int owner_rtid;

	// state
	unsigned long hgatp;
	unsigned long pgd;
	struct cvm_mem_info mem_info;

	unsigned int ttid_next;

	// sub
	struct cvm_vcpu vcpus[MAX_CVM_VCPUS];

	struct tee tees[MAX_TEES];
	unsigned int tee_id_next;

	byte hash[MDSIZE];

	struct tee_shared_mem shared_to_mems[MAX_SHARED_MEMS];
	struct tee_shared_mem shared_from_mems[MAX_SHARED_MEMS];

	bool inited;
};

extern struct cvm cvms[MAX_CVMS];

unsigned long create_cvm(struct sbi_trap_regs *regs, unsigned int *tid);
unsigned long init_cvm_vcpu(struct sbi_trap_regs *regs, unsigned int tid,
			    unsigned int *ttid,
			    struct kvm_vcpu_channel *shared_mem);
unsigned long enter_cvm(struct sbi_trap_regs *regs, unsigned int tid,
			unsigned int ttid);
unsigned long exit_cvm(struct sbi_trap_regs *regs, unsigned int tid,
		       unsigned int ttid, tee_quit_cause exit_cause,
		       struct sbi_trap_info *trap,
		       struct cvm_extra_trap_info *extra_trap);
unsigned long destroy_cvm(unsigned int tid);
void set_cvm_mem_info(unsigned int tid, struct cvm_mem_info *mem_info);

#endif
