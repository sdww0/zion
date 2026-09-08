#ifndef __CVM_H__
#define __CVM_H__

#include <sbi/sbi_types.h>
#include <sbi/sbi_hartmask.h>
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

enum cvm_lifecycle {
	CVM_LIFECYCLE_FREE = 0,
	CVM_LIFECYCLE_INITIALIZING,
	CVM_LIFECYCLE_READY,
	CVM_LIFECYCLE_DESTROYING,
};

enum cvm_vcpu_lifecycle {
	CVM_VCPU_FREE = 0,
	CVM_VCPU_INITIALIZING,
	CVM_VCPU_READY,
	CVM_VCPU_RUNNING,
};

struct cvm_vcpu {
	void *master;
	struct tee_thread *tthread;

	struct kvm_vcpu_channel channel;

	tee_quit_cause exit_cause;
	struct exit_mmio_reg exit_mmio_reg;
	enum cvm_vcpu_lifecycle lifecycle;
	unsigned int running_hart_index;
};

struct cvm {

	unsigned int owner_rtid;

	// state
	unsigned long hgatp;
	unsigned long pgd;
	struct cvm_mem_info mem_info;

	unsigned int ttid_next;
	enum cvm_lifecycle lifecycle;
	unsigned int active_ops;
	unsigned int active_vcpus;
	struct sbi_hartmask active_harts;

	// sub
	struct cvm_vcpu vcpus[MAX_CVM_VCPUS];

	struct tee tees[MAX_TEES];
	unsigned long tee_alloc_bitmap;
	unsigned long tee_destroy_bitmap;
	unsigned long tee_retired_bitmap;
	unsigned int tee_generation[MAX_TEES];
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
unsigned long exit_cvm(struct sbi_trap_regs *regs, unsigned int rtid,
		       unsigned int ttid, tee_quit_cause exit_cause,
		       struct sbi_trap_info *trap,
		       struct cvm_extra_trap_info *extra_trap);
unsigned long destroy_cvm(unsigned int tid);
int set_cvm_mem_info(unsigned int tid, struct cvm_mem_info *mem_info);
int cvm_get_by_tid(unsigned int tid, unsigned int *rtid);
int cvm_get_by_rtid(unsigned int rtid);
void cvm_put(unsigned int rtid);
int cvm_map_gpa(unsigned int rtid, uint64_t gpa, uint64_t hpa,
		size_t size, int target_level, uint64_t permissions);
int cvm_remap_gpa(unsigned int rtid, uint64_t gpa, uint64_t hpa,
		  size_t size, int target_level, uint64_t permissions);
bool cvm_hpa_range_is_mapped(uint64_t hpa, size_t size);
int cvm_resolve_private_block(unsigned int rtid, uint64_t gpa,
			      uint64_t *block_hpa, bool *created);
int cvm_set_pt_mode(unsigned int rtid, uint8_t mode);
int cvm_translate_gpa(unsigned int rtid, uint64_t gpa, bool write,
		      uint64_t *hpa, size_t *contiguous);
int cvm_copy_from_gpa(unsigned int rtid, void *dest, uint64_t src_gpa,
		      size_t size);
int cvm_zero_gpa(unsigned int rtid, uint64_t gpa, size_t size);
int cvm_register_enclave(unsigned int rtid, unsigned int eid,
			 unsigned int *handle);
int cvm_resolve_enclave(unsigned int rtid, unsigned int handle,
			unsigned int *eid);
int cvm_begin_enclave_destroy(unsigned int rtid, unsigned int handle,
			      unsigned int *eid);
void cvm_cancel_enclave_destroy(unsigned int rtid, unsigned int handle,
				unsigned int eid);
int cvm_finish_enclave_destroy(unsigned int rtid, unsigned int handle,
			       unsigned int eid);

#endif
