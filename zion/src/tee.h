#ifndef __TEE_H__
#define __TEE_H__

#include <sbi/sbi_ecall.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_types.h>
#include "zion.h"

#define SBI_EXT_EXPERIMENTAL_zion 0x08424b45

// common
#define SBI_SM_RESERVE_MEM 1014
#define SBI_SM_LOAD_PAGE 1020
#define SBI_SM_REGISTER_PT 1021
#define SBI_SM_SYNC_PT 1034
#define SBI_SM_LOAD_MEM 1025
#define SBI_SM_SET_INITED 1026
#define SBI_SM_CYCLE_BEGIN 1027
#define SBI_SM_CYCLE_END 1028
#define SBI_SM_CLEAN_SEC_MEM 1029

// ree
#define SBI_SM_SET_CVM_MEM_INFO 1018
#define SBI_SM_CREATE_CVM 1015
#define SBI_SM_INIT_CVM_VCPU 1012
#define SBI_SM_ENTER_CVM 1013
#define SBI_SM_EXIT_CVM 1022
#define SBI_SM_DESTROY_CVM 1023

// tee
#define SBI_SM_REGISTER_SHARED_MEM_WITH_REE 1030
#define SBI_SM_FREE_SHARED_MEM_WITH_REE 1031
#define SBI_SM_SHARE_MEM_TO 1032
#define SBI_SM_SHARE_MEM_FROM 1033

// enclave (Keystone compatible)
#define SBI_SM_CREATE_ENCLAVE      2001
#define SBI_SM_DESTROY_ENCLAVE     2002
#define SBI_SM_RUN_ENCLAVE         2003
#define SBI_SM_EXIT_ENCLAVE        2004
#define SBI_SM_COPY_FROM_ENCLAVE   2005
#define SBI_SM_COPY_TO_ENCLAVE     2006
#define SBI_SM_MEMORY_RECLAIM      2007
#define SBI_SM_SET_ENCLAVE_ENTRY   2008

#define FID_RANGE_HOST 2999
#define SBI_SM_RANDOM 3001

#define SBI_SM_GET_SEALING_KEY 3003

struct sbi_load_page {
	unsigned long stash;
	unsigned long pos;
};

struct sbi_load_mem {
	unsigned long stash;
	unsigned long pos;
	unsigned long size;
};

struct sbi_mark_mem {
	unsigned long addr;
	unsigned long num;
	unsigned int eid;
};

struct sbi_register_pt {
	unsigned long gpa;
	unsigned long hfn;
	unsigned long level;
	unsigned int is_huge;
	unsigned int rdonly;
};

struct tee_shared_mem {
	unsigned int rtid;
	unsigned int mode;
	unsigned int idx;
	unsigned long addr;
	unsigned long num;
};

struct sbi_tee_share_mem_req {
	unsigned int s_idx;
	unsigned int d_rtid;
	unsigned int d_mode;
	unsigned int d_idx;
	unsigned long addr;
	unsigned long num;
};

struct tee_gpr {
	uintptr_t slot;
	uintptr_t ra;
	uintptr_t sp;
	uintptr_t gp;
	uintptr_t tp;
	uintptr_t t0;
	uintptr_t t1;
	uintptr_t t2;
	uintptr_t s0;
	uintptr_t s1;
	uintptr_t a0;
	uintptr_t a1;
	uintptr_t a2;
	uintptr_t a3;
	uintptr_t a4;
	uintptr_t a5;
	uintptr_t a6;
	uintptr_t a7;
	uintptr_t s2;
	uintptr_t s3;
	uintptr_t s4;
	uintptr_t s5;
	uintptr_t s6;
	uintptr_t s7;
	uintptr_t s8;
	uintptr_t s9;
	uintptr_t s10;
	uintptr_t s11;
	uintptr_t t3;
	uintptr_t t4;
	uintptr_t t5;
	uintptr_t t6;
} __packed;

struct tee_csr {
	uintptr_t mepc;
	uintptr_t mstatus;
	uintptr_t hstatus;
	uintptr_t scounteren;
	uintptr_t hcounteren;
	uintptr_t hgatp;

	uintptr_t vsstatus;
	uintptr_t vsie;
	uintptr_t vsip;
	uintptr_t vstvec;
	uintptr_t vsscratch;
	uintptr_t vsepc;
	uintptr_t vscause;
	uintptr_t vstval;
	uintptr_t hvip;
	uintptr_t vsatp;
};

struct tee_thread {
	void *master;
	struct tee_gpr gprs;
	struct tee_csr csrs;
	struct zion_state state;
	struct zion_state *prev_state;
};

struct tee {
	unsigned int id;
	zion_mode mode;
};

extern struct tee_thread tee_threads[MAX_TEE_THREADS];
extern unsigned int tee_thread_next;

struct cvm_extra_trap_info;
struct kvm_vcpu_channel;

struct tee_thread *tee_thread_alloc(void);
void tee_thread_free(struct tee_thread *tthread);
unsigned long reserve_mem(unsigned long base, unsigned long count);
unsigned long register_pt(unsigned int tid, struct sbi_register_pt *pt);
unsigned long sync_pt(unsigned int tid, unsigned long gpa,
		      unsigned long pt_paddr);
unsigned long load_mem(unsigned int d_rtid, struct sbi_load_mem *req);
void set_inited(unsigned int tid);
int teem_init(uintptr_t start, unsigned long size);
void tee_metadata_init(void);

unsigned long sbi_sm_reserve_mem(struct sbi_trap_regs *regs, unsigned long type,
				 uintptr_t base, unsigned long count);
unsigned long sbi_sm_create_cvm(struct sbi_trap_regs *regs,
				struct sbi_ecall_return *out);
unsigned long sbi_sm_init_cvm_vcpu(struct sbi_trap_regs *regs, unsigned int tid,
				   struct sbi_ecall_return *out,
				   struct kvm_vcpu_channel *shared_mem_ptr);
unsigned long sbi_sm_enter_cvm(struct sbi_trap_regs *regs, unsigned int tid,
			       unsigned int ttid);
unsigned long sbi_sm_exit_cvm(struct sbi_trap_regs *regs, unsigned int tid,
			      unsigned int ttid, tee_quit_cause exit_cause,
			      struct sbi_trap_info *trap,
			      struct cvm_extra_trap_info *extra_trap);
unsigned long sbi_sm_destroy_cvm(struct sbi_trap_regs *regs, unsigned int tid);
unsigned long sbi_sm_set_cvm_mem_info(struct sbi_trap_regs *regs,
				      unsigned int tid, uintptr_t create_args);
unsigned long sbi_sm_load_mem(struct sbi_trap_regs *regs, unsigned int tid,
			      uintptr_t create_args);
unsigned long sbi_sm_register_pt(struct sbi_trap_regs *regs, unsigned int tid,
				 uintptr_t create_args);
unsigned long sbi_sm_sync_pt(struct sbi_trap_regs *regs, unsigned int tid,
			     unsigned long gpa, unsigned long pt_paddr);
unsigned long sbi_sm_register_shared_mem_with_ree(struct sbi_trap_regs *regs,
						  uintptr_t create_arg);
unsigned long sbi_sm_set_inited(unsigned long tid);
unsigned long sbi_sm_cycle_begin(void);
unsigned long sbi_sm_cycle_end(void);
unsigned long sbi_sm_clean_sec_mem(void);

#endif
