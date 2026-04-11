#ifndef __REE_H__
#define __REE_H__
#include "zion.h"
#include "tee.h"

struct kvm_extra_trap_info {
	unsigned long htinst;
	unsigned long htinst_len;
};

struct kvm_cpu_context {
	unsigned long zero;
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	unsigned long sepc;
	unsigned long sstatus;
	unsigned long hstatus;
};

struct kvm_vcpu_csr {
	unsigned long vsstatus;
	unsigned long vsie;
	unsigned long vstvec;
	unsigned long vsscratch;
	unsigned long vsepc;
	unsigned long vscause;
	unsigned long vstval;
	unsigned long hvip;
	unsigned long vsatp;
	unsigned long scounteren;
};

struct kvm_vcpu_channel {
	struct kvm_cpu_context *guest_context;
	struct kvm_vcpu_csr *guest_csr;
	struct kvm_extra_trap_info *extra_trap;
};

struct ree_hart {
	struct tee_thread *tthread;
	struct zion_state *current_state;
};

struct ree {
	struct ree_hart harts[MAX_REE_HARTS];

	struct tee tees[MAX_TEES];
	unsigned int tee_id_next;
};

extern struct ree ree;

struct zion_state *hart_get_caller(void);
unsigned int hart_get_caller_rtid(void);
unsigned int hart_get_caller_ttid(void);
unsigned int hart_get_callee_rtid(unsigned int tid);
zion_mode hart_get_mode(void);
void hart_enter_context(struct tee_thread *d_tthread);
void hart_exit_context(struct tee_thread *s_tthread);
void save_tthread_state(struct zion_state *state, unsigned int rtid,
			unsigned int ttid, struct tee_thread *tthread,
			zion_mode mode);
void ree_metadata_init(void);

#endif
