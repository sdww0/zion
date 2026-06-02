
#include <sbi/sbi_types.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hfence.h>
#include <sbi/sbi_timer.h>
#include <sbi/riscv_asm.h>
#include "context.h"
#include "cvm.h"
#include "ree.h"
#include "pmp.h"

extern int tee_region_id;

/* Per-hart saved host timer compare value.
 * Saved before enclave entry (which pushes mtimecmp far ahead)
 * and restored on enclave exit so the host kernel's timer events
 * are not lost. */
#define TEE_MAX_HARTS 16
static u64 saved_mtimecmp[TEE_MAX_HARTS] = {0};

#define GUEST_ARG_REG_LIST(_) \
	_(a0)                 \
	_(a1)                 \
	_(a2)                 \
	_(a3)                 \
	_(a4)                 \
	_(a5)                 \
	_(a6)                 \
	_(a7)

#define GUEST_INIT_REG_LIST(_) \
	_(ra)                  \
	_(sp)                  \
	_(gp)                  \
	_(tp)                  \
	_(t0)                  \
	_(t1)                  \
	_(t2)                  \
	_(s0)                  \
	_(s1)                  \
	GUEST_ARG_REG_LIST(_)  \
	_(s2)                  \
	_(s3)                  \
	_(s4)                  \
	_(s5)                  \
	_(s6)                  \
	_(s7)                  \
	_(s8)                  \
	_(s9)                  \
	_(s10)                 \
	_(s11)                 \
	_(t3)                  \
	_(t4)                  \
	_(t5)                  \
	_(t6)

#define GUEST_SAVED_REG_SANITY_LIST(_) \
	_("S2", s2)                    \
	_("S3", s3)                    \
	_("S4", s4)                    \
	_("S5", s5)                    \
	_("S6", s6)                    \
	_("S7", s7)                    \
	_("S8", s8)                    \
	_("S9", s9)                    \
	_("S10", s10)

/* HOST */
static const unsigned long ree_mideleg =
	MIP_SSIP | MIP_VSSIP | MIP_STIP | MIP_VSTIP | MIP_SEIP | MIP_VSEIP |
	MIP_SGEIP;
static const unsigned long ree_hideleg = MIP_VSSIP | MIP_VSTIP | MIP_VSEIP;
static const unsigned long ree_medeleg =
	(1U << CAUSE_MISALIGNED_FETCH) | (1U << CAUSE_BREAKPOINT) |
	(1U << CAUSE_USER_ECALL) | (1U << CAUSE_VIRTUAL_SUPERVISOR_ECALL) |
	(1U << CAUSE_FETCH_PAGE_FAULT) | (1U << CAUSE_LOAD_PAGE_FAULT) |
	(1U << CAUSE_STORE_PAGE_FAULT) | (1U << CAUSE_FETCH_GUEST_PAGE_FAULT) |
	(1U << CAUSE_LOAD_GUEST_PAGE_FAULT) | (1U << CAUSE_VIRTUAL_INST_FAULT) |
	(1U << CAUSE_STORE_GUEST_PAGE_FAULT);
static const unsigned long ree_hedeleg =
	(1U << CAUSE_MISALIGNED_FETCH) | (1U << CAUSE_BREAKPOINT) |
	(1U << CAUSE_USER_ECALL) | (1U << CAUSE_FETCH_PAGE_FAULT) |
	(1U << CAUSE_LOAD_PAGE_FAULT) | (1U << CAUSE_STORE_PAGE_FAULT);

/* TVM */
static const unsigned long cvm_mideleg = MIP_VSSIP | MIP_VSTIP | MIP_VSEIP;
static const unsigned long cvm_hideleg = MIP_VSSIP | MIP_VSTIP | MIP_VSEIP;
static const unsigned long cvm_medeleg =
	(1U << CAUSE_MISALIGNED_FETCH) | (1U << CAUSE_BREAKPOINT) |
	(1U << CAUSE_USER_ECALL) | (1U << CAUSE_FETCH_PAGE_FAULT) |
	(1U << CAUSE_LOAD_PAGE_FAULT) | (1U << CAUSE_STORE_PAGE_FAULT);
static const unsigned long cvm_hedeleg =
	(1U << CAUSE_MISALIGNED_FETCH) | (1U << CAUSE_BREAKPOINT) |
	(1U << CAUSE_USER_ECALL) | (1U << CAUSE_FETCH_PAGE_FAULT) |
	(1U << CAUSE_LOAD_PAGE_FAULT) | (1U << CAUSE_STORE_PAGE_FAULT);

/* ENCLAVE delegation:
 *
 * medeleg must include page faults so they reach HS-mode, where hedeleg
 * can further delegate them to VS-mode (Eyrie's stvec handler).
 *
 * Without medeleg bits, page faults stay in M-mode where there is no
 * VS-mode page fault handler — the runtime's demand-paging and
 * sbi_stop_enclave(STOP_PAGE_FAULT) path never executes.
 *
 * Guest page faults (cause 20/21/23) must NOT be in hedeleg — they
 * always trap to M-mode for G-stage handling by the SM.
 *
 * mideleg=0: all interrupts to M-mode (Keystone pattern). */
static const unsigned long enclave_mideleg = 0;
static const unsigned long enclave_hideleg = 0;
static const unsigned long enclave_medeleg =
	(1U << CAUSE_MISALIGNED_FETCH) | (1U << CAUSE_BREAKPOINT) |
	(1U << CAUSE_USER_ECALL) |
	(1U << CAUSE_FETCH_PAGE_FAULT) |
	(1U << CAUSE_LOAD_PAGE_FAULT) |
	(1U << CAUSE_STORE_PAGE_FAULT);
static const unsigned long enclave_hedeleg =
	(1U << CAUSE_MISALIGNED_FETCH) | (1U << CAUSE_BREAKPOINT) |
	(1U << CAUSE_USER_ECALL) | (1U << CAUSE_FETCH_PAGE_FAULT) |
	(1U << CAUSE_LOAD_PAGE_FAULT) | (1U << CAUSE_STORE_PAGE_FAULT);

static bool invalid_registers_print = false;
static const unsigned long guest_saved_reg_reset_sentinel = 0x1234;

static bool sanitize_guest_saved_reg(const char *reg_name,
				     unsigned long *reg_value)
{
	if (*reg_value == 0)
		return false;

#ifdef DEBUG
	/*
	 * The host-visible shared channel should not drive guest callee-saved
	 * registers after initial entry. Keep this as a debug probe; normal
	 * builds avoid printing it because stale shared values are not the PMP
	 * access-control signal we care about.
	 */
	sbi_printf("[SM] TEE security check: %s register mismatch, value: %lx\n",
		   reg_name, *reg_value);
#else
	(void)reg_name;
#endif
	if (*reg_value == guest_saved_reg_reset_sentinel)
		*reg_value = 0;

	return true;
}

static void check_guest_saved_regs(struct kvm_vcpu_channel *channel)
{
	if (invalid_registers_print)
		return;

#define CHECK_SAVED_REG(label, field)                                          \
	invalid_registers_print |=                                             \
		sanitize_guest_saved_reg(label, &channel->guest_context->field);
	GUEST_SAVED_REG_SANITY_LIST(CHECK_SAVED_REG)
#undef CHECK_SAVED_REG
}

static inline void copy_guest_arg_regs_to_trap_regs(
	struct sbi_trap_regs *regs, const struct kvm_cpu_context *guest_context)
{
#define COPY_GUEST_ARG_TO_TRAP(field) regs->field = guest_context->field;
	GUEST_ARG_REG_LIST(COPY_GUEST_ARG_TO_TRAP)
#undef COPY_GUEST_ARG_TO_TRAP
}

static inline void copy_guest_init_regs_to_trap_regs(
	struct sbi_trap_regs *regs, const struct kvm_cpu_context *guest_context)
{
#define COPY_GUEST_INIT_TO_TRAP(field) regs->field = guest_context->field;
	GUEST_INIT_REG_LIST(COPY_GUEST_INIT_TO_TRAP)
#undef COPY_GUEST_INIT_TO_TRAP
}

static inline void copy_trap_arg_regs_to_guest_context(
	struct kvm_cpu_context *guest_context, const struct sbi_trap_regs *regs)
{
#define COPY_TRAP_ARG_TO_GUEST(field) guest_context->field = regs->field;
	GUEST_ARG_REG_LIST(COPY_TRAP_ARG_TO_GUEST)
#undef COPY_TRAP_ARG_TO_GUEST
}

static inline void sync_trap_pc_from_guest(struct sbi_trap_regs *regs,
					   struct kvm_vcpu_channel *channel)
{
	regs->mepc = channel->guest_context->sepc;
	check_guest_saved_regs(channel);
}

static inline void get_cvm_status_from_ree(struct sbi_trap_regs *regs,
					   tee_quit_cause exit_cause,
					   struct exit_mmio_reg *exit_mmio_reg,
					   struct kvm_vcpu_channel *channel)
{
	csr_write(CSR_SSTATUS, channel->guest_context->sstatus);

	switch (exit_cause) {
	case CVM_EXIT_MMIO_STORE:
	case CVM_EXIT_VIRT_INST:
		sync_trap_pc_from_guest(regs, channel);
		break;
	case CVM_EXIT_MMIO_LOAD:
		zion_printf(
			"[SM] CVM_EXIT_MMIO_LOAD, load value before ree, value: 0x%lx\n",
			((unsigned long *)regs)[exit_mmio_reg->rd_offset]);

		((unsigned long *)regs)[exit_mmio_reg->rd_offset] =
			((unsigned long *)channel
				 ->guest_context)[exit_mmio_reg->rd_offset];

		zion_printf(
			"[SM] CVM_EXIT_MMIO_LOAD, load value from ree, value: 0x%lx\n",
			((unsigned long *)regs)[exit_mmio_reg->rd_offset]);

		sync_trap_pc_from_guest(regs, channel);
		break;
	case CVM_EXIT_SBI_CALL:
		copy_guest_arg_regs_to_trap_regs(regs,
						 channel->guest_context);
		sync_trap_pc_from_guest(regs, channel);
		break;
	case TEE_INIT:
		copy_guest_init_regs_to_trap_regs(regs,
						  channel->guest_context);
		regs->mepc = channel->guest_context->sepc;
		break;
	default:
		break;
	}
}

static inline void put_cvm_status_to_ree(struct sbi_trap_regs *regs,
					 tee_quit_cause exit_cause,
					 struct exit_mmio_reg *exit_mmio_reg,
					 struct cvm_extra_trap_info *extra_trap,
					 struct kvm_vcpu_channel *channel)
{
	channel->guest_context->sstatus = csr_read(CSR_SSTATUS);

	if (extra_trap) {
		channel->extra_trap->htinst	= extra_trap->htinst;
		channel->extra_trap->htinst_len = extra_trap->htinst_len;
	}

	switch (exit_cause) {
	case CVM_EXIT_MMIO_STORE:
		((unsigned long *)
			 channel->guest_context)[exit_mmio_reg->rs2_offset] =
			((unsigned long *)regs)[exit_mmio_reg->rs2_offset];
		zion_printf(
			"[SM] CVM_EXIT_MMIO_STORE, store value to ree, value: 0x%lx\n",
			((unsigned long *)regs)[exit_mmio_reg->rs2_offset]);
		channel->guest_context->sepc = regs->mepc;
		break;
	case CVM_EXIT_MMIO_LOAD:
	case CVM_EXIT_VIRT_INST:
		channel->guest_context->sepc = regs->mepc;
		break;
	case CVM_EXIT_SBI_CALL:
		copy_trap_arg_regs_to_guest_context(channel->guest_context,
						    regs);
		channel->guest_context->sepc = regs->mepc;
		break;
	case CVM_EXIT_INTERRUPT:
	case CVM_EXIT_SHARED_MEM_PAGE_FAULT:
		break;
	default:
		if (exit_cause != CVM_EXIT_INTERRUPT &&
		    exit_cause != CVM_EXIT_SHARED_MEM_PAGE_FAULT) {
			sbi_printf(
				"[SM] !!!ERROR!!! in put_cvm_status_to_ree(), exit_cause=%u\n",
				(unsigned int)exit_cause);
		}
		break;
	}

	channel->guest_context->hstatus = csr_read(CSR_HSTATUS);
}

static void switch_vector_to_tee(void)
{
	extern void __trap_vector_tee();
	csr_write(mtvec, &__trap_vector_tee);
}

static void switch_vector_to_ree(void)
{
	extern void _trap_handler_hyp();
	csr_write(mtvec, &_trap_handler_hyp);
}

static inline void switch_gprs(struct sbi_trap_regs *regs, uintptr_t *s_gprs,
			       uintptr_t *d_gprs, int return_on_resume)
{
	int i;

	for (i = 0; i < 32; i++) {
		s_gprs[i]		   = ((unsigned long *)regs)[i];
		((unsigned long *)regs)[i] = d_gprs[i];
	}
	s_gprs[0] = !return_on_resume;
}

static inline void switch_to_csrs(struct sbi_trap_regs *regs,
				  struct tee_csr *s_csrs,
				  struct tee_csr *d_csrs,
				  context_switch_to_mode context_mode)
{

	s_csrs->mepc = regs->mepc;
	regs->mepc   = d_csrs->mepc;

	s_csrs->mstatus = regs->mstatus;
	regs->mstatus	= d_csrs->mstatus;

#define LOCAL_SWITCH_CSR(csrname)            \
	s_csrs->csrname = csr_read(csrname); \
	csr_write(csrname, d_csrs->csrname);

	if (context_mode == REE_TO_CVM) {

		LOCAL_SWITCH_CSR(hstatus);
		LOCAL_SWITCH_CSR(scounteren);
		// GUEST CSR
		csr_write(CSR_HGATP, d_csrs->hgatp);
		csr_write(CSR_HCOUNTEREN, d_csrs->hcounteren);

		csr_write(CSR_VSSTATUS, d_csrs->vsstatus);
		csr_write(CSR_VSIE, d_csrs->vsie);
		csr_write(CSR_VSIP, d_csrs->vsip);
		csr_write(CSR_VSTVEC, d_csrs->vstvec);
		csr_write(CSR_VSSCRATCH, d_csrs->vsscratch);
		csr_write(CSR_VSEPC, d_csrs->vsepc);
		csr_write(CSR_VSCAUSE, d_csrs->vscause);
		csr_write(CSR_VSTVAL, d_csrs->vstval);
		csr_write(CSR_VSATP, d_csrs->vsatp);
	} else if (context_mode == REE_TO_ENCLAVE) {
		/* Keystone approach: mideleg=0, all interrupts go to M-mode.
		 * M-timer fires → SM stops enclave → host reprograms timer → resume.
		 */

		/* Enclave uses VS-mode CSR set, same as CVM */
		LOCAL_SWITCH_CSR(hstatus);
		LOCAL_SWITCH_CSR(scounteren);
		csr_write(CSR_HGATP, d_csrs->hgatp);
		csr_write(CSR_HCOUNTEREN, d_csrs->hcounteren);

		csr_write(CSR_VSSTATUS, d_csrs->vsstatus);
		csr_write(CSR_VSIE, d_csrs->vsie);
		csr_write(CSR_VSIP, d_csrs->vsip);
		csr_write(CSR_VSTVEC, d_csrs->vstvec);
		csr_write(CSR_VSSCRATCH, d_csrs->vsscratch);
		csr_write(CSR_VSEPC, d_csrs->vsepc);
		csr_write(CSR_VSCAUSE, d_csrs->vscause);
		csr_write(CSR_VSTVAL, d_csrs->vstval);
		csr_write(CSR_VSATP, d_csrs->vsatp);

		/* Save host henvcfg/menvcfg, clear for enclave */
		LOCAL_SWITCH_CSR(henvcfg);
		LOCAL_SWITCH_CSR(menvcfg);
		csr_write(CSR_HENVCFG, 0);
		csr_write(CSR_MENVCFG, 0);

		/* Save host's timer compare value, then push mtimecmp far
		 * into the future so M-timer won't fire immediately on
		 * enclave entry. Without this, if mtime >= mtimecmp
		 * (e.g., host didn't reprogram timer between stop and
		 * resume), the timer fires before the enclave executes
		 * even one instruction, causing an infinite stop/resume loop.
		 *
		 * sbi_timer_event_start programs the actual mtimecmp register
		 * (via ACLINT or Sstc). ~4 billion cycles ≈ 4s at 1GHz. */
		saved_mtimecmp[current_hartid()] = sbi_timer_event_value();
		sbi_timer_event_start(sbi_timer_value() + 0x100000000ULL);
	}
#undef LOCAL_SWITCH_CSR
}

static inline void switch_from_csrs(struct sbi_trap_regs *regs,
				    struct tee_csr *s_csrs,
				    struct tee_csr *d_csrs,
				    context_switch_from_mode context_mode)
{

	s_csrs->mepc = regs->mepc;
	regs->mepc   = d_csrs->mepc;

	s_csrs->mstatus = regs->mstatus;
	regs->mstatus	= d_csrs->mstatus;

#define LOCAL_SWITCH_CSR(csrname)            \
	s_csrs->csrname = csr_read(csrname); \
	csr_write(csrname, d_csrs->csrname);

	if (context_mode == REE_FROM_CVM) {
		LOCAL_SWITCH_CSR(hstatus);
		LOCAL_SWITCH_CSR(scounteren);

		s_csrs->hgatp	   = csr_read_set(CSR_HGATP, 0);
		s_csrs->hcounteren = csr_read_set(CSR_HCOUNTEREN, 0);
		s_csrs->vsstatus   = csr_read_set(CSR_VSSTATUS, 0);
		s_csrs->vsie	   = csr_read_set(CSR_VSIE, 0);
		s_csrs->vsip	   = csr_read_set(CSR_VSIP, 0);
		s_csrs->vstvec	   = csr_read_set(CSR_VSTVEC, 0);
		s_csrs->vsscratch  = csr_read_set(CSR_VSSCRATCH, 0);
		s_csrs->vsepc	   = csr_read_set(CSR_VSEPC, 0);
		s_csrs->vscause	   = csr_read_set(CSR_VSCAUSE, 0);
		s_csrs->vstval	   = csr_read_set(CSR_VSTVAL, 0);
		s_csrs->hvip	   = csr_read_set(CSR_HVIP, 0);
		s_csrs->vsatp	   = csr_read_set(CSR_VSATP, 0);
	} else if (context_mode == REE_FROM_ENCLAVE) {
		/* Keystone approach: mideleg restored by switch_trap_deleg */

		/* Save enclave VS-mode CSRs, restore REE CSRs */
		LOCAL_SWITCH_CSR(hstatus);
		LOCAL_SWITCH_CSR(scounteren);

		/* MUST restore host's hgatp — enclave's G-stage page table
		 * must not remain active after exit. */
		s_csrs->hgatp	   = csr_read_set(CSR_HGATP, 0);
		csr_write(CSR_HGATP, d_csrs->hgatp);
		s_csrs->hcounteren = csr_read_set(CSR_HCOUNTEREN, 0);
		s_csrs->vsstatus   = csr_read_set(CSR_VSSTATUS, 0);
		s_csrs->vsie	   = csr_read_set(CSR_VSIE, 0);
		s_csrs->vsip	   = csr_read_set(CSR_VSIP, 0);
		s_csrs->vstvec	   = csr_read_set(CSR_VSTVEC, 0);
		s_csrs->vsscratch  = csr_read_set(CSR_VSSCRATCH, 0);
		s_csrs->vsepc	   = csr_read_set(CSR_VSEPC, 0);
		s_csrs->vscause	   = csr_read_set(CSR_VSCAUSE, 0);
		s_csrs->vstval	   = csr_read_set(CSR_VSTVAL, 0);
		s_csrs->hvip	   = csr_read_set(CSR_HVIP, 0);
		s_csrs->vsatp	   = csr_read_set(CSR_VSATP, 0);

		/* Restore host henvcfg/menvcfg */
		s_csrs->henvcfg    = csr_read_set(CSR_HENVCFG, 0);
		s_csrs->menvcfg    = csr_read_set(CSR_MENVCFG, 0);
		csr_write(CSR_HENVCFG, d_csrs->henvcfg);
		csr_write(CSR_MENVCFG, d_csrs->menvcfg);

		/* Restore host's timer compare value.
		 * The enclave entry pushed mtimecmp far into the future;
		 * if we don't restore it, the host kernel's next timer
		 * event will be delayed by ~4 seconds, causing RCU stalls
		 * and scheduling freezes. */
		sbi_timer_event_start(saved_mtimecmp[current_hartid()]);
	}
#undef LOCAL_SWITCH_CSR
}

static inline void switch_trap_deleg(struct zion_state *state)
{
	if (state->mode == REE) {
		csr_write(CSR_MIDELEG, ree_mideleg);
		csr_write(CSR_HIDELEG, ree_hideleg);
		csr_write(CSR_MEDELEG, ree_medeleg);
		csr_write(CSR_HEDELEG, ree_hedeleg);
	} else if (state->mode == CVM) {
		csr_write(CSR_MIDELEG, cvm_mideleg);
		csr_write(CSR_HIDELEG, cvm_hideleg);
		csr_write(CSR_MEDELEG, cvm_medeleg);
		csr_write(CSR_HEDELEG, cvm_hedeleg);
	} else if (state->mode == ENCLAVE) {
		csr_write(CSR_MIDELEG, enclave_mideleg);
		csr_write(CSR_HIDELEG, enclave_hideleg);
		csr_write(CSR_MEDELEG, enclave_medeleg);
		csr_write(CSR_HEDELEG, enclave_hedeleg);
	}
}

void context_switch_to(struct sbi_trap_regs *regs, struct tee_thread *s_tthread,
		       struct tee_thread *d_tthread,
		       context_switch_to_mode context_mode,
		       tee_quit_cause exit_cause,
		       struct exit_mmio_reg *exit_mmio_reg,
		       struct kvm_vcpu_channel *channel)
{
	uintptr_t *s_gprs = (uintptr_t *)&s_tthread->gprs;
	uintptr_t *d_gprs = (uintptr_t *)&d_tthread->gprs;

	struct tee_csr *s_csrs = &s_tthread->csrs;
	struct tee_csr *d_csrs = &d_tthread->csrs;

	hart_enter_context(d_tthread);

	// Store the hypervisor registers into their thread registers &
	// Load the CVM private vCPU registers to the context,
	switch_gprs(regs, s_gprs, d_gprs, 1);

	switch_to_csrs(regs, s_csrs, d_csrs, context_mode);

	if (context_mode == REE_TO_CVM) {
		// Get the CVM status from the REE based on the exit cause
		get_cvm_status_from_ree(regs, exit_cause, exit_mmio_reg,
					channel);

		switch_vector_to_tee();
		pmp_set_keystone(tee_region_id, PMP_ALL_PERM);
		__sbi_hfence_gvma_all();
	} else if (context_mode == REE_TO_ENCLAVE) {
		/* Enclave: switch trap vector, lock PMP, flush TLB */
		switch_vector_to_tee();
		pmp_set_keystone(tee_region_id, PMP_ALL_PERM);
		__sbi_hfence_gvma_all();
	}
	switch_trap_deleg(&d_tthread->state);
}

void context_switch_from(struct sbi_trap_regs *regs,
			 struct tee_thread *s_tthread,
			 struct tee_thread *d_tthread,
			 context_switch_from_mode context_mode,
			 tee_quit_cause exit_cause,
			 struct exit_mmio_reg *exit_mmio_reg,
			 struct cvm_extra_trap_info *extra_trap,
			 struct kvm_vcpu_channel *channel, int return_on_resume)
{
	uintptr_t *s_gprs = (uintptr_t *)&s_tthread->gprs;
	uintptr_t *d_gprs = (uintptr_t *)&d_tthread->gprs;

	struct tee_csr *s_csrs = &s_tthread->csrs;
	struct tee_csr *d_csrs = &d_tthread->csrs;

	hart_exit_context(s_tthread);

	if (context_mode == REE_FROM_CVM) {
		put_cvm_status_to_ree(regs, exit_cause, exit_mmio_reg,
				      extra_trap, channel);

		switch_vector_to_ree();
		pmp_set_keystone(tee_region_id, PMP_NO_PERM);
		__sbi_hfence_gvma_all();
	} else if (context_mode == REE_FROM_ENCLAVE) {
		switch_vector_to_ree();
		pmp_set_keystone(tee_region_id, PMP_NO_PERM);
		__sbi_hfence_gvma_all();
	} else if (context_mode == CVM_FROM_ENCLAVE) {
		__sbi_hfence_gvma_all();
	}
	switch_trap_deleg(&d_tthread->state);

	switch_gprs(regs, s_gprs, d_gprs, return_on_resume);
	switch_from_csrs(regs, s_csrs, d_csrs, context_mode);

	/* Forward pending M-mode interrupts as S-mode interrupts so the
	 * host kernel sees them.  During enclave, mideleg=0 means all
	 * interrupts went to M-mode.
	 *
	 * Timer: mtimecmp was already restored by switch_from_csrs above.
	 * If the host's timer has expired, MTIP will be set and will fire
	 * as an M-mode trap on mret. OpenSBI's sbi_timer_process() then
	 * forwards it to S-mode. No need to manually forward MTIP→STIP
	 * (MTIP is read-only in MIP — csr_clear is a no-op).
	 *
	 * Software: MSIP is writable; forward to SSIP for S-mode delivery.
	 * External: MEIP is read-only; inject SEIP so the host sees it. */
	if (context_mode == REE_FROM_ENCLAVE) {
		uintptr_t pending = csr_read(CSR_MIP);
		if (pending & MIP_MSIP) {
			csr_clear(CSR_MIP, MIP_MSIP);
			csr_set(CSR_MIP, MIP_SSIP);
		}
		if (pending & MIP_MEIP) {
			/* MEIP is read-only; just inject SEIP */
			csr_set(CSR_MIP, MIP_SEIP);
		}
	}
}
