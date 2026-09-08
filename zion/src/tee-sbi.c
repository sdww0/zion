#include <sbi/sbi_types.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include "ree.h"
#include "tee.h"
#include "cvm.h"
#include "mprv.h"

unsigned long sbi_sm_reserve_mem(struct sbi_trap_regs *regs, unsigned long type,
				 uintptr_t base, unsigned long count)
{
	(void)regs;
	(void)type;

	type = reserve_mem(base, count);
	if (type)
		tee_log("[SBI] sbi_sm_reserve_mem() failed: ret=0x%lx, base=0x%lx, count=0x%lx\n",
			   type, base, count);
	return type;
}

unsigned long sbi_sm_create_cvm(struct sbi_trap_regs *regs,
				struct sbi_ecall_return *out)
{

	unsigned long ret;
	unsigned int tid = 0;
	ret	   = create_cvm(regs, &tid);
	if (!ret)
		out->value = tid;
	else
		tee_log("[SBI] sbi_sm_create_cvm() failed: ret=0x%lx\n",
			   ret);
	return ret;
}

unsigned long sbi_sm_init_cvm_vcpu(struct sbi_trap_regs *regs, unsigned int tid,
				   struct sbi_ecall_return *out,
				   struct kvm_vcpu_channel *shared_mem_ptr)
{

	unsigned long ret;
	unsigned int ttid = 0;
	ret	   = init_cvm_vcpu(regs, tid, &ttid, shared_mem_ptr);
	if (!ret)
		out->value = ttid;
	else
		tee_log("[SBI] sbi_sm_init_cvm_vcpu() failed: tid=%x, ret=%lx\n",
			   tid, ret);
	return ret;
}

unsigned long sbi_sm_enter_cvm(struct sbi_trap_regs *regs, unsigned int tid,
			       unsigned int ttid)
{
	return enter_cvm(regs, tid, ttid);
}

/* Exit paths must distinguish between explicit SBI exits and interrupts. */
unsigned long sbi_sm_exit_cvm(struct sbi_trap_regs *regs, unsigned int rtid,
			      unsigned int ttid, tee_quit_cause exit_cause,
			      struct sbi_trap_info *trap,
			      struct cvm_extra_trap_info *extra_trap
				)
{
	regs->a0 = exit_cvm(regs, rtid, ttid, exit_cause, trap, extra_trap);
	// Skip ecall in host
	regs->mepc += 4;
	return regs->a0;
}

unsigned long sbi_sm_destroy_cvm(struct sbi_trap_regs *regs, unsigned int tid)
{
	(void)regs;
	return destroy_cvm(tid);
}

// Set TVM memory information.
unsigned long sbi_sm_set_cvm_mem_info(struct sbi_trap_regs *regs,
				      unsigned int tid, uintptr_t create_args)
{
	struct cvm_mem_info mem_info;

	(void)regs;

	int region_overlap =
		copy_to_sm(&mem_info, create_args, sizeof(struct cvm_mem_info));
	if (region_overlap)
		return -1;

	return set_cvm_mem_info(tid, &mem_info);
}

unsigned long sbi_sm_load_mem(struct sbi_trap_regs *regs, unsigned int tid,
			      uintptr_t create_args)
{
	struct sbi_load_mem p;
	unsigned int d_rtid;
	unsigned long ret;

	(void)regs;
	ret = copy_to_sm(&p, create_args, sizeof(struct sbi_load_mem));
	if (ret) {
		return ret;
	}

	d_rtid = hart_get_callee_rtid(tid);
	tee_log(
		"[SBI] sbi_sm_load_mem() info: tid=%u, d_rtid=%u, stash=0x%lx, pos=0x%lx, size=0x%lx\n",
		tid, d_rtid, p.stash, p.pos, p.size);

	return load_mem(d_rtid, &p);
}

unsigned long sbi_sm_register_pt(struct sbi_trap_regs *regs, unsigned int tid,
				 uintptr_t create_args)
{
	struct sbi_register_pt pt;
	unsigned long ret;

	(void)regs;
	int region_overlap =
		copy_to_sm(&pt, create_args, sizeof(struct sbi_register_pt));
	if (region_overlap)
		return -1;

	ret = register_pt(tid, &pt);

	return ret;
}

unsigned long sbi_sm_sync_pt(struct sbi_trap_regs *regs, unsigned int tid,
			     unsigned long gpa, unsigned long pt_paddr)
{
	(void)regs;
	return sync_pt(tid, gpa, pt_paddr);
}

/*------------------TEE-facing APIs---------------------*/
unsigned long sbi_sm_register_shared_mem_with_ree(struct sbi_trap_regs *regs,
						  uintptr_t create_arg)
{
	struct sbi_mark_mem mark_mem;

	(void)regs;
	if (copy_to_sm(&mark_mem, create_arg, sizeof(struct sbi_mark_mem)))
		return -1;

	tee_log(
		"[SBI] SBI_SM_REGISTER_SHARED_MEM_WITH_REE!!! addr=%lx, num=%lx\n",
		mark_mem.addr, mark_mem.num);

	return 0;
}

unsigned long sbi_sm_set_inited(unsigned long tid)
{
	set_inited((unsigned int)tid);
	return 0;
}

extern unsigned long tee_trap_records[TEE_TRAP_STAT_SLOTS];
extern unsigned long tee_trap_cycles[TEE_TRAP_STAT_SLOTS];

unsigned long sbi_sm_cycle_begin()
{
	zion_enable_counters();

#ifdef ZION_DEBUG
	unsigned long csr_mcounter	= csr_read(CSR_MCOUNTEREN);
	unsigned long csr_scounter	= csr_read(CSR_SCOUNTEREN);
	unsigned long csr_mcountinhibit = csr_read(CSR_MCOUNTINHIBIT);

	tee_log(
		"[SM] hartid=%u, mcounter=%lx, scounter=%lx, mcountinhibit=%lx\n",
		current_hartid(), csr_mcounter, csr_scounter,
		csr_mcountinhibit);
#endif

	for (size_t i = 0; i < TEE_TRAP_STAT_SLOTS; i++) {

		tee_trap_records[i] = 0;
		tee_trap_cycles[i]  = 0;
	}

	return 0;
}

unsigned long sbi_sm_cycle_end()
{
#ifdef ZION_DEBUG
	for (size_t i = 0; i < TEE_TRAP_STAT_SLOTS; i++) {
		unsigned long avg =
			tee_trap_records[i] ?
				tee_trap_cycles[i] / tee_trap_records[i] :
				0;
		tee_log(
			"[SM] tee_trap_records[%lu]=%lu, cycles=%lu, AVG=%lu\n",
			i, tee_trap_records[i], tee_trap_cycles[i], avg);
	}
#endif

	return 0;
}

unsigned long sbi_sm_clean_sec_mem()
{
	ree_metadata_init();
	return 0;
}
