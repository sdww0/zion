#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hfence.h>
#include <sbi/sbi_string.h>
#include "cvm.h"
#include "context.h"
#include "mprv.h"
#include "tee-mem.h"

struct cvm cvms[MAX_CVMS];
static unsigned long cvms_alloc_bitmap = 0;
static unsigned long ree_tee_alloc_bitmap = 0;
static const unsigned long cvm_guest_hstatus_flags =
	HSTATUS_VTW | HSTATUS_SPVP | HSTATUS_SPV;

static void reset_cvm_metadata(unsigned int rtid)
{
	if (rtid >= MAX_CVMS)
		return;

	sbi_memset(&cvms[rtid], 0, sizeof(cvms[rtid]));
	cvms[rtid].owner_rtid = (unsigned int)-1;

	for (size_t i = 0; i < MAX_CVM_VCPUS; i++)
		cvms[rtid].vcpus[i].exit_cause = TEE_INIT;
}

static bool cvm_rtid_allocated(unsigned int rtid)
{
	return rtid < CVM_NUM && (cvms_alloc_bitmap & (1UL << rtid));
}

static int alloc_cvm_rtid(unsigned int *rtid)
{
	for (unsigned int i = 0; i < CVM_NUM; i++) {
		if (cvms_alloc_bitmap & (1UL << i))
			continue;

		cvms_alloc_bitmap |= 1UL << i;
		*rtid = i;
		return 0;
	}

	return -1;
}

static void free_cvm_rtid(unsigned int rtid)
{
	if (rtid < CVM_NUM)
		cvms_alloc_bitmap &= ~(1UL << rtid);
}

static bool ree_tee_allocated(unsigned int tid)
{
	return tid < MAX_TEES && (ree_tee_alloc_bitmap & (1UL << tid));
}

static int alloc_ree_tee_id(unsigned int *tid)
{
	for (unsigned int i = 0; i < MAX_TEES; i++) {
		if (ree_tee_alloc_bitmap & (1UL << i))
			continue;

		ree_tee_alloc_bitmap |= 1UL << i;
		*tid = i;
		return 0;
	}

	return -1;
}

static void free_ree_tee_id(unsigned int tid)
{
	if (tid >= MAX_TEES)
		return;

	sbi_memset(&ree.tees[tid], 0, sizeof(ree.tees[tid]));
	ree_tee_alloc_bitmap &= ~(1UL << tid);
}

static int cvm_tid_to_rtid(unsigned int tid, unsigned int *rtid)
{
	if (!ree_tee_allocated(tid) || ree.tees[tid].mode != CVM)
		return -1;

	*rtid = ree.tees[tid].id;
	if (!cvm_rtid_allocated(*rtid))
		return -1;

	return 0;
}

static void free_cvm_vcpu_threads(unsigned int rtid)
{
	if (rtid >= MAX_CVMS)
		return;

	for (size_t i = 0; i < MAX_CVM_VCPUS; i++) {
		tee_thread_free(cvms[rtid].vcpus[i].tthread);
		cvms[rtid].vcpus[i].tthread = NULL;
	}
}

static void init_guest_csrs(struct tee_csr *guest_csrs, uintptr_t mstatus,
			    unsigned long hgatp)
{
	guest_csrs->mstatus = mstatus;
	guest_csrs->hstatus = cvm_guest_hstatus_flags;
	guest_csrs->scounteren = ZION_COUNTER_ENABLE_MASK;
	guest_csrs->hcounteren = -1UL;
	guest_csrs->hvip = 0;
	guest_csrs->hgatp = hgatp & ~HGATP_VMID_MASK;
}

static void dump_trap_regs(const char *label, const struct sbi_trap_regs *regs)
{
	(void)label;
	(void)regs;
	zion_printf("%s:  \n\
				ra: 0x%lx, sp: 0x%lx, gp: 0x%lx, tp: 0x%lx\n \
				t0: 0x%lx, t1: 0x%lx, t2: 0x%lx, s0: 0x%lx\n \
				s1: 0x%lx, a0: 0x%lx, a1: 0x%lx, a2: 0x%lx\n \
				a3: 0x%lx, a4: 0x%lx, a5: 0x%lx, a6: 0x%lx\n \
				a7: 0x%lx, s2: 0x%lx, s3: 0x%lx, s4: 0x%lx\n \
				s5: 0x%lx, s6: 0x%lx, s7: 0x%lx, s8: 0x%lx\n \
				s9: 0x%lx, s10: 0x%lx, s11: 0x%lx, t3: 0x%lx\n \
				t4: 0x%lx, t5: 0x%lx, t6: 0x%lx, mepc: 0x%lx\n \
				mstatus: 0x%lx\n",
		    label, regs->ra, regs->sp, regs->gp, regs->tp, regs->t0,
		    regs->t1, regs->t2, regs->s0, regs->s1, regs->a0,
		    regs->a1, regs->a2, regs->a3, regs->a4, regs->a5,
		    regs->a6, regs->a7, regs->s2, regs->s3, regs->s4,
		    regs->s5, regs->s6, regs->s7, regs->s8, regs->s9,
		    regs->s10, regs->s11, regs->t3, regs->t4, regs->t5,
		    regs->t6, regs->mepc, regs->mstatus);
}

unsigned long create_cvm(struct sbi_trap_regs *regs, unsigned int *_tid)
{
	unsigned int rtid;
	unsigned int tid;
	struct tee *tee;

	(void)regs;

	if (alloc_ree_tee_id(&tid) != 0)
		return -1;

	if (alloc_cvm_rtid(&rtid) != 0) {
		free_ree_tee_id(tid);
		return -1;
	}

	reset_cvm_metadata(rtid);
	reset_cvm_pt_pool(&g_mem_pool, rtid);

	unsigned long pgd = (unsigned long)get_cvm_root_pt(&g_mem_pool, rtid);
	if (!pgd) {
		free_cvm_rtid(rtid);
		free_ree_tee_id(tid);
		return -1;
	}

	unsigned long hgatp = GSTAGE_MODE;

	hgatp |= ((unsigned long)rtid << HGATP_VMID_SHIFT) & HGATP_VMID_MASK;
	hgatp |= (pgd >> PAGE_SHIFT) & HGATP_PPN;

	zion_printf("[SM] create_cvm(): hgatp=%lx, pgd=%lx\n", hgatp, pgd);

	cvms[rtid].hgatp = hgatp;
	cvms[rtid].pgd	 = pgd;

	tee		      = &ree.tees[tid];

	tee->id		      = rtid;
	tee->mode	      = CVM;
	cvms[rtid].owner_rtid = (unsigned int)-1;

	*_tid = tid;

	zion_printf("[SBI] create_cvm(): pgd=%lx, tid=%u, rtid=%u\n", pgd, tid,
		   rtid);

	return 0;
}

unsigned long init_cvm_vcpu(struct sbi_trap_regs *regs, unsigned int tid,
			    unsigned int *_ttid,
			    struct kvm_vcpu_channel *_shared_mem)
{
	unsigned int rtid, ttid;

	(void)regs;
	if (cvm_tid_to_rtid(tid, &rtid) != 0)
		return -1;

	ttid   = cvms[rtid].ttid_next;
	if (ttid >= MAX_CVM_VCPUS)
		return -1;

	struct tee_thread *tthread = tee_thread_alloc();
	if (!tthread)
		return -1;

	*_ttid = ttid;
	cvms[rtid].ttid_next++;

	struct cvm_vcpu *vcpu	   = &cvms[rtid].vcpus[ttid];
	tthread->master		   = (void *)vcpu;

	save_tthread_state(&tthread->state, rtid, ttid, tthread, CVM);
	tthread->prev_state = NULL;
	vcpu->tthread	    = tthread;

	int illegal = copy_to_sm((void *)&vcpu->channel, (uintptr_t)_shared_mem,
				 sizeof(struct kvm_vcpu_channel));
	if (illegal) {
		cvms[rtid].ttid_next--;
		vcpu->tthread = NULL;
		tee_thread_free(tthread);
		sbi_printf(
			"[SBI] !!!ERROR!!! in tvm_vcpu_init(): copy_to_sm()\n");
		sbi_hart_hang();
		return -1;
	}

	zion_printf(
		"[SBI] tvm_vcpu_init(): guest_context=%lx, guest_csr=%lx, extra_trap=%lx\n",
		vcpu->channel.guest_context, vcpu->channel.guest_csr,
		vcpu->channel.extra_trap);

	uintptr_t mstatus = csr_read(CSR_MSTATUS);

	zion_printf("[SBI] init_cvm_vcpu(): original mstatus=%lx\n", mstatus);

	mstatus &= ~MSTATUS_MPP;
	mstatus |= (PRV_S << MSTATUS_MPP_SHIFT);

	mstatus |= MSTATUS_MPV;

	mstatus &= ~MSTATUS_FS;
	mstatus |= (1UL << 14);

	mstatus &= ~MSTATUS_SIE;
	mstatus &= ~MSTATUS_SPIE;

	init_guest_csrs(&vcpu->tthread->csrs, mstatus, cvms[rtid].hgatp);

	sbi_printf("[SM] CVM vcpu: tid=%u, rtid=%u, ttid=%u\n",
		   tid, rtid, ttid);
	return 0;
}

unsigned long enter_cvm(struct sbi_trap_regs *regs, unsigned int tid,
			unsigned int ttid)
{
	unsigned int rtid;
	if (cvm_tid_to_rtid(tid, &rtid) != 0)
		return -1;
	struct cvm_vcpu *vcpu = &cvms[rtid].vcpus[ttid];

	context_switch_to(regs, ree.harts[current_hartid()].tthread,
			  vcpu->tthread, REE_TO_CVM, vcpu->exit_cause,
			  &vcpu->exit_mmio_reg, &vcpu->channel);

	dump_trap_regs("Registers info in enter_cvm", regs);

	struct tee_csr *d_csrs = &vcpu->tthread->csrs;
	(void)d_csrs;

	zion_printf("[SBI] enter_cvm(): tee csrs: \n\
				mepc: 0x%lx, mstatus: 0x%lx, hstatus: 0x%lx\n \
				scounteren: 0x%lx, hcounteren: 0x%lx, hgatp: 0x%lx\n",
		    d_csrs->mepc, d_csrs->mstatus, d_csrs->hstatus,
		    d_csrs->scounteren, d_csrs->hcounteren, d_csrs->hgatp);

	zion_printf("[SBI] enter_cvm(): tee vcsrs: \n\
				vsstatus: 0x%lx, vsie: 0x%lx, vsip: 0x%lx\n \
				vstvec: 0x%lx, vsscratch: 0x%lx, vsepc: 0x%lx\n \
				vscause: 0x%lx, vstval: 0x%lx, hvip: 0x%lx\n \
				vsatp: 0x%lx\n",
		    d_csrs->vsstatus, d_csrs->vsie, d_csrs->vsip,
		    d_csrs->vstvec, d_csrs->vsscratch, d_csrs->vsepc,
		    d_csrs->vscause, d_csrs->vstval, d_csrs->hvip,
		    d_csrs->vsatp);

	return 0;
}
unsigned long exit_cvm(struct sbi_trap_regs *regs, unsigned int tid,
		       unsigned int ttid, tee_quit_cause exit_cause,
		       struct sbi_trap_info *trap,
		       struct cvm_extra_trap_info *extra_trap)
{
	struct tee_thread *s_tthread, *d_tthread;
	unsigned int rtid;

	(void)trap;
	if (cvm_tid_to_rtid(tid, &rtid) != 0)
		return -1;
	struct cvm_vcpu *vcpu = &cvms[rtid].vcpus[ttid];
	vcpu->exit_cause      = exit_cause;

	s_tthread = vcpu->tthread;
	d_tthread = s_tthread->prev_state->tthread;

	context_switch_from(regs, s_tthread, d_tthread, REE_FROM_CVM,
			    vcpu->exit_cause, &vcpu->exit_mmio_reg, extra_trap,
			    &vcpu->channel, 1);

	dump_trap_regs("Registers info in exit_cvm", regs);

	return 0;
}

unsigned long destroy_cvm(unsigned int tid)
{
	unsigned int rtid;

	if (cvm_tid_to_rtid(tid, &rtid) != 0)
		return -1;

	zion_printf("[SM] Destroy CVM: tid=%u, rtid=%u\n", tid, rtid);

	free_cvm_vcpu_threads(rtid);
	free_data_blocks_per_tid(&g_mem_pool.data_pool, rtid);
	reset_cvm_pt_pool(&g_mem_pool, rtid);
	reset_cvm_metadata(rtid);
	__sbi_hfence_gvma_all();

	free_cvm_rtid(rtid);
	free_ree_tee_id(tid);
	return 0;
}

void set_cvm_mem_info(unsigned int tid, struct cvm_mem_info *mem_info)
{
	unsigned int rtid;

	if (cvm_tid_to_rtid(tid, &rtid) != 0)
		return;

	struct cvm_mem_info *dest = &cvms[rtid].mem_info;

	*dest = *mem_info;

	sbi_printf("[SM] CVM mem: tid=%u, slot=%u, gpa=0x%lx, size=0x%lx, private=%u\n",
		   tid, dest->slot, dest->guest_phys_addr, dest->memory_size,
		   dest->private);
}
