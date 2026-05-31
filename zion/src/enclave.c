/*
 * Zion Enclave — native implementation using zion's context switch.
 *
 * Replaces keystone/enclave.c + keystone/sm-sbi.c + keystone/cpu.c.
 * Uses zion's tee_thread + context_switch_to/from for VS-mode execution.
 * Uses tee-mem G-stage page tables for isolation alongside PMP.
 */
#include "enclave.h"
#include "zion.h"
#include "tee.h"
#include "context.h"
#include "tee-mem.h"
#include "pmp.h"
#include "sm.h"
#include "page.h"
#include "cpu.h"
#include "mprv.h"
#include <crypto.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_console.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_error.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_hfence.h>
#include "plugins/plugins.h"
#include "platform-hook.h"
#include TARGET_PLATFORM_HEADER

/* ---- Global attestation state (was in keystone/sm.c) ---- */
byte sm_hash[MDSIZE] = { 0 };
byte sm_signature[SIGNATURE_SIZE] = { 0 };
byte sm_public_key[PUBLIC_KEY_SIZE] = { 0 };
byte sm_private_key[PRIVATE_KEY_SIZE] = { 0 };
byte dev_public_key[PUBLIC_KEY_SIZE] = { 0 };

/* ---- Enclave array (was in keystone/enclave.c) ---- */
struct enclave enclaves[ENCL_MAX];

/* ---- Per-hart enclave context ---- */
static struct cpu_state cpus[MAX_HARTS];

int cpu_is_enclave_context(void)
{
	return cpus[csr_read(mhartid)].is_enclave;
}

int cpu_get_enclave_id(void)
{
	return cpus[csr_read(mhartid)].eid;
}

void cpu_enter_enclave_context(enclave_id eid)
{
	cpus[csr_read(mhartid)].is_enclave = 1;
	cpus[csr_read(mhartid)].eid = eid;
}

void cpu_exit_enclave_context(void)
{
	cpus[csr_read(mhartid)].is_enclave = 0;
}

/* ---- Enclave metadata ---- */
static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;

#define ENCLAVE_EXISTS(eid) ((eid) < ENCL_MAX && \
			     enclaves[(eid)].state != INVALID)

static unsigned long encl_alloc_eid(enclave_id *_eid)
{
	for (int i = 0; i < ENCL_MAX; i++) {
		if (enclaves[i].state == INVALID) {
			*_eid = i;
			return SBI_ERR_SM_ENCLAVE_SUCCESS;
		}
	}
	return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
}

static unsigned long encl_free_eid(enclave_id eid)
{
	enclaves[eid].state = INVALID;
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void enclave_init_metadata(void)
{
	for (int i = 0; i < ENCL_MAX; i++) {
		enclaves[i].eid = i;
		enclaves[i].state = INVALID;
		enclaves[i].n_thread = 0;
		sbi_memset(&enclaves[i].regions, 0,
			   sizeof(enclaves[i].regions));
	}
}

/* ---- Region helpers ---- */
int get_enclave_region_index(enclave_id eid, enum enclave_region_type type)
{
	for (int i = 0; i < ENCLAVE_REGIONS_MAX; i++) {
		if (enclaves[eid].regions[i].type == type)
			return i;
	}
	return -1;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid)
{
	if (memid < 0 || memid >= ENCLAVE_REGIONS_MAX)
		return 0;
	return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid)
{
	if (memid < 0 || memid >= ENCLAVE_REGIONS_MAX)
		return 0;
	return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);
}

/* ---- Copy from user (MPRV-based) ---- */
unsigned long copy_enclave_create_args(uintptr_t src,
				       struct keystone_sbi_create_t *dest)
{
	return copy_to_sm(dest, src, sizeof(struct keystone_sbi_create_t));
}

static int is_create_args_valid(struct keystone_sbi_create_t *args)
{
	if (args->epm_region.size < RISCV_PGSIZE)
		return 0;
	if (args->utm_region.size == 0)
		return 0;
	return 1;
}


/* ---- Initial tee_thread setup for enclave ---- */
static void setup_enclave_thread(struct tee_thread *thread,
				 struct enclave *enc,
				 uintptr_t entry_point,
				 uintptr_t sp,
				 uintptr_t arg0,
				 enclave_id eid)
{
	/* CSRs for VS-mode enclave execution.
	 * MPP=S, MPV=1 → mret enters VS-mode.
	 * No MPIE/SIE — enclave starts with interrupts off (Eyrie sets them up). */
	thread->csrs.mepc = entry_point;
	thread->csrs.mstatus = (PRV_S << MSTATUS_MPP_SHIFT) |
			       MSTATUS_MPV;
	thread->csrs.hstatus = HSTATUS_SPV | HSTATUS_VSXL;
	thread->csrs.hcounteren = 0x7; /* enable cycle/time/inst counters */
	thread->csrs.hgatp = enc->hgatp;
	thread->csrs.vsatp = 0; /* no S-mode page table initially */
	thread->csrs.vsstatus = SSTATUS_SUM; /* allow S-mode to access U-mode pages */
	thread->csrs.vstvec = 0;
	thread->csrs.vsscratch = 0;
	thread->csrs.vsepc = 0;
	thread->csrs.vscause = 0;
	thread->csrs.vstval = 0;
	thread->csrs.vsie = 0;
	thread->csrs.vsip = 0;
	thread->csrs.hvip = 0;

	/* GPRs — Eyrie runtime eyrie_boot(a0, a1..a7) expects:
	 * a0 = dummy (SBI return value), a1 = dram_base, a2 = dram_size,
	 * a3 = runtime_base, a4 = user_base, a5 = free_base,
	 * a6 = untrusted_base, a7 = untrusted_size */
	sbi_memset(&thread->gprs, 0, sizeof(thread->gprs));
	thread->gprs.sp = sp;
	thread->gprs.a0 = arg0; /* dram_base (Eyrie's "dummy" param) */
	thread->gprs.a1 = enc->params.dram_base;
	thread->gprs.a2 = enc->params.dram_size;
	thread->gprs.a3 = enc->params.runtime_base;
	thread->gprs.a4 = enc->params.user_base;
	thread->gprs.a5 = enc->params.free_base;
	thread->gprs.a6 = enc->params.untrusted_base;
	thread->gprs.a7 = enc->params.untrusted_size;

	/* Thread state */
	thread->state.mode = ENCLAVE;
	thread->state.rtid = (unsigned int)eid;
	thread->state.ttid = 0;
}

/* ---- Public API ---- */

unsigned long create_enclave(unsigned long *eidptr,
			     struct keystone_sbi_create_t create_args)
{
	/*
	 * Compatible with Keystone SDK/driver interface:
	 *   epm_region.paddr = EPM PA (driver-allocated, binary already loaded)
	 *   epm_region.size  = EPM size
	 *   utm_region.paddr = UTM PA (driver-allocated)
	 *   utm_region.size  = UTM size
	 *   runtime_paddr    = Eyrie runtime offset within EPM
	 *
	 * SM adapts: copies EPM content into secure pool, uses G-stage
	 * to redirect enclave GPA → pool PA. Driver/SDK unchanged.
	 */
	uintptr_t epm_pa  = create_args.epm_region.paddr; /* EPM GPA = REE PA */
	size_t epm_size   = create_args.epm_region.size;
	uintptr_t utm_pa  = create_args.utm_region.paddr;
	size_t utm_size   = create_args.utm_region.size;
	enclave_id eid;
	unsigned long ret;

	if (!is_create_args_valid(&create_args))
		return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

	/* Allocate EID */
	ret = encl_alloc_eid(&eid);
	if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
		return ret;

	/* ---- Allocate EPM blocks from secure memory pool ---- */
	int n_blocks = (epm_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
	uint64_t epm_blocks[16]; /* max 32MB (16 * 2MB) */
	if (n_blocks > 16) {
		ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
		goto free_eid;
	}

	for (int i = 0; i < n_blocks; i++) {
		uint64_t pa = alloc_data_block(&g_mem_pool.data_pool, eid);
		if (pa == (uint64_t)-1) {
			sbi_printf("[SM] create_enclave: eid=%d alloc block %d failed\n",
				   eid, i);
			ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
			goto free_blocks;
		}
		epm_blocks[i] = pa;
	}

	/* ---- Copy EPM content from driver-allocated PA → secure pool ---- */
	for (int i = 0; i < n_blocks; i++) {
		size_t chunk = (i == n_blocks - 1) ?
			       (epm_size - i * BLOCK_SIZE) : BLOCK_SIZE;
		/* M-mode direct PA access — no MPRV needed.
		 * src (epm_pa) is kernel-allocated physical memory,
		 * dst (epm_blocks[i]) is secure pool physical memory.
		 * Both accessible from M-mode without page table walk. */
		sbi_memcpy((void *)epm_blocks[i],
			   (void *)(epm_pa + i * BLOCK_SIZE), chunk);
	}

	/* ---- Build G-stage page table ---- */
	reset_enclave_pt_pool(&g_mem_pool, (uint32_t)eid);
	int enc_cvm_id = CVM_NUM + eid;

	/*
	 * EPM: map original EPM GPA → secure pool PA (non-identity).
	 * Enclave sees its memory at the same GPA the SDK/driver used,
	 * but G-stage transparently redirects to the secure pool.
	 */
	for (int i = 0; i < n_blocks; i++) {
		uint64_t gpa = epm_pa + (uint64_t)i * BLOCK_SIZE;
		if (map_gpa_to_hpa(&g_mem_pool, enc_cvm_id,
				   gpa, epm_blocks[i], BLOCK_SIZE, true, false))
			goto free_blocks;
	}

	/* UTM: identity mapping (host needs ongoing access) */
	if (utm_pa && utm_size) {
		if (map_gpa_to_hpa(&g_mem_pool, enc_cvm_id,
				   utm_pa, utm_pa, utm_size, false, false))
			goto free_blocks;
	}

	/* Compute hgatp */
	void *root_pt = get_enclave_root_pt(&g_mem_pool, (uint32_t)eid);
	if (!root_pt)
		goto free_blocks;
	uint64_t hgatp = ((unsigned long)root_pt >> PAGE_SHIFT) |
		 (HGATP_MODE_SV48X4 << HGATP_MODE_SHIFT);

	/* ---- Fill enclave metadata ---- */
	enclaves[eid].eid = eid;
	enclaves[eid].n_thread = 0;
	enclaves[eid].hgatp = hgatp;
	enclaves[eid].mem_info.epm_base = epm_pa;
	enclaves[eid].mem_info.epm_size = epm_size;
	enclaves[eid].mem_info.utm_base = utm_pa;
	enclaves[eid].mem_info.utm_size = utm_size;
	enclaves[eid].active_thread = NULL;
	enclaves[eid].saved_mepc = 0;

	/* Runtime params — Eyrie uses these as-is (GPA unchanged) */
	struct runtime_params_t *p = &enclaves[eid].params;
	p->dram_base = epm_pa;
	p->dram_size = epm_size;
	p->runtime_base = create_args.runtime_paddr;
	p->user_base = create_args.user_paddr;
	p->free_base = create_args.free_paddr;
	p->untrusted_base = utm_pa;
	p->untrusted_size = utm_size;
	p->free_requested = create_args.free_requested;

	/* Platform hook */
	ret = platform_create_enclave(&enclaves[eid]);
	if (ret)
		goto free_blocks;

	ret = validate_and_hash_enclave(&enclaves[eid]);
	if (ret)
		goto free_blocks;

	spin_lock(&encl_lock);
	enclaves[eid].state = FRESH;
	spin_unlock(&encl_lock);

	*eidptr = eid;
	sbi_printf("[SM] create_enclave: eid=%d epm_gpa=0x%lx size=0x%lx hgatp=0x%lx\n",
		   eid, epm_pa, epm_size, hgatp);
	return SBI_ERR_SM_ENCLAVE_SUCCESS;

free_blocks:
	free_data_blocks_per_tid(&g_mem_pool.data_pool, eid);
free_eid:
	encl_free_eid(eid);
	return ret;
}

unsigned long destroy_enclave(enclave_id eid)
{
	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state > STOPPED) {
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;
	}
	enclaves[eid].state = DESTROYING;
	spin_unlock(&encl_lock);

	/* Free active thread if still allocated (stop without exit) */
	if (enclaves[eid].active_thread) {
		tee_thread_free(enclaves[eid].active_thread);
		enclaves[eid].active_thread = NULL;
	}

	platform_destroy_enclave(&enclaves[eid]);

	/* TODO: memset blocks before freeing (tee-mem.c: free_data_blocks_per_tid)
	 * to prevent data leakage to next enclave allocated same blocks. */
	free_data_blocks_per_tid(&g_mem_pool.data_pool, eid);

	enclaves[eid].hgatp = 0;

	/* Release enclave G-stage PT pool */
	reset_enclave_pt_pool(&g_mem_pool, (uint32_t)eid);

	encl_free_eid(eid);
	sbi_printf("[SM] destroy_enclave: eid=%d destroyed\n", eid);
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state != FRESH) {
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
	}
	enclaves[eid].state = RUNNING;
	enclaves[eid].n_thread++;
	spin_unlock(&encl_lock);

	/* Allocate a tee_thread for this enclave */
	struct tee_thread *thread = tee_thread_alloc();
	if (!thread) {
		spin_lock(&encl_lock);
		enclaves[eid].n_thread--;
		enclaves[eid].state = FRESH;
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
	}

	/* Entry point and args from Eyrie runtime layout */
	struct runtime_params_t *p = &enclaves[eid].params;
	uintptr_t entry = p->runtime_base;
	uintptr_t sp = p->free_base + p->free_requested; /* stack at top of free */
	uintptr_t arg0 = p->dram_base; /* Eyrie expects dram_base in a0 */

	setup_enclave_thread(thread, &enclaves[eid], entry, sp, arg0, eid);

	sbi_printf("[SM] ===== ENCLAVE FIRST ENTRY =====\n");
	sbi_printf("[SM] CSRs: mepc=0x%lx mstatus=0x%lx hstatus=0x%lx\n",
		   thread->csrs.mepc, thread->csrs.mstatus, thread->csrs.hstatus);
	sbi_printf("[SM] CSRs: hgatp=0x%lx hcounteren=0x%lx vsatp=0x%lx vsstatus=0x%lx\n",
		   thread->csrs.hgatp, thread->csrs.hcounteren,
		   thread->csrs.vsatp, thread->csrs.vsstatus);
	sbi_printf("[SM] CSRs: vstvec=0x%lx vsscratch=0x%lx vsepc=0x%lx vscause=0x%lx\n",
		   thread->csrs.vstvec, thread->csrs.vsscratch,
		   thread->csrs.vsepc, thread->csrs.vscause);
	sbi_printf("[SM] GPRs: sp=0x%lx a0=0x%lx a1=0x%lx a2=0x%lx\n",
		   thread->gprs.sp, thread->gprs.a0,
		   thread->gprs.a1, thread->gprs.a2);
	sbi_printf("[SM] GPRs: a3=0x%lx a4=0x%lx a5=0x%lx a6=0x%lx a7=0x%lx\n",
		   thread->gprs.a3, thread->gprs.a4, thread->gprs.a5,
		   thread->gprs.a6, thread->gprs.a7);
	sbi_printf("[SM] Params: dram=0x%lx size=0x%lx runtime=0x%lx user=0x%lx\n",
		   p->dram_base, p->dram_size, p->runtime_base, p->user_base);
	sbi_printf("[SM] Params: free=0x%lx utm=0x%lx utm_size=0x%lx\n",
		   p->free_base, p->untrusted_base, p->untrusted_size);
	sbi_printf("[SM] =================================\n");

	enclaves[eid].active_thread = thread;
	cpu_enter_enclave_context(eid);
	sbi_printf("[SM] run_enclave: eid=%d entry=0x%lx sp=0x%lx\n",
		   eid, entry, sp);

	/*
	 * Switch context: host → enclave.
	 * context_switch_to saves host state, loads enclave state into regs,
	 * switches trap vector, sets PMP, loads hgatp.
	 * After this returns, regs contains the enclave's state.
	 * When OpenSBI does mret, execution enters the enclave.
	 */
	context_switch_to(regs,
			  /* src = current host context */
			  &tee_threads[0], /* placeholder; switch_to reads from regs */
			  /* dst = enclave */
			  thread,
			  REE_TO_ENCLAVE,
			  0, NULL, NULL);

	sbi_printf("[SM] entering enclave via tee_mret: mepc=0x%lx mstatus=0x%lx\n",
		   regs->mepc, regs->mstatus);

	sbi_printf("[SM] ===== REE->ENCLAVE REG DUMP =====\n");
	sbi_printf("[SM]   mepc=0x%lx mstatus=0x%lx mpp=%lu mpv=%lu sie=%lu\n",
		   regs->mepc, regs->mstatus,
		   (regs->mstatus & MSTATUS_MPP) >> MSTATUS_MPP_SHIFT,
		   (regs->mstatus & MSTATUS_MPV) >> 39,
		   (regs->mstatus & MSTATUS_SIE) >> 1);
	sbi_printf("[SM]   hgatp=0x%lx hstatus=0x%lx mtvec=0x%lx\n",
		   csr_read(CSR_HGATP), csr_read(CSR_HSTATUS),
		   csr_read(CSR_MTVEC));
	sbi_printf("[SM]   medeleg=0x%lx mideleg=0x%lx mie=0x%lx\n",
		   csr_read(CSR_MEDELEG), csr_read(CSR_MIDELEG),
		   csr_read(CSR_MIE));
	sbi_printf("[SM]   hideleg=0x%lx hedeleg=0x%lx\n",
		   csr_read(CSR_HIDELEG), csr_read(CSR_HEDELEG));
	sbi_printf("[SM]   satp=0x%lx sscratch=0x%lx stvec=0x%lx\n",
		   csr_read(CSR_SATP), csr_read(CSR_SSCRATCH),
		   csr_read(CSR_STVEC));
	sbi_printf("[SM]   vsstatus=0x%lx vsatp=0x%lx vstvec=0x%lx\n",
		   csr_read(CSR_VSSTATUS), csr_read(CSR_VSATP),
		   csr_read(CSR_VSTVEC));
	sbi_printf("[SM]   GPRs: a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx\n",
		   regs->a0, regs->a1, regs->a2, regs->a3);
	sbi_printf("[SM]   GPRs: a4=0x%lx a5=0x%lx a6=0x%lx a7=0x%lx\n",
		   regs->a4, regs->a5, regs->a6, regs->a7);
	sbi_printf("[SM]   GPRs: sp=0x%lx ra=0x%lx gp=0x%lx tp=0x%lx\n",
		   regs->sp, regs->ra, regs->gp, regs->tp);
	sbi_printf("[SM]   GPRs: t0=0x%lx t1=0x%lx t2=0x%lx s0=0x%lx\n",
		   regs->t0, regs->t1, regs->t2, regs->s0);
	sbi_printf("[SM] ===== REE->ENCLAVE DUMP END =====\n");

	/* Direct mret — bypass OpenSBI sbi_trap_exit which clears MPV.
	 * context_switch_to already set all CSRs (hstatus, hgatp, mtvec).
	 * We just restore GPRs + mstatus + mepc and mret into VS-mode.
	 * This function never returns. */
	tee_mret(regs);
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
	spin_lock(&encl_lock);
	if (enclaves[eid].state != RUNNING) {
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;
	}
	enclaves[eid].n_thread--;
	if (enclaves[eid].n_thread == 0)
		enclaves[eid].state = STOPPED;
	spin_unlock(&encl_lock);

	cpu_exit_enclave_context();
	platform_switch_from_enclave(&enclaves[eid]);

	/* Restore host context. src=enclave thread (saves enclave CSR state),
	 * dst=host thread (loads host CSR state from saved state). */
	struct tee_thread *encl_thread = enclaves[eid].active_thread;
	struct tee_thread *host_thread = &tee_threads[0];
	context_switch_from(regs, encl_thread, host_thread,
			    REE_FROM_ENCLAVE,
			    0, NULL, NULL, NULL, 0);

	/* Free the allocated tee_thread */
	tee_thread_free(encl_thread);
	enclaves[eid].active_thread = NULL;

	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request,
			   enclave_id eid)
{
	spin_lock(&encl_lock);
	if (enclaves[eid].state != RUNNING) {
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;
	}
	enclaves[eid].n_thread--;
	if (enclaves[eid].n_thread == 0)
		enclaves[eid].state = STOPPED;
	spin_unlock(&encl_lock);

	cpu_exit_enclave_context();
	platform_switch_from_enclave(&enclaves[eid]);

	struct tee_thread *encl_thread = enclaves[eid].active_thread;
	struct tee_thread *host_thread = &tee_threads[0];
	context_switch_from(regs, encl_thread, host_thread,
			    REE_FROM_ENCLAVE,
			    0, NULL, NULL, NULL, 1);

	/* Save enclave PC for resume — regs->mepc was saved by switch_from_csrs
	 * into encl_thread->csrs.mepc, but we also stash it here for resume. */
	enclaves[eid].saved_mepc = encl_thread->csrs.mepc;
	/* Keep active_thread alive — resume will reuse it */

	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state != STOPPED) {
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
	}
	enclaves[eid].state = RUNNING;
	enclaves[eid].n_thread++;
	spin_unlock(&encl_lock);

	/* Reuse the tee_thread from the previous run (kept alive by stop) */
	struct tee_thread *thread = enclaves[eid].active_thread;
	if (!thread) {
		spin_lock(&encl_lock);
		enclaves[eid].n_thread--;
		enclaves[eid].state = STOPPED;
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
	}

	/* Restore PC from where the enclave stopped */
	thread->csrs.mepc = enclaves[eid].saved_mepc;

	/*
	 * Don't reset sp — Eyrie's stack is active, switch_from_csrs
	 * already saved stop-time sp into encl_thread->gprs.sp.
	 * Reset a0 only (Eyrie treats dram_base as a constant).
	 */
	struct runtime_params_t *p = &enclaves[eid].params;
	thread->gprs.a0 = p->dram_base;

	cpu_enter_enclave_context(eid);
	sbi_printf("[SM] resume_enclave: eid=%d mepc=0x%lx\n",
		   eid, thread->csrs.mepc);

	context_switch_to(regs, &tee_threads[0], thread,
			  REE_TO_ENCLAVE, 0, NULL, NULL);

	/* Direct mret into enclave — same as run_enclave.
	 * MUST bypass OpenSBI sbi_trap_exit which clears MPV. */
	sbi_printf("[SM] resuming enclave via tee_mret: mepc=0x%lx mstatus=0x%lx\n",
		   regs->mepc, regs->mstatus);
	tee_mret(regs);
}

/* ---- Attestation (stubs — full implementation TBD) ---- */
unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data,
			     uintptr_t size, enclave_id eid)
{
	/* TODO: implement full attestation */
	sbi_printf("[SM] attest_enclave: eid=%d (stub)\n", eid);
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
			      size_t key_ident_size, enclave_id eid)
{
	/* TODO: implement sealing key derivation */
	sbi_printf("[SM] get_sealing_key: eid=%d (stub)\n", eid);
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long validate_and_hash_enclave(struct enclave *enclave)
{
	/* TODO: implement proper validation and hashing */
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* ---- SBI wrappers (called from sm-sbi-opensbi.c) ---- */
unsigned long sbi_sm_create_enclave(unsigned long *out_val,
				    uintptr_t create_args)
{
	struct keystone_sbi_create_t args;
	unsigned long ret = copy_enclave_create_args(create_args, &args);
	if (ret)
		return ret;
	return create_enclave(out_val, args);
}

unsigned long sbi_sm_destroy_enclave(unsigned long eid)
{
	return destroy_enclave((enclave_id)eid);
}

unsigned long sbi_sm_run_enclave(struct sbi_trap_regs *regs,
				 unsigned long eid)
{
	run_enclave(regs, (enclave_id)eid);
	/* Execution continues in enclave; regs now has enclave state.
	 * Set a0 to success for when the enclave exits back. */
	regs->a0 = SBI_ERR_SM_ENCLAVE_SUCCESS;
	return 0;
}

unsigned long sbi_sm_resume_enclave(struct sbi_trap_regs *regs,
				    unsigned long eid)
{
	unsigned long ret = resume_enclave(regs, (enclave_id)eid);
	regs->a0 = ret;
	return 0;
}

unsigned long sbi_sm_exit_enclave(struct sbi_trap_regs *regs,
				  unsigned long retval)
{
	enclave_id eid = (enclave_id)cpu_get_enclave_id();
	unsigned long ret = exit_enclave(regs, eid);
	regs->a0 = ret;
	regs->a1 = retval;
	return 0;
}

unsigned long sbi_sm_stop_enclave(struct sbi_trap_regs *regs,
				  unsigned long request)
{
	enclave_id eid = (enclave_id)cpu_get_enclave_id();
	unsigned long ret = stop_enclave(regs, request, eid);
	regs->a0 = ret;
	return 0;
}

unsigned long sbi_sm_attest_enclave(uintptr_t report, uintptr_t data,
				    uintptr_t size)
{
	return attest_enclave(report, data, size,
			      (enclave_id)cpu_get_enclave_id());
}

unsigned long sbi_sm_get_sealing_key(uintptr_t seal_key, uintptr_t key_ident,
				     size_t key_ident_size)
{
	return get_sealing_key(seal_key, key_ident, key_ident_size,
			       (enclave_id)cpu_get_enclave_id());
}

unsigned long sbi_sm_random(void)
{
	return platform_random();
}

unsigned long sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id,
				 uintptr_t arg0, uintptr_t arg1)
{
	return call_plugin(cpu_get_enclave_id(), plugin_id, call_id,
			   arg0, arg1);
}
