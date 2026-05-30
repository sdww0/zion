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

/* ---- G-stage page table setup ---- */
static int setup_enclave_gstage(enclave_id eid)
{
	uintptr_t epm_base = get_enclave_region_base(eid, 0);
	size_t    epm_size = get_enclave_region_size(eid, 0);
	uintptr_t utm_base = get_enclave_region_base(eid, 1);
	size_t    utm_size = get_enclave_region_size(eid, 1);

	if (!epm_base || !epm_size)
		return -1;

	/* Store memory info for trap handler */
	enclaves[eid].mem_info.epm_base = epm_base;
	enclaves[eid].mem_info.epm_size = epm_size;
	enclaves[eid].mem_info.utm_base = utm_base;
	enclaves[eid].mem_info.utm_size = utm_size;

	/* Reset and build G-stage page table */
	reset_enclave_pt_pool(&g_mem_pool, (uint32_t)eid);
	int enc_cvm_id = CVM_NUM + eid;

	/* Map EPM: identity (GPA=HPA) */
	if (map_gpa_to_hpa(&g_mem_pool, enc_cvm_id,
			   epm_base, epm_base, epm_size, false, false))
		return -1;

	/* Map UTM if present */
	if (utm_base && utm_size) {
		if (map_gpa_to_hpa(&g_mem_pool, enc_cvm_id,
				   utm_base, utm_base, utm_size, false, false))
			return -1;
	}

	/* Compute hgatp */
	void *root_pt = get_enclave_root_pt(&g_mem_pool, (uint32_t)eid);
	if (!root_pt)
		return -1;

	enclaves[eid].hgatp = ((unsigned long)root_pt >> PAGE_SHIFT) |
			      (HGATP_MODE_SV39X4 << HGATP_MODE_SHIFT);

	return 0;
}

/* ---- Initial tee_thread setup for enclave ---- */
static void setup_enclave_thread(struct tee_thread *thread,
				 struct enclave *enc,
				 uintptr_t entry_point,
				 uintptr_t sp,
				 uintptr_t arg0,
				 enclave_id eid)
{
	/* CSRs for VS-mode enclave execution */
	thread->csrs.mepc = entry_point;
	thread->csrs.mstatus = (MSTATUS_MPP << MSTATUS_MPP_SHIFT) |
			       MSTATUS_MPIE | MSTATUS_SIE;
	thread->csrs.hstatus = HSTATUS_SPV | HSTATUS_VSXL;
	thread->csrs.hcounteren = 0x7; /* enable cycle/time/inst counters */
	thread->csrs.hgatp = enc->hgatp;
	thread->csrs.vsatp = 0; /* no S-mode page table initially */
	thread->csrs.vsstatus = 0;
	thread->csrs.vstvec = 0;
	thread->csrs.vsscratch = 0;
	thread->csrs.vsepc = 0;
	thread->csrs.vscause = 0;
	thread->csrs.vstval = 0;
	thread->csrs.vsie = 0;
	thread->csrs.vsip = 0;
	thread->csrs.hvip = 0;

	/* GPRs — Eyrie runtime expects: a0=entry_arg, sp=stack */
	sbi_memset(&thread->gprs, 0, sizeof(thread->gprs));
	thread->gprs.sp = sp;
	thread->gprs.a0 = arg0;

	/* Thread state */
	thread->state.mode = ENCLAVE;
	thread->state.rtid = (unsigned int)eid;
	thread->state.ttid = 0;
}

/* ---- Public API ---- */

unsigned long create_enclave(unsigned long *eidptr,
			     struct keystone_sbi_create_t create_args)
{
	uintptr_t base = create_args.epm_region.paddr;
	size_t size = create_args.epm_region.size;
	uintptr_t utbase = create_args.utm_region.paddr;
	size_t utsize = create_args.utm_region.size;
	enclave_id eid;
	unsigned long ret;
	int region, shared_region;

	if (!is_create_args_valid(&create_args))
		return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

	/* Runtime params (used by Eyrie runtime) */
	struct runtime_params_t params;
	params.dram_base = base;
	params.dram_size = size;
	params.runtime_base = create_args.runtime_paddr;
	params.user_base = create_args.user_paddr;
	params.free_base = create_args.free_paddr;
	params.untrusted_base = utbase;
	params.untrusted_size = utsize;
	params.free_requested = create_args.free_requested;

	/* Allocate EID */
	ret = encl_alloc_eid(&eid);
	if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
		return ret;

	/* Create PMP regions */
	ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
	if (pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
		goto free_eid;

	if (pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM,
				   &shared_region, 0))
		goto free_region;

	/* Lock EPM from host access */
	if (pmp_set_global(region, PMP_NO_PERM))
		goto free_shared;

	/* Initialize metadata */
	enclaves[eid].eid = eid;
	enclaves[eid].regions[0].pmp_rid = region;
	enclaves[eid].regions[0].type = REGION_EPM;
	enclaves[eid].regions[1].pmp_rid = shared_region;
	enclaves[eid].regions[1].type = REGION_UTM;
	enclaves[eid].n_thread = 0;
	enclaves[eid].params = params;

	/* Setup G-stage page tables */
	if (setup_enclave_gstage(eid)) {
		sbi_printf("[SM] create_enclave: eid=%d G-stage setup failed\n",
			   eid);
		goto unset_region;
	}

	/* Platform hook (optional enhancements) */
	ret = platform_create_enclave(&enclaves[eid]);
	if (ret)
		goto unset_region;

	/* Attestation hash (placeholder — full validation TBD) */
	ret = validate_and_hash_enclave(&enclaves[eid]);
	if (ret)
		goto unset_region;

	spin_lock(&encl_lock);
	enclaves[eid].state = FRESH;
	spin_unlock(&encl_lock);

	*eidptr = eid;
	sbi_printf("[SM] create_enclave: eid=%d base=0x%lx size=0x%lx hgatp=0x%lx\n",
		   eid, base, size, enclaves[eid].hgatp);
	return SBI_ERR_SM_ENCLAVE_SUCCESS;

unset_region:
	pmp_unset_global(region);
free_shared:
	pmp_region_free_atomic(shared_region);
free_region:
	pmp_region_free_atomic(region);
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

	platform_destroy_enclave(&enclaves[eid]);

	/* Clear enclave memory and free PMP regions */
	for (int i = 0; i < ENCLAVE_REGIONS_MAX; i++) {
		if (enclaves[eid].regions[i].type == REGION_INVALID ||
		    enclaves[eid].regions[i].type == REGION_UTM)
			continue;
		region_id rid = enclaves[eid].regions[i].pmp_rid;
		void *base = (void *)pmp_region_get_addr(rid);
		size_t size = pmp_region_get_size(rid);
		sbi_memset(base, 0, size);
		pmp_unset_global(rid);
		pmp_region_free_atomic(rid);
	}

	int utm_idx = get_enclave_region_index(eid, REGION_UTM);
	if (utm_idx != -1)
		pmp_region_free_atomic(enclaves[eid].regions[utm_idx].pmp_rid);

	enclaves[eid].hgatp = 0;
	enclaves[eid].encl_satp = 0;

	/* Release enclave PT pool */
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

	/* Update host regs for mret — switch_to already did this via regs */
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
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

	/* Restore host context via zion's context switch */
	struct tee_thread *thread = &tee_threads[0]; /* host thread */
	context_switch_from(regs, thread, thread,
			    REE_FROM_ENCLAVE,
			    0, NULL, NULL, NULL, 0);

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

	struct tee_thread *thread = &tee_threads[0];
	context_switch_from(regs, thread, thread,
			    REE_FROM_ENCLAVE,
			    0, NULL, NULL, NULL, 1);

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

	struct tee_thread *thread = tee_thread_alloc();
	if (!thread) {
		spin_lock(&encl_lock);
		enclaves[eid].n_thread--;
		enclaves[eid].state = STOPPED;
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
	}

	/* Use saved entry point for resume */
	struct runtime_params_t *p = &enclaves[eid].params;
	setup_enclave_thread(thread, &enclaves[eid],
			     p->runtime_base,
			     p->free_base + p->free_requested,
			     p->dram_base, eid);

	cpu_enter_enclave_context(eid);

	context_switch_to(regs, &tee_threads[0], thread,
			  REE_TO_ENCLAVE, 0, NULL, NULL);

	return SBI_ERR_SM_ENCLAVE_SUCCESS;
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
