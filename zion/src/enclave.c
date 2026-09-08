/*
 * Zion Enclave — native implementation using zion's context switch.
 *
 * Replaces zion/enclave.c + zion/sm-sbi.c + zion/cpu.c.
 * Uses zion's tee_thread + context_switch_to/from for VS-mode execution.
 * Uses tee-mem G-stage page tables for isolation alongside PMP.
 */
#include "enclave.h"
#include "zion.h"
#include "tee.h"
#include "ree.h"
#include "cvm.h"
#include "context.h"
#include "tee-mem.h"
#include "pmp.h"
#include "sm.h"
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
#include <sbi/sbi_hfence.h>
#include "plugins/plugins.h"
#include "platform-hook.h"
#include TARGET_PLATFORM_HEADER

#define ENCLAVE_EPM_MAX_BLOCKS 128 /* 256 MiB with 2 MiB data blocks */

/* OpenSBI leaves only about 4 KiB for each M-mode C stack. Keep the temporary
 * EPM block vector in per-hart static storage so large enclave creation does
 * not consume one quarter of that stack before entering the page-table code. */
static uint64_t enclave_epm_block_workspaces[MAX_REE_HARTS]
	[ENCLAVE_EPM_MAX_BLOCKS];

/* ---- Global attestation state (was in zion/sm.c) ---- */
byte sm_hash[MDSIZE] = { 0 };
byte sm_signature[SIGNATURE_SIZE] = { 0 };
byte sm_public_key[PUBLIC_KEY_SIZE] = { 0 };
byte sm_private_key[PRIVATE_KEY_SIZE] = { 0 };
byte sm_sealing_root[SEALING_ROOT_SIZE] = { 0 };
byte dev_public_key[PUBLIC_KEY_SIZE] = { 0 };

/* OpenSBI's default 8 KiB hart allocation contains a 4 KiB scratch page,
 * leaving only 4 KiB for the M-mode C stack.  Ed25519 already consumes most
 * of that budget, so attestation payloads and KDF input must not be automatic
 * objects.  A hart cannot execute two M-mode calls concurrently; per-hart
 * workspaces therefore preserve SMP concurrency without a global crypto lock.
 * Every caller wipes its workspace before returning. */
union sealing_key_response {
	struct zion_sbi_sealing_key legacy;
	struct zion_sbi_sealing_key_v1 versioned;
};

struct attestation_workspace {
	struct report report;
	union sealing_key_response sealing_key;
	unsigned char key_ident[ATTEST_DATA_MAXLEN];
	unsigned char measurement[MDSIZE];
};

static struct attestation_workspace attest_workspaces[MAX_REE_HARTS];
static unsigned char sealing_info[MAX_REE_HARTS]
	[SEALING_KDF_V1_INFO_OVERHEAD + MDSIZE + ATTEST_DATA_MAXLEN];

void sm_sign(void *signature, const void *data, size_t len)
{
	sign(signature, data, len, sm_public_key, sm_private_key);
}

int sm_derive_sealing_key(unsigned char *key,
			  const unsigned char *key_ident,
			  size_t key_ident_size,
			  const unsigned char *enclave_hash)
{
	unsigned int hart_index = zion_current_hart_index();
	unsigned char *info;
	int ret;

	if (!key || !enclave_hash || key_ident_size > ATTEST_DATA_MAXLEN ||
	    (key_ident_size && !key_ident) || hart_index >= MAX_REE_HARTS)
		return -1;

	info = sealing_info[hart_index];
	ret = kdf_derive_sealing_key_v1(sm_sealing_root, SEALING_ROOT_SIZE,
		  enclave_hash, MDSIZE, key_ident, key_ident_size,
		  key, SEALING_KEY_SIZE, info, sizeof(sealing_info[hart_index]));
	return ret;
}

/* ---- Enclave array (was in zion/enclave.c) ---- */
struct enclave enclaves[ENCL_MAX];

/* ---- Per-hart enclave context ---- */
static struct cpu_state cpus[MAX_REE_HARTS];

int cpu_is_enclave_context(void)
{
	return cpus[zion_current_hart_index()].is_enclave;
}

int cpu_get_enclave_id(void)
{
	return cpus[zion_current_hart_index()].eid;
}

void cpu_enter_enclave_context(enclave_id eid)
{
	unsigned int hart_index = zion_current_hart_index();
	cpus[hart_index].is_enclave = 1;
	cpus[hart_index].eid = eid;
}

void cpu_exit_enclave_context(void)
{
	cpus[zion_current_hart_index()].is_enclave = 0;
}

/* ---- Enclave metadata ---- */
static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;
static unsigned int enclave_handle_generation[MAX_ENCLAVES];
static unsigned long enclave_retired_bitmap;

#define ENCLAVE_HANDLE_SLOT_BITS 8U
#define ENCLAVE_HANDLE_SLOT_MASK ((1U << ENCLAVE_HANDLE_SLOT_BITS) - 1U)
#define ENCLAVE_HANDLE_GENERATION_MAX (~0U >> ENCLAVE_HANDLE_SLOT_BITS)

#if MAX_ENCLAVES > (1U << ENCLAVE_HANDLE_SLOT_BITS)
#error "MAX_ENCLAVES does not fit in an enclave handle"
#endif

static unsigned int enclave_public_handle(enclave_id eid)
{
	return enclave_handle_generation[eid] << ENCLAVE_HANDLE_SLOT_BITS |
	       (unsigned int)eid;
}

#define ENCLAVE_EXISTS(eid) ((eid) < MAX_ENCLAVES && \
			     enclaves[(eid)].state != INVALID)

static unsigned long encl_alloc_eid(enclave_id *_eid)
{
	spin_lock(&encl_lock);
	for (int i = 0; i < MAX_ENCLAVES; i++) {
		if (enclaves[i].state == INVALID &&
		    !(enclave_retired_bitmap & (1UL << i))) {
			enclaves[i].state = ALLOCATED;
			spin_unlock(&encl_lock);
			*_eid = i;
			return SBI_ERR_SM_ENCLAVE_SUCCESS;
		}
	}
	spin_unlock(&encl_lock);
	return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
}

static unsigned long encl_free_eid(enclave_id eid)
{
	spin_lock(&encl_lock);
	/* Retire all owner and execution metadata before making the slot
	 * allocatable again.  Platform-private data is left to the platform
	 * destroy/init hooks, but no stale measurement or thread pointer may
	 * survive EID reuse. */
	enclaves[eid].encl_satp = 0;
	enclaves[eid].owner_mode = REE;
	enclaves[eid].owner_rtid = (unsigned int)-1;
	sbi_memset(enclaves[eid].regions, 0,
		   sizeof(enclaves[eid].regions));
	sbi_memset(enclaves[eid].hash, 0, sizeof(enclaves[eid].hash));
	sbi_memset(enclaves[eid].sign, 0, sizeof(enclaves[eid].sign));
	sbi_memset(&enclaves[eid].params, 0,
		   sizeof(enclaves[eid].params));
	enclaves[eid].n_thread = 0;
	sbi_memset(enclaves[eid].threads, 0,
		   sizeof(enclaves[eid].threads));
	enclaves[eid].hgatp = 0;
	enclaves[eid].pgd = 0;
	sbi_memset(&enclaves[eid].mem_info, 0,
		   sizeof(enclaves[eid].mem_info));
	enclaves[eid].active_thread = NULL;
	enclaves[eid].saved_mepc = 0;
	if (enclave_handle_generation[eid] ==
	    ENCLAVE_HANDLE_GENERATION_MAX)
		enclave_retired_bitmap |= 1UL << eid;
	else
		enclave_handle_generation[eid]++;
	enclaves[eid].state = INVALID;
	spin_unlock(&encl_lock);
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void enclave_init_metadata(void)
{
	sbi_memset(enclave_handle_generation, 0,
		   sizeof(enclave_handle_generation));
	enclave_retired_bitmap = 0;
	for (int i = 0; i < ENCL_MAX; i++) {
		enclaves[i].eid = i;
		enclaves[i].state = INVALID;
		enclaves[i].owner_mode = REE;
		enclaves[i].owner_rtid = (unsigned int)-1;
		enclaves[i].n_thread = 0;
		sbi_memset(&enclaves[i].regions, 0,
			   sizeof(enclaves[i].regions));
		platform_init_enclave(&enclaves[i]);
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
				       struct zion_sbi_create_t *dest)
{
	int region_overlap = copy_to_sm(dest, src, sizeof(struct zion_sbi_create_t));

	if (region_overlap)
		return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
	else
		return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct zion_sbi_create_t *args)
{
	uintptr_t epm_start, epm_end, utm_start, utm_end;

	if (!args->epm_region.size ||
	    (args->epm_region.paddr & (PAGE_SIZE - 1)) ||
	    (args->epm_region.size & (PAGE_SIZE - 1)))
		return 0;

	/* check for overflow */
	if (args->epm_region.paddr >=
	    args->epm_region.paddr + args->epm_region.size)
		return 0;
	if (args->utm_region.size) {
		if (!args->utm_region.paddr ||
		    (args->utm_region.paddr & (PAGE_SIZE - 1)) ||
		    (args->utm_region.size & (PAGE_SIZE - 1)) ||
		    args->utm_region.paddr >=
			args->utm_region.paddr + args->utm_region.size)
			return 0;
	} else if (args->utm_region.paddr) {
		return 0;
	}

	epm_start = args->epm_region.paddr;
	epm_end   = args->epm_region.paddr + args->epm_region.size;
	utm_start = args->utm_region.paddr;
	utm_end   = utm_start + args->utm_region.size;

	/* EPM is copied into enclave-private blocks while UTM remains mapped to
	 * the parent.  Letting the two GPA ranges overlap would give one address
	 * conflicting private/shared meanings. */
	if (args->utm_region.size && epm_start < utm_end && utm_start < epm_end)
		return 0;

	/* check that runtime/user/free pointers are within EPM */
	if (args->runtime_paddr < epm_start ||
	    args->runtime_paddr >= epm_end)
		return 0;
	if (args->user_paddr < epm_start ||
	    args->user_paddr >= epm_end)
		return 0;
	if (args->free_paddr < epm_start ||
	    args->free_paddr > epm_end)
		/* note: free_paddr == epm_end if there's no free memory */
		return 0;

	/* check ordering: runtime < user < free */
	if (args->runtime_paddr > args->user_paddr)
		return 0;
	if (args->user_paddr > args->free_paddr)
		return 0;

	/* The initial stack pointer is free_paddr + free_requested.  Validate
	 * with subtraction so an overflowing request cannot escape the EPM. */
	if (args->free_requested > epm_end - args->free_paddr)
		return 0;

	/* Measurement hashes complete pages from dram_base through free_paddr,
	 * matching the Zion report format. */
	if ((args->runtime_paddr & (PAGE_SIZE - 1)) ||
	    (args->user_paddr & (PAGE_SIZE - 1)) ||
	    (args->free_paddr & (PAGE_SIZE - 1)))
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
			       MSTATUS_MPV | SSTATUS_FS;
	thread->csrs.hstatus = HSTATUS_SPV | HSTATUS_VSXL;
	thread->csrs.hcounteren = 0x7; /* enable cycle/time/inst counters */
	thread->csrs.hgatp = enc->hgatp;
	thread->csrs.vsatp = 0; /* no S-mode page table initially */
	/* Permit FP from the first VS/VU instruction. Eyrie also sets FS during
	 * boot, while bare measured payloads have no runtime initialization. */
	thread->csrs.vsstatus = SSTATUS_SUM | SSTATUS_FS;
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

static int copy_parent_memory(zion_mode owner_mode, unsigned int owner_rtid,
			      void *dest, uintptr_t src, size_t size)
{
	if (owner_mode == REE) {
		/* The REE can bypass its driver and issue this SBI directly.  M-mode
		 * must not use an unchecked caller PA to read the monitor or a trusted
		 * extent into a new enclave.  The catch-all OS PMP region explicitly
		 * permits overlap, while the SM and every trusted extent do not. */
		if (!size || pmp_detect_region_overlap_atomic(src, size))
			return -1;
		sbi_memcpy(dest, (void *)src, size);
		return 0;
	}
	if (owner_mode == CVM)
		return cvm_copy_from_gpa(owner_rtid, dest, src, size);

	return -1;
}

static int zero_parent_memory(zion_mode owner_mode, unsigned int owner_rtid,
			      uintptr_t addr, size_t size)
{
	if (!size)
		return 0;
	if (owner_mode == REE) {
		/* UTM clearing is a write primitive.  Never let an untrusted direct
		 * SBI target the monitor or trusted memory through M-mode. */
		if (pmp_detect_region_overlap_atomic(addr, size))
			return -1;
		sbi_memset((void *)addr, 0, size);
		return 0;
	}
	if (owner_mode == CVM)
		return cvm_zero_gpa(owner_rtid, addr, size);

	return -1;
}

static int map_parent_utm(enclave_id eid, zion_mode owner_mode,
			  unsigned int owner_rtid, uintptr_t utm_gpa,
			  size_t utm_size)
{
	int enc_cvm_id = CVM_NUM + eid;

	for (size_t offset = 0; offset < utm_size; offset += PAGE_SIZE) {
		uint64_t hpa = utm_gpa + offset;
		size_t contiguous = PAGE_SIZE;

		if (owner_mode == CVM &&
		    (cvm_translate_gpa(owner_rtid, utm_gpa + offset, true,
				       &hpa, &contiguous) || contiguous < PAGE_SIZE))
			return -1;
		if (map_gpa_to_hpa(&g_mem_pool, enc_cvm_id, utm_gpa + offset,
				   hpa, PAGE_SIZE, 0, PTE_R | PTE_W))
			return -1;
	}

	return 0;
}

unsigned long create_enclave(unsigned long *eidptr,
			     struct zion_sbi_create_t create_args,
			     zion_mode owner_mode, unsigned int owner_rtid)
{
	/*
	 * Compatible with Zion SDK/driver interface:
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
	size_t initialized_size = create_args.free_paddr - epm_pa;
	uintptr_t utm_pa  = create_args.utm_region.paddr;
	size_t utm_size   = create_args.utm_region.size;
	enclave_id eid;
	unsigned long ret;
	bool platform_created = false;
	unsigned int hart_index = zion_current_hart_index();
	uint64_t *epm_blocks;

	tee_log("[SM] enclave create request: owner=%d:%u epm=0x%lx+0x%lx "
		 "utm=0x%lx+0x%lx runtime=0x%lx user=0x%lx free=0x%lx "
		 "requested=0x%lx\n",
		 owner_mode, owner_rtid, epm_pa, (unsigned long)epm_size,
		 utm_pa, (unsigned long)utm_size, create_args.runtime_paddr,
		 create_args.user_paddr, create_args.free_paddr,
		 create_args.free_requested);

	if (hart_index >= MAX_REE_HARTS || !eidptr ||
	    (owner_mode != REE && owner_mode != CVM) ||
	    (owner_mode == CVM && owner_rtid >= CVM_NUM) ||
	    !is_create_args_valid(&create_args))
		return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
	epm_blocks = enclave_epm_block_workspaces[hart_index];
	sbi_memset(epm_blocks, 0,
		   sizeof(enclave_epm_block_workspaces[hart_index]));

	/* Creation reads parent memory and allocates trusted blocks.  Count it as
	 * a trusted-memory user for the complete transaction so an extent cannot
	 * be inserted between the REE PMP-range check and the M-mode copy, or be
	 * removed while its blocks/page-table metadata are being consumed. */
	tee_mem_context_enter_begin();
	tee_mem_context_enter_end();
	if (owner_mode == REE &&
	    (pmp_detect_region_overlap_atomic(epm_pa, epm_size) ||
	     (utm_size &&
	      pmp_detect_region_overlap_atomic(utm_pa, utm_size)))) {
		ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
		goto release_memory_policy;
	}

	/* Allocate EID */
	ret = encl_alloc_eid(&eid);
	if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
		goto release_memory_policy;

	/* Clean UTM through the parent's address space.  For a CVM these are
	 * guest-physical addresses, never directly dereferenceable HPAs. */
	if (zero_parent_memory(owner_mode, owner_rtid, utm_pa, utm_size)) {
		ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
		goto free_eid;
	}

	/* ---- Allocate EPM blocks from secure memory pool ---- */
	uintptr_t first_epm_gpa = epm_pa & ~(BLOCK_SIZE - 1);
	uintptr_t gpa_offset = epm_pa - first_epm_gpa;
	if (epm_size > ENCLAVE_EPM_MAX_BLOCKS * BLOCK_SIZE - gpa_offset) {
		ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
		goto free_eid;
	}
	size_t covered_size = gpa_offset + epm_size;
	int n_blocks = (covered_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
	for (int i = 0; i < n_blocks; i++) {
		uint64_t pa = alloc_data_block(
			&g_mem_pool.data_pool, DATA_BLOCK_ENCLAVE_OWNER(eid));
		if (pa == (uint64_t)-1) {
			tee_log("[SM] create_enclave: eid=%d alloc block %d failed\n",
				   eid, i);
			ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
			goto free_blocks;
		}
		epm_blocks[i] = pa;
	}

	/* ---- Copy EPM content from driver-allocated PA → secure pool ---- */
	//tee_log("[SM] create_enclave: EPM copy: epm_pa=0x%lx n_blocks=%d block_size=0x%lx\n",
	//	   epm_pa, n_blocks, BLOCK_SIZE);
	/* EPM backing storage is allocated in 2 MiB blocks and alloc_data_block()
	 * has already scrubbed every byte.  The parent only initialized the range
	 * through free_paddr; copying the remaining (potentially hundreds of MiB)
	 * free-memory tail would merely copy zeroes over zeroes while holding the
	 * caller in one M-mode SBI transaction. */
	//tee_log("[SM]   gpa_offset=0x%lx within megapage\n", gpa_offset);
	for (size_t cursor = 0; cursor < initialized_size;) {
		uintptr_t src = epm_pa + cursor;
		uintptr_t block_offset = src & (BLOCK_SIZE - 1);
		int block_index = (src - first_epm_gpa) / BLOCK_SIZE;
		size_t chunk = initialized_size - cursor;
		uintptr_t dst = epm_blocks[block_index] + block_offset;

		if (chunk > BLOCK_SIZE - block_offset)
			chunk = BLOCK_SIZE - block_offset;
		//tee_log("[SM]   block[%d]: src=0x%lx dst=0x%lx chunk=0x%lx\n",
		//	   i, src, dst, chunk);
		//tee_log("[SM]   src[0..3]: %08x %08x %08x %08x\n",
		//	   ((volatile uint32_t *)src)[0],
		//	   ((volatile uint32_t *)src)[1],
		//	   ((volatile uint32_t *)src)[2],
		//	   ((volatile uint32_t *)src)[3]);
		if (copy_parent_memory(owner_mode, owner_rtid, (void *)dst, src,
				       chunk)) {
			ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
			goto free_blocks;
		}
		cursor += chunk;
		//tee_log("[SM]   dst[0..3]: %08x %08x %08x %08x\n",
		//	   ((volatile uint32_t *)dst)[0],
		//	   ((volatile uint32_t *)dst)[1],
		//	   ((volatile uint32_t *)dst)[2],
		//	   ((volatile uint32_t *)dst)[3]);
	}

	/* ---- Build G-stage page table ---- */
	reset_enclave_pt_pool(&g_mem_pool, (uint32_t)eid);
	int enc_cvm_id = CVM_NUM + eid;
	void *root_pt = alloc_enclave_root_pt(&g_mem_pool, (uint32_t)eid);
	if (!root_pt) {
		ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
		goto free_blocks;
	}

	/* Map aligned, complete blocks with 2 MiB leaves.  Retain 4 KiB leaves for
	 * an unaligned head/tail so no padding outside the declared EPM is exposed.
	 * Large RV8 workloads otherwise require tens of thousands of synchronous
	 * page-table operations during enclave creation. */
	for (size_t cursor = 0; cursor < epm_size;) {
		uint64_t gpa = epm_pa + cursor;
		uint64_t block_offset = gpa & (BLOCK_SIZE - 1);
		int block_index = (gpa - first_epm_gpa) / BLOCK_SIZE;
		uint64_t hpa = epm_blocks[block_index] + block_offset;
		size_t remaining = epm_size - cursor;
		size_t map_size = PAGE_SIZE;
		int target_level = 0;

		if (!block_offset && !(hpa & (BLOCK_SIZE - 1)) &&
		    remaining >= BLOCK_SIZE) {
			map_size = BLOCK_SIZE;
			target_level = 1;
		}

		if (map_gpa_to_hpa(&g_mem_pool, enc_cvm_id,
				   gpa, hpa, map_size, target_level,
				   PTE_R | PTE_W | PTE_X)) {
			ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
			goto free_blocks;
		}
		cursor += map_size;
	}

	/* UTM remains owned by the parent.  A native caller is identity-mapped;
	 * a CVM caller is mapped to the HPA behind each parent GPA. */
	if (utm_pa && utm_size) {
		if (map_parent_utm(eid, owner_mode, owner_rtid, utm_pa,
				   utm_size)) {
			ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
			goto free_blocks;
		}
	}

	/* Compute hgatp */
	uint64_t hgatp = ((unsigned long)root_pt >> PAGE_SHIFT) |
		 (HGATP_MODE_SV48X4 << HGATP_MODE_SHIFT) |
		 (((unsigned long)(CVM_NUM + eid + 1) << HGATP_VMID_SHIFT) &
		  HGATP_VMID_MASK);

	/* ---- Fill enclave metadata ---- */
	enclaves[eid].eid = eid;
	enclaves[eid].owner_mode = owner_mode;
	enclaves[eid].owner_rtid = owner_rtid;
	enclaves[eid].n_thread = 0;
	enclaves[eid].hgatp = hgatp;
	enclaves[eid].pgd = (unsigned long)root_pt;
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
	platform_created = true;

	ret = validate_and_hash_enclave(&enclaves[eid]);
	if (ret)
		goto destroy_platform;

	spin_lock(&encl_lock);
	enclaves[eid].state = FRESH;
	spin_unlock(&encl_lock);

	*eidptr = eid;
	//tee_log("[SM] create_enclave: eid=%d epm_gpa=0x%lx size=0x%lx hgatp=0x%lx\n",
	//	   eid, epm_pa, epm_size, hgatp);
	sbi_memset(epm_blocks, 0,
		   sizeof(enclave_epm_block_workspaces[hart_index]));
	tee_mem_context_exit_begin();
	tee_mem_context_exit_end();
	return SBI_ERR_SM_ENCLAVE_SUCCESS;

destroy_platform:
	if (platform_created)
		platform_destroy_enclave(&enclaves[eid]);
free_blocks:
	free_data_blocks_per_owner(&g_mem_pool.data_pool,
				   DATA_BLOCK_ENCLAVE_OWNER(eid));
	reset_enclave_pt_pool(&g_mem_pool, (uint32_t)eid);
free_eid:
	encl_free_eid(eid);

release_memory_policy:
	sbi_memset(epm_blocks, 0,
		   sizeof(enclave_epm_block_workspaces[hart_index]));
	tee_mem_context_exit_begin();
	tee_mem_context_exit_end();
	return ret;
}

unsigned long destroy_enclave(enclave_id eid, zion_mode owner_mode,
			      unsigned int owner_rtid)
{
	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(eid) ||
	    enclaves[eid].owner_mode != owner_mode ||
	    enclaves[eid].owner_rtid != owner_rtid ||
	    (enclaves[eid].state != FRESH &&
	     enclaves[eid].state != STOPPED)) {
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

	/* free_data_blocks_per_owner() now zeroes each block before
	 * returning it to the free list, preventing data leakage. */
	free_data_blocks_per_owner(&g_mem_pool.data_pool,
				   DATA_BLOCK_ENCLAVE_OWNER(eid));

	enclaves[eid].hgatp = 0;

	/* Release enclave G-stage PT pool */
	reset_enclave_pt_pool(&g_mem_pool, (uint32_t)eid);

	encl_free_eid(eid);
	//tee_log("[SM] destroy_enclave: eid=%d destroyed\n", eid);
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
	zion_mode owner_mode = hart_get_mode();
	unsigned int owner_rtid = hart_get_caller_rtid();
	context_switch_to_mode switch_mode;
	struct tee_thread *parent_thread;

	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state != FRESH ||
	    enclaves[eid].owner_mode != owner_mode ||
	    enclaves[eid].owner_rtid != owner_rtid) {
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

	/* Entry point = dram_base (loader-binary entry, loaded by host SDK) */
	uintptr_t entry = p->dram_base;
	uintptr_t sp = p->free_base + p->free_requested; /* stack at top of free */
	uintptr_t arg0 = p->dram_base; /* Eyrie expects dram_base in a0 */

	//tee_log("[SM] run_enclave: eid=%d entry=0x%lx dram_base=0x%lx runtime=0x%lx\n",
	//	   eid, entry, p->dram_base, p->runtime_base);
	//tee_log("[SM]   dram_size=0x%lx user=0x%lx free=0x%lx utm=0x%lx\n",
	//	   p->dram_size, p->user_base, p->free_base, p->untrusted_base);

	setup_enclave_thread(thread, &enclaves[eid], entry, sp, arg0, eid);

	//tee_log("[SM] ===== ENCLAVE FIRST ENTRY =====\n");
	//tee_log("[SM] CSRs: mepc=0x%lx mstatus=0x%lx hstatus=0x%lx\n",
	//	   thread->csrs.mepc, thread->csrs.mstatus, thread->csrs.hstatus);
	//tee_log("[SM] CSRs: hgatp=0x%lx hcounteren=0x%lx vsatp=0x%lx vsstatus=0x%lx\n",
	//	   thread->csrs.hgatp, thread->csrs.hcounteren,
	//	   thread->csrs.vsatp, thread->csrs.vsstatus);
	//tee_log("[SM] CSRs: vstvec=0x%lx vsscratch=0x%lx vsepc=0x%lx vscause=0x%lx\n",
	//	   thread->csrs.vstvec, thread->csrs.vsscratch,
	//	   thread->csrs.vsepc, thread->csrs.vscause);
	//tee_log("[SM] GPRs: sp=0x%lx a0=0x%lx a1=0x%lx a2=0x%lx\n",
	//	   thread->gprs.sp, thread->gprs.a0,
	//	   thread->gprs.a1, thread->gprs.a2);
	//tee_log("[SM] GPRs: a3=0x%lx a4=0x%lx a5=0x%lx a6=0x%lx a7=0x%lx\n",
	//	   thread->gprs.a3, thread->gprs.a4, thread->gprs.a5,
	//	   thread->gprs.a6, thread->gprs.a7);
	//tee_log("[SM] Params: dram=0x%lx size=0x%lx runtime=0x%lx user=0x%lx\n",
	//	   p->dram_base, p->dram_size, p->runtime_base, p->user_base);
	//tee_log("[SM] Params: free=0x%lx utm=0x%lx utm_size=0x%lx\n",
	//	   p->free_base, p->untrusted_base, p->untrusted_size);
	//tee_log("[SM] =================================\n");

	parent_thread = hart_get_caller()->tthread;
	switch_mode = owner_mode == CVM ? CVM_TO_ENCLAVE : REE_TO_ENCLAVE;
	enclaves[eid].active_thread = thread;
	platform_switch_to_enclave(&enclaves[eid]);
	cpu_enter_enclave_context(eid);
	//tee_log("[SM] run_enclave: eid=%d entry=0x%lx sp=0x%lx\n",
	//	   eid, entry, sp);

	/*
	 * Switch context: host → enclave.
	 * context_switch_to saves host state, loads enclave state into regs,
	 * switches trap vector, sets PMP, loads hgatp.
	 * After this returns, regs contains the enclave's state.
	 * The caller (tee-sbi-opensbi.c) sets out->skip_regs_update = true
	 * so sbi_ecall_handler won't overwrite regs->a0/mepc.
	 * OpenSBI's assembly trap exit path restores regs and mrets into
	 * VS-mode (enclave), exactly like CVM's enter_cvm() path.
	 */
	context_switch_to(regs, parent_thread, thread, switch_mode,
			  0, NULL, NULL);

	return 0;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid,
			   unsigned long exit_cause)
{
	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state != RUNNING ||
	    !enclaves[eid].active_thread) {
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;
	}
	enclaves[eid].state = EXITING;
	spin_unlock(&encl_lock);

	cpu_exit_enclave_context();
	platform_switch_from_enclave(&enclaves[eid]);

	/* Restore host context. src=enclave thread (saves enclave CSR state),
	 * dst=host thread (loads host CSR state from saved state). */
	struct tee_thread *encl_thread = enclaves[eid].active_thread;
	struct tee_thread *host_thread = encl_thread->prev_state->tthread;
	context_switch_from_mode switch_mode =
		enclaves[eid].owner_mode == CVM ?
		CVM_FROM_ENCLAVE : REE_FROM_ENCLAVE;
	context_switch_from(regs, encl_thread, host_thread,
			    switch_mode,
			    0, NULL, NULL, NULL, 0);

	/* Free the allocated tee_thread */
	tee_thread_free(encl_thread);
	spin_lock(&encl_lock);
	enclaves[eid].active_thread = NULL;
	if (enclaves[eid].n_thread)
		enclaves[eid].n_thread--;
	enclaves[eid].state = STOPPED;
	spin_unlock(&encl_lock);

	return exit_cause ? exit_cause : SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request,
			   enclave_id eid, bool advance_mepc)
{
	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state != RUNNING ||
	    !enclaves[eid].active_thread) {
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;
	}
	enclaves[eid].state = EXITING;
	spin_unlock(&encl_lock);

	cpu_exit_enclave_context();
	platform_switch_from_enclave(&enclaves[eid]);

	struct tee_thread *encl_thread = enclaves[eid].active_thread;
	struct tee_thread *host_thread = encl_thread->prev_state->tthread;
	context_switch_from_mode switch_mode =
		enclaves[eid].owner_mode == CVM ?
		CVM_FROM_ENCLAVE : REE_FROM_ENCLAVE;
	context_switch_from(regs, encl_thread, host_thread,
			    switch_mode,
			    0, NULL, NULL, NULL, 1);

	/* An explicit STOP arrives through a four-byte SBI ecall and must resume
	 * after it.  A monitor-initiated interrupt stop must retry the interrupted
	 * instruction, so its PC is preserved exactly. */
	enclaves[eid].saved_mepc = encl_thread->csrs.mepc;
	if (advance_mepc) {
		enclaves[eid].saved_mepc += 4;
		/* The resumed SBI call completed successfully. Do not return the
		 * original STOP request value that was in a0 at trap time. */
		encl_thread->gprs.a0 = SBI_ERR_SM_ENCLAVE_SUCCESS;
	}

	/* Set MPV=1 so mret enters virtual mode (VS or VU depending on MPP).
	 * Do NOT modify MPP — hardware already set it to the correct privilege
	 * level at trap time (S for VS-mode, U for VU-mode).  The enclave's
	 * EAPP runs in U-mode, so MPP=0 is valid and must be preserved. */
	encl_thread->csrs.mstatus |= MSTATUS_MPV;

	/* Keep active_thread alive — resume will reuse it */
	spin_lock(&encl_lock);
	if (enclaves[eid].n_thread)
		enclaves[eid].n_thread--;
	enclaves[eid].state = STOPPED;
	spin_unlock(&encl_lock);

	switch (request) {
	case STOP_TIMER_INTERRUPT:
		return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
	case STOP_EDGE_CALL_HOST:
		return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
	default:
		return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
	}
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
	zion_mode owner_mode = hart_get_mode();
	unsigned int owner_rtid = hart_get_caller_rtid();
	context_switch_to_mode switch_mode;
	struct tee_thread *parent_thread;

	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state != STOPPED ||
	    enclaves[eid].owner_mode != owner_mode ||
	    enclaves[eid].owner_rtid != owner_rtid ||
	    !enclaves[eid].active_thread ||
	    enclaves[eid].n_thread >= MAX_ENCL_THREADS) {
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
	}
	enclaves[eid].state = RUNNING;
	enclaves[eid].n_thread++;
	spin_unlock(&encl_lock);

	/* Reuse the tee_thread from the previous run (kept alive by stop) */
	struct tee_thread *thread = enclaves[eid].active_thread;

	/* Restore PC from where the enclave stopped */
	thread->csrs.mepc = enclaves[eid].saved_mepc;

	/*
	 * Don't reset sp or a0 — Eyrie's stack and register state are
	 * active.  switch_gprs (via stop_enclave) already saved the
	 * enclave's running-state GPRs into encl_thread->gprs.
	 * Blindly overwriting a0 breaks code that uses a0 for something
	 * other than dram_base (e.g. loader-binary's elf32_checkFile
	 * receives an elf_t* struct pointer in a0).
	 */

	parent_thread = hart_get_caller()->tthread;
	switch_mode = owner_mode == CVM ? CVM_TO_ENCLAVE : REE_TO_ENCLAVE;
	platform_switch_to_enclave(&enclaves[eid]);
	cpu_enter_enclave_context(eid);
	// tee_log("[SM] resume_enclave: eid=%d mepc=0x%lx\n",
	// 	   eid, thread->csrs.mepc);

	context_switch_to(regs, parent_thread, thread, switch_mode,
			  0, NULL, NULL);

	return 0;
}

/* ---- Attestation and sealing ---- */
static int resolve_enclave_epm_page(struct enclave *enc, uintptr_t gpa,
				    uintptr_t *hpa)
{
	pte_t *pt;
	uint64_t page_hpa;
	size_t contiguous = 0;

	if (!enc || !hpa || !enc->pgd ||
	    gpa < enc->mem_info.epm_base ||
	    gpa >= enc->mem_info.epm_base + enc->mem_info.epm_size ||
	    (gpa & (PAGE_SIZE - 1)))
		return -1;

	pt = (pte_t *)enc->pgd;
	page_hpa = 0;
	for (int level = 3; level >= 0; level--) {
		uint64_t mask = level == 3 ? CVM_ROOT_PT_INDEX_MASK :
					       ZION_PTE_INDEX_MASK;
		uint64_t index = (gpa >>
			(PAGE_SHIFT + level * gstage_index_bits)) & mask;
		pte_t pte = pt[index];

		if (!(pte & PTE_V))
			return -1;
		if (pte & (PTE_R | PTE_W | PTE_X)) {
			uint64_t leaf_size = PAGE_SIZE <<
					     (level * gstage_index_bits);

			if (!(pte & PTE_R))
				return -1;
			page_hpa = (((pte & ZION_PTE_ADDR_MASK) >>
				       ZION_PTE_PPN_SHIFT) << PAGE_SHIFT) +
				   (gpa & (leaf_size - 1));
			break;
		}
		pt = (pte_t *)(((pte & ZION_PTE_ADDR_MASK) >>
				   ZION_PTE_PPN_SHIFT) << PAGE_SHIFT);
	}
	if (!page_hpa)
		return -1;
	if (page_hpa & (PAGE_SIZE - 1))
		return -1;
	if (!data_block_owned_range(&g_mem_pool.data_pool, page_hpa,
				    DATA_BLOCK_ENCLAVE_OWNER(enc->eid),
				    &contiguous) || contiguous < PAGE_SIZE)
		return -1;

	*hpa = (uintptr_t)page_hpa;
	return 0;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data,
			     uintptr_t size, enclave_id eid)
{
	unsigned int hart_index = zion_current_hart_index();
	struct report *report;
	unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

	if (!report_ptr || size > ATTEST_DATA_MAXLEN || (size && !data))
		return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
	if (hart_index >= MAX_REE_HARTS)
		return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
	report = &attest_workspaces[hart_index].report;

	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state != RUNNING ||
	    !enclaves[eid].active_thread) {
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
	}
	sbi_memset(report, 0, sizeof(*report));
	sbi_memcpy(report->enclave.hash, enclaves[eid].hash, MDSIZE);
	spin_unlock(&encl_lock);

	if (size && copy_to_sm(report->enclave.data, data, size)) {
		ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
		goto out;
	}
	report->enclave.data_len = size;
	sbi_memcpy(report->dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
	sbi_memcpy(report->sm.hash, sm_hash, MDSIZE);
	sbi_memcpy(report->sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
	sbi_memcpy(report->sm.signature, sm_signature, SIGNATURE_SIZE);
	sm_sign(report->enclave.signature, &report->enclave,
		MDSIZE + sizeof(report->enclave.data_len) + size);
	if (!ed25519_verify(report->enclave.signature,
			    (const unsigned char *)&report->enclave,
			    MDSIZE + sizeof(report->enclave.data_len) + size,
			    report->sm.public_key)) {
		ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
		goto out;
	}

	if (copy_from_sm(report_ptr, report, sizeof(*report)))
		ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;

out:
	sbi_memset(report, 0, sizeof(*report));
	return ret;
}

static unsigned long get_sealing_key_response(uintptr_t sealing_key,
			      uintptr_t key_ident, size_t key_ident_size,
			      enclave_id eid, bool versioned)
{
	unsigned int hart_index = zion_current_hart_index();
	struct attestation_workspace *workspace;
	union sealing_key_response *result;
	unsigned char *ident;
	unsigned char *measurement;
	size_t result_size;
	unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

	if (!sealing_key || key_ident_size > ATTEST_DATA_MAXLEN ||
	    (key_ident_size && !key_ident))
		return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
	if (hart_index >= MAX_REE_HARTS)
		return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
	workspace = &attest_workspaces[hart_index];
	result = &workspace->sealing_key;
	ident = workspace->key_ident;
	measurement = workspace->measurement;

	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(eid) || enclaves[eid].state != RUNNING ||
	    !enclaves[eid].active_thread) {
		spin_unlock(&encl_lock);
		return SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
	}
	sbi_memcpy(measurement, enclaves[eid].hash, MDSIZE);
	spin_unlock(&encl_lock);

	sbi_memset(result, 0, sizeof(*result));
	sbi_memset(ident, 0, ATTEST_DATA_MAXLEN);
	if (key_ident_size && copy_to_sm(ident, key_ident, key_ident_size)) {
		ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
		goto out;
	}
	if (sm_derive_sealing_key(result->legacy.key, ident, key_ident_size,
				  measurement)) {
		ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
		goto out;
	}
	if (versioned) {
		result->versioned.kdf_version = SEALING_KDF_VERSION;
		sm_sign(result->versioned.signature, &result->versioned,
			SEALING_KEY_V1_SIGNED_SIZE);
		result_size = sizeof(result->versioned);
	} else {
		sm_sign(result->legacy.signature, result->legacy.key,
			SEALING_KEY_SIZE);
		result_size = sizeof(result->legacy);
	}
	if (copy_from_sm(sealing_key, result, result_size))
		ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;

out:
	sbi_memset(result, 0, sizeof(*result));
	sbi_memset(ident, 0, ATTEST_DATA_MAXLEN);
	sbi_memset(measurement, 0, MDSIZE);
	return ret;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
			      size_t key_ident_size, enclave_id eid)
{
	return get_sealing_key_response(sealing_key, key_ident, key_ident_size,
					eid, false);
}

unsigned long get_sealing_key_v1(uintptr_t sealing_key, uintptr_t key_ident,
				 size_t key_ident_size, enclave_id eid)
{
	return get_sealing_key_response(sealing_key, key_ident, key_ident_size,
					eid, true);
}

unsigned long validate_and_hash_enclave(struct enclave *enclave)
{
	uintptr_t sizes[3];
	uintptr_t page_hpa;
	hash_ctx ctx;

	if (!enclave || enclave->params.runtime_base < enclave->params.dram_base ||
	    enclave->params.user_base < enclave->params.runtime_base ||
	    enclave->params.free_base < enclave->params.user_base ||
	    enclave->params.free_base >
		enclave->params.dram_base + enclave->params.dram_size)
		return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

	sizes[0] = enclave->params.runtime_base - enclave->params.dram_base;
	sizes[1] = enclave->params.user_base - enclave->params.runtime_base;
	sizes[2] = enclave->params.free_base - enclave->params.user_base;
	hash_init(&ctx);
	hash_extend(&ctx, sizes, sizeof(sizes));

	for (uintptr_t page = enclave->params.dram_base;
	     page < enclave->params.free_base; page += PAGE_SIZE) {
		if (resolve_enclave_epm_page(enclave, page, &page_hpa)) {
			sbi_memset(&ctx, 0, sizeof(ctx));
			return SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE;
		}
		hash_extend_page(&ctx, (void *)page_hpa);
	}
	hash_finalize(enclave->hash, &ctx);
	sbi_memset(&ctx, 0, sizeof(ctx));
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* ---- SBI wrappers called by the OpenSBI ecall dispatcher ---- */
static int resolve_owned_enclave_handle(unsigned long handle,
					zion_mode owner_mode,
					unsigned int owner_rtid,
					enclave_id *eid)
{
	unsigned int resolved;
	unsigned int generation = 0;

	if (!eid || (owner_mode != REE && owner_mode != CVM))
		return -1;

	if (owner_mode == CVM) {
		if (handle > (unsigned long)SBI_SM_ENCLAVE_HANDLE_MAX)
			return -1;
		if (cvm_resolve_enclave(owner_rtid, (unsigned int)handle,
					&resolved))
			return -1;
	} else {
		if (handle > (unsigned long)SBI_SM_ENCLAVE_HANDLE_MAX)
			return -1;
		resolved = (unsigned int)handle & ENCLAVE_HANDLE_SLOT_MASK;
		generation = (unsigned int)handle >> ENCLAVE_HANDLE_SLOT_BITS;
	}

	spin_lock(&encl_lock);
	if (!ENCLAVE_EXISTS(resolved) ||
	    (owner_mode == REE &&
	     enclave_handle_generation[resolved] != generation) ||
	    enclaves[resolved].owner_mode != owner_mode ||
	    enclaves[resolved].owner_rtid != owner_rtid) {
		spin_unlock(&encl_lock);
		return -1;
	}
	spin_unlock(&encl_lock);

	*eid = (enclave_id)resolved;
	return 0;
}

unsigned long sbi_sm_create_enclave(unsigned long *out_val,
				    uintptr_t create_args)
{
	struct zion_sbi_create_t args;
	zion_mode owner_mode = hart_get_mode();
	unsigned int owner_rtid = hart_get_caller_rtid();
	unsigned long global_eid;
	unsigned int local_tid;

	if (!out_val || (owner_mode != REE && owner_mode != CVM))
		return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

	unsigned long ret = copy_enclave_create_args(create_args, &args);
	if (ret)
		return ret;

	ret = create_enclave(&global_eid, args, owner_mode, owner_rtid);
	if (ret)
		return ret;

	if (owner_mode == CVM) {
		if (cvm_register_enclave(owner_rtid, (unsigned int)global_eid,
					 &local_tid)) {
			destroy_enclave((enclave_id)global_eid, owner_mode,
					owner_rtid);
			return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
		}
		*out_val = local_tid;
	} else {
		spin_lock(&encl_lock);
		*out_val = enclave_public_handle((enclave_id)global_eid);
		spin_unlock(&encl_lock);
	}

	tee_log("[SM] enclave create: owner=%d:%u handle=%lu eid=%lu\n",
		 owner_mode, owner_rtid, *out_val, global_eid);
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long sbi_sm_destroy_enclave(unsigned long handle)
{
	zion_mode owner_mode = hart_get_mode();
	unsigned int owner_rtid = hart_get_caller_rtid();
	enclave_id eid;
	unsigned long ret;

	if (owner_mode == CVM) {
		if (handle > (unsigned long)SBI_SM_ENCLAVE_HANDLE_MAX)
			return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;
		if (cvm_begin_enclave_destroy(owner_rtid, (unsigned int)handle,
					      &eid))
			return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;
	} else if (resolve_owned_enclave_handle(handle, owner_mode, owner_rtid,
						  &eid)) {
		return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;
	}

	ret = destroy_enclave(eid, owner_mode, owner_rtid);
	if (ret) {
		if (owner_mode == CVM)
			cvm_cancel_enclave_destroy(owner_rtid, (unsigned int)handle,
						   eid);
		return ret;
	}

	if (owner_mode == CVM &&
	    cvm_finish_enclave_destroy(owner_rtid, (unsigned int)handle, eid)) {
		tee_log("[SM] enclave destroy: failed to release owner handle=%lu eid=%u\n",
			handle, eid);
		return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
	}

	tee_log("[SM] enclave destroy: owner=%d:%u handle=%lu eid=%u\n",
		 owner_mode, owner_rtid, handle, eid);
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long sbi_sm_run_enclave(struct sbi_trap_regs *regs,
				 unsigned long handle)
{
	zion_mode owner_mode = hart_get_mode();
	unsigned int owner_rtid = hart_get_caller_rtid();
	enclave_id eid;

	if (resolve_owned_enclave_handle(handle, owner_mode, owner_rtid, &eid))
		return SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
	return run_enclave(regs, eid);
}

unsigned long sbi_sm_resume_enclave(struct sbi_trap_regs *regs,
				    unsigned long handle)
{
	zion_mode owner_mode = hart_get_mode();
	unsigned int owner_rtid = hart_get_caller_rtid();
	enclave_id eid;

	if (resolve_owned_enclave_handle(handle, owner_mode, owner_rtid, &eid))
		return SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
	return resume_enclave(regs, eid);
}

unsigned long sbi_sm_exit_enclave(struct sbi_trap_regs *regs,
				  unsigned long retval)
{
	enclave_id eid = (enclave_id)cpu_get_enclave_id();
	return exit_enclave(regs, eid, 0); /* 0 = clean exit */
}

unsigned long sbi_sm_stop_enclave(struct sbi_trap_regs *regs,
				  unsigned long request)
{
	enclave_id eid = (enclave_id)cpu_get_enclave_id();
	/* stop_enclave switches regs to host context.
	 * sbi_ecall_handler will set regs->a0 = ret, regs->mepc += 4.
	 * The return value tells the host why the enclave stopped. */
	return stop_enclave(regs, request, eid, true);
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

unsigned long sbi_sm_get_sealing_key_v1(uintptr_t seal_key,
					uintptr_t key_ident,
					size_t key_ident_size)
{
	return get_sealing_key_v1(seal_key, key_ident, key_ident_size,
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
