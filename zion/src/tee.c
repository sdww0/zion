#include <sbi/sbi_types.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include "zion.h"
#include "tee.h"
#include "ree.h"
#include "cvm.h"
#include "pmp.h"
#include "crypto.h"
#include "mprv.h"
#include "platform-hook.h"

#include "tee-mem.h"

struct tee_thread tee_threads[MAX_TEE_THREADS];
unsigned int tee_thread_next = 0;
#define TEE_THREAD_BITMAP_BITS (sizeof(unsigned long) * 8)
#define TEE_THREAD_BITMAP_WORDS \
	((MAX_TEE_THREADS + TEE_THREAD_BITMAP_BITS - 1) / \
	 TEE_THREAD_BITMAP_BITS)
static unsigned long tee_thread_alloc_bitmap[TEE_THREAD_BITMAP_WORDS];
static spinlock_t tee_thread_lock = SPIN_LOCK_INITIALIZER;

int tee_region_id = -1;
int tee_alias_region_id = -1;

static bool tee_thread_bit_is_set(size_t index)
{
	return tee_thread_alloc_bitmap[index / TEE_THREAD_BITMAP_BITS] &
	       (1UL << (index % TEE_THREAD_BITMAP_BITS));
}

static void tee_thread_bit_set(size_t index)
{
	tee_thread_alloc_bitmap[index / TEE_THREAD_BITMAP_BITS] |=
		1UL << (index % TEE_THREAD_BITMAP_BITS);
}

static void tee_thread_bit_clear(size_t index)
{
	tee_thread_alloc_bitmap[index / TEE_THREAD_BITMAP_BITS] &=
		~(1UL << (index % TEE_THREAD_BITMAP_BITS));
}

struct tee_thread *tee_thread_alloc(void)
{
	spin_lock(&tee_thread_lock);
	for (size_t i = MAX_REE_HARTS; i < MAX_TEE_THREADS; i++) {
		if (tee_thread_bit_is_set(i))
			continue;

		tee_thread_bit_set(i);
		sbi_memset(&tee_threads[i], 0, sizeof(tee_threads[i]));
		spin_unlock(&tee_thread_lock);
		return &tee_threads[i];
	}
	spin_unlock(&tee_thread_lock);

	return NULL;
}

void tee_thread_free(struct tee_thread *tthread)
{
	if (!tthread)
		return;

	if (tthread < tee_threads ||
	    tthread >= &tee_threads[MAX_TEE_THREADS])
		return;

	size_t index = tthread - tee_threads;

	if (index < MAX_REE_HARTS)
		return;

	spin_lock(&tee_thread_lock);
	if (!tee_thread_bit_is_set(index)) {
		spin_unlock(&tee_thread_lock);
		return;
	}
	sbi_memset(tthread, 0, sizeof(*tthread));
	tee_thread_bit_clear(index);
	spin_unlock(&tee_thread_lock);
}

static size_t get_load_mem_chunk_size(const struct sbi_load_mem *req,
				      size_t cursor)
{
	size_t remaining = req->size - cursor;

	return remaining > BLOCK_SIZE ? BLOCK_SIZE : remaining;
}

static int resolve_load_mem_block(unsigned int d_rtid, uint64_t gpa,
				  uint64_t *block_hpa)
{
	bool created = false;

	if (cvm_resolve_private_block(d_rtid, gpa, block_hpa,
				      &created) != 0)
		return -1;

	if (created) {
		zion_printf(
			"[SM] load_mem(): Allocated block hpa=%lx for gpa=%lx\n",
			*block_hpa, gpa);
		return 0;
	}

	zion_printf(
		"[SM] load_mem(): Block already mapped, block_hpa=%lx for gpa=%lx\n",
		*block_hpa, gpa);

	return 0;
}

static size_t trim_load_mem_chunk_to_block(uint64_t gpa, uint64_t *block_hpa,
					   size_t load_size)
{
	uint64_t offset = gpa & (BLOCK_SIZE - 1);

	*block_hpa += offset;
	if (offset + load_size > BLOCK_SIZE)
		load_size = BLOCK_SIZE - offset;

	zion_printf(
		"[SM] load_mem(): Final block_hpa=%lx, offset=%lx, load_size=%lx\n",
		*block_hpa, offset, load_size);

	return load_size;
}

static int copy_load_mem_chunk(uint64_t block_hpa, unsigned long stash,
			       size_t cursor, size_t load_size)
{
	unsigned long mstatus_old = csr_read(CSR_MSTATUS);
	unsigned long mstatus	   = mstatus_old;

	mstatus &= ~MSTATUS_MPP;
	mstatus |= (PRV_U << MSTATUS_MPP_SHIFT);
	csr_write(CSR_MSTATUS, mstatus);

	zion_printf("[SM] load_mem(): stash=%lx, cursor=%lx, load_size=%lx\n",
		    stash, cursor, load_size);
	int illegal = copy_to_sm((void *)block_hpa, stash + cursor, load_size);
	csr_write(CSR_MSTATUS, mstatus_old);

	return illegal ? -1 : 0;
}

void set_inited(unsigned int tid)
{
	unsigned int target_rtid;
	zion_mode target_mode;
	struct zion_state *current_state = hart_get_caller();
	if (current_state->mode == REE) {
		if (tid >= MAX_TEES)
			return;
		target_rtid = ree.tees[tid].id;
		target_mode = ree.tees[tid].mode;

	} else if (current_state->mode == CVM) {
		if (current_state->rtid >= CVM_NUM || tid >= MAX_TEES)
			return;
		target_rtid = cvms[current_state->rtid].tees[tid].id;
		target_mode = cvms[current_state->rtid].tees[tid].mode;
	} else {
		return;
	}

	if (target_mode == CVM) {
		if (cvm_get_by_rtid(target_rtid) != 0)
			return;
		cvms[target_rtid].inited = true;
		cvm_put(target_rtid);
	}
}

unsigned long reserve_mem(unsigned long base, unsigned long count)
{
	unsigned long size;
	unsigned long result = 0;
#ifdef ZION_MEGREZ_ACTIVATE
	uintptr_t alias = 0;
#endif

	if (!count || count > (~0UL >> PAGE_SHIFT) ||
	    base + (count << PAGE_SHIFT) < base)
		return -1;
	size = count << PAGE_SHIFT;

	if (tee_mem_maintenance_begin())
		return SBI_EINVALID_STATE;
	if (tee_region_id >= 0) {
		result = SBI_EALREADY;
		goto out;
	}
	tee_log("[SBI] reserve_mem(): base=0x%lx, count=0x%lx, size=0x%lx\n",
		   base, count, size);
	int ret = tee_mem_init((uint8_t *)base, count);
	tee_log("[SBI] reserve_mem(): tee_mem_init() ret=%d\n", ret);
	if (ret) {
		tee_log("[SBI] reserve_mem(): tee_mem_init() failed, base=0x%lx, count=0x%lx, ret=%d\n",
			   base, count, ret);
		result = ret;
		goto out;
	}

	tee_region_id = teem_init(base, size);
	if (tee_region_id < 0) {
		tee_log("[SBI] reserve_mem(): teem_init() failed, base=0x%lx, count=0x%lx, ret=%d\n",
			   base, count, tee_region_id);
		result = tee_region_id;
		tee_region_id = -1;
		goto out;
	}

#ifdef ZION_MEGREZ_ACTIVATE
	if (!platform_security_alias(base, size, &alias)) {
		tee_log("[SBI] reserve_mem(): range has no Megrez security alias\n");
		pmp_region_free_atomic(tee_region_id);
		tee_region_id = -1;
		result = SBI_EBAD_RANGE;
		goto out;
	}
	tee_alias_region_id = teem_init(alias, size);
	if (tee_alias_region_id < 0) {
		pmp_region_free_atomic(tee_region_id);
		tee_region_id = -1;
		result = SBI_ENOSPC;
		goto out;
	}
#endif

	/* The pool must become inaccessible to the host on every online hart
	 * before the reservation call returns.  A hart executing a TEE grants
	 * itself access locally in context_switch_to() and revokes it on exit. */
	ret = pmp_set_global(tee_region_id, PMP_NO_PERM);
	if (ret) {
		tee_log("[SBI] reserve_mem(): global PMP deny failed, ret=%d\n",
			ret);
		if (tee_alias_region_id >= 0) {
			pmp_region_free_atomic(tee_alias_region_id);
			tee_alias_region_id = -1;
		}
		pmp_region_free_atomic(tee_region_id);
		tee_region_id = -1;
		result = ret;
		goto out;
	}
	if (tee_alias_region_id >= 0) {
		ret = pmp_set_global(tee_alias_region_id, PMP_NO_PERM);
		if (ret) {
			pmp_unset_global(tee_region_id);
			pmp_region_free_atomic(tee_alias_region_id);
			pmp_region_free_atomic(tee_region_id);
			tee_alias_region_id = -1;
			tee_region_id = -1;
			result = ret;
			goto out;
		}
	}
	if (tee_mem_set_core_pmp_region(tee_region_id)) {
		if (tee_alias_region_id >= 0) {
			pmp_unset_global(tee_alias_region_id);
			pmp_region_free_atomic(tee_alias_region_id);
			tee_alias_region_id = -1;
		}
		pmp_unset_global(tee_region_id);
		pmp_region_free_atomic(tee_region_id);
		tee_region_id = -1;
		result = SBI_EFAIL;
		goto out;
	}

	tee_log("[SBI] reserve_mem(): pool ready, region=%d, alias_region=%d, addr=0x%lx, alias=0x%lx, size=0x%lx\n",
		   tee_region_id, tee_alias_region_id,
		   (unsigned long)pmp_region_get_addr(tee_region_id),
		   (unsigned long)alias,
		   (unsigned long)pmp_region_get_size(tee_region_id));
out:
	tee_mem_maintenance_end();
	return result;
}

unsigned long extend_mem(unsigned long base, unsigned long count,
			 unsigned long *extent_id)
{
	unsigned long size;
	uint32_t new_extent_id;
	int pmp_region_id = -1;
	unsigned long result = 0;

	if (!extent_id || !count || count > (~0UL >> PAGE_SHIFT) ||
	    base + (count << PAGE_SHIFT) < base)
		return SBI_EINVAL;
	size = count << PAGE_SHIFT;
	if (tee_mem_maintenance_begin())
		return SBI_EINVALID_STATE;
	if (tee_region_id < 0) {
		result = SBI_EINVALID_STATE;
		goto out;
	}
	if (tee_mem_validate_new_extent(base, size)) {
		result = SBI_EBAD_RANGE;
		goto out;
	}
	/* A host page already visible through a CVM G-stage mapping cannot be
	 * reclassified as trusted allocator memory. REGISTER_PT participates in
	 * the same memory-policy exclusion, so this scan is stable until the new
	 * PMP deny region has been published. */
	if (cvm_hpa_range_is_mapped(base, size)) {
		result = SBI_EBAD_RANGE;
		goto out;
	}
#ifdef ZION_MEGREZ_ACTIVATE
	/* Extent removal currently stores one PMP id.  Refuse a second aliased
	 * range until its companion id is part of the extent metadata. */
	{
		uintptr_t alias;
		if (platform_security_alias(base, size, &alias)) {
			result = SBI_ENOTSUPP;
			goto out;
		}
	}
#endif

	pmp_region_id = teem_init(base, size);
	if (pmp_region_id < 0) {
		result = SBI_ENOSPC;
		goto out;
	}
	if (pmp_set_global(pmp_region_id, PMP_NO_PERM)) {
		pmp_region_free_atomic(pmp_region_id);
		result = SBI_EFAIL;
		goto out;
	}

	/* The host and every other S/U-mode hart are denied before stale
	 * contents are erased or blocks become visible to the allocator. */
	sbi_memset((void *)base, 0, size);
	if (tee_mem_add_extent(base, size, pmp_region_id, &new_extent_id)) {
		pmp_unset_global(pmp_region_id);
		pmp_region_free_atomic(pmp_region_id);
		result = SBI_ENOSPC;
		goto out;
	}

	*extent_id = new_extent_id;
	tee_log("[SM] trusted extent online: id=%u base=0x%lx size=0x%lx pmp=%d\n",
		 new_extent_id, base, size, pmp_region_id);
out:
	tee_mem_maintenance_end();
	return result;
}

unsigned long remove_mem_extent(unsigned long extent_id)
{
	tee_mem_extent_info_t info;
	unsigned long result = 0;
	int ret;

	if (!extent_id || extent_id > ~(uint32_t)0)
		return SBI_EINVAL;
	if (tee_mem_maintenance_begin())
		return SBI_EINVALID_STATE;
	ret = tee_mem_prepare_remove_extent((uint32_t)extent_id, &info);
	if (ret == -2) {
		result = SBI_EINVALID_STATE;
		goto out;
	}
	if (ret) {
		result = SBI_EINVAL;
		goto out;
	}

	/* All mappings/owners are gone at this point. Erase before allowing the
	 * host to regain access, then retire the PMP definition and metadata. */
	sbi_memset((void *)info.base, 0, info.size);
	if (pmp_unset_global(info.pmp_region_id)) {
		tee_mem_cancel_remove_extent((uint32_t)extent_id);
		result = SBI_EFAIL;
		goto out;
	}
	if (pmp_region_free_atomic(info.pmp_region_id)) {
		/* Permissions are already open. Do not retain allocator metadata for
		 * memory which the host can access. */
		tee_mem_finish_remove_extent((uint32_t)extent_id);
		result = SBI_EFAIL;
		goto out;
	}
	tee_mem_finish_remove_extent((uint32_t)extent_id);
	tee_log("[SM] trusted extent removed: id=%lu base=0x%lx size=0x%lx\n",
		 extent_id, (unsigned long)info.base, (unsigned long)info.size);
out:
	tee_mem_maintenance_end();
	return result;
}

unsigned long query_mem_extent(unsigned long extent_id, uintptr_t info_ptr)
{
	tee_mem_extent_info_t info;

	if (!info_ptr || extent_id > ~(uint32_t)0 ||
	    tee_mem_query_extent((uint32_t)extent_id, &info))
		return SBI_EINVAL;
	return copy_from_sm(info_ptr, &info, sizeof(info)) ?
		SBI_EINVALID_ADDR : SBI_OK;
}

unsigned long register_pt(unsigned int tid, struct sbi_register_pt *pt)
{
	unsigned int rtid = hart_get_callee_rtid(tid);
	unsigned long hpa;
	unsigned long ret;

	if (!pt || cvm_get_by_rtid(rtid) != 0)
		return -1;

	if (pt->level > 2 || pt->hfn > (~0UL >> PAGE_SHIFT)) {
		cvm_put(rtid);
		return SBI_EINVAL;
	}

	/* level is initialized by KVM; legacy is_huge/rdonly fields are not. */
	size_t size = PAGE_SIZE << (pt->level * gstage_index_bits);
	hpa = pt->hfn << PAGE_SHIFT;
	/* Keep maintenance from turning this REE mapping into a trusted extent
	 * between the PMP overlap test and publication of the leaf PTE. */
	tee_mem_context_enter_begin();
	tee_mem_context_enter_end();
	if (pmp_detect_region_overlap_atomic(hpa, size))
		ret = SBI_EBAD_RANGE;
	else
		ret = cvm_remap_gpa(rtid, pt->gpa, hpa, size, pt->level,
				    PTE_R | PTE_W | PTE_X);
	tee_mem_context_exit_begin();
	tee_mem_context_exit_end();
	cvm_put(rtid);
	return ret;
}

unsigned long sync_pt(unsigned int tid, unsigned long gpa,
		      unsigned long pt_paddr)
{
	(void)tid;
	(void)gpa;
	(void)pt_paddr;
	/* No production caller builds monitor-owned page tables outside the SM.
	 * Accepting a host-supplied non-leaf pointer would let the REE replace a
	 * trusted G-stage walk with mutable or cross-domain physical memory. */
	return SBI_ENOTSUPP;
}

unsigned long load_mem(unsigned int d_rtid, struct sbi_load_mem *p)
{
	hash_ctx hash_ctx;
	unsigned long ret = -1;

	if (!p || (p->size &&
		   (p->pos + p->size < p->pos ||
		    p->stash + p->size < p->stash)) ||
	    cvm_get_by_rtid(d_rtid) != 0)
		return -1;

	zion_printf(
		"[SM] load_mem(): d_rtid=%x, stash=%lx, pos=%lx, size=%lx\n",
		d_rtid, p->stash, p->pos, p->size);

	hash_init(&hash_ctx);

	// Hash the runtime parameters
	hash_extend(&hash_ctx, p, sizeof(struct sbi_load_mem));

	size_t cursor	= 0;
	while (cursor < p->size) {
		uint64_t gpa = p->pos + cursor;
		size_t load_size = get_load_mem_chunk_size(p, cursor);
		uint64_t block_hpa = 0;

		if (resolve_load_mem_block(d_rtid, gpa, &block_hpa) != 0 ||
		    block_hpa == 0)
			goto out;

		load_size =
			trim_load_mem_chunk_to_block(gpa, &block_hpa, load_size);
		if (copy_load_mem_chunk(block_hpa, p->stash, cursor, load_size) !=
		    0) {
			tee_log(
				"[SBI] !!!ERROR!!! in load_mem(): copy block, stash=%lx, pos=%lx\n",
				p->stash, p->pos);
			goto out;
		}

		cursor += load_size;
	}

	// Finalize the hash
	hash_finalize(cvms[d_rtid].hash, &hash_ctx);
	ret = 0;

out:
	sbi_memset(&hash_ctx, 0, sizeof(hash_ctx));
	cvm_put(d_rtid);
	return ret;
}

int teem_init(uintptr_t start, unsigned long size)
{
	int region = -1;
	int ret = pmp_region_init_atomic(start, size, PMP_PRI_ANY, &region, 0);
	if (ret) {
		tee_log("[SBI] teem_init(): pmp_region_init_atomic() failed, ret=%d\n",
			   ret);
		return -1;
	}

	return region;
}

void tee_metadata_init()
{

	for (size_t i = 0; i < MAX_CVMS; i++) {
		cvms[i].tee_id_next = 0;
		cvms[i].inited	    = false;
		for (size_t j = 0; j < MAX_CVM_VCPUS; j++) {
			cvms[i].vcpus[j].exit_cause = TEE_INIT;
		}
	}
}
