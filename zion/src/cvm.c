#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hfence.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_tlb.h>
#include <sbi/riscv_locks.h>
#include "cvm.h"
#include "context.h"
#include "mprv.h"
#include "tee-mem.h"

struct cvm cvms[MAX_CVMS];
static unsigned long cvms_alloc_bitmap = 0;
static unsigned long ree_tee_alloc_bitmap = 0;
static spinlock_t cvm_table_lock = SPIN_LOCK_INITIALIZER;
static spinlock_t cvm_locks[CVM_NUM];
static spinlock_t cvm_map_locks[CVM_NUM];
static const unsigned long cvm_guest_hstatus_flags =
	HSTATUS_VTW | HSTATUS_SPVP | HSTATUS_SPV;

/* CVM enclave handles are opaque 32-bit generation IDs. Keep eight low bits
 * for the local slot so the first allocation remains compatible with the
 * historical 0..MAX_TEES-1 values. A slot is retired instead of wrapping. */
#define CVM_ENCLAVE_HANDLE_SLOT_BITS 8U
#define CVM_ENCLAVE_HANDLE_SLOT_MASK \
	((1U << CVM_ENCLAVE_HANDLE_SLOT_BITS) - 1U)
#define CVM_ENCLAVE_HANDLE_GENERATION_MAX \
	(~0U >> CVM_ENCLAVE_HANDLE_SLOT_BITS)

#if MAX_TEES > (1U << CVM_ENCLAVE_HANDLE_SLOT_BITS)
#error "MAX_TEES does not fit in a CVM enclave handle"
#endif

static unsigned int cvm_enclave_handle(unsigned int slot,
					unsigned int generation)
{
	return generation << CVM_ENCLAVE_HANDLE_SLOT_BITS | slot;
}

static int cvm_decode_enclave_handle_locked(struct cvm *cvm,
					     unsigned int handle,
					     unsigned int *slot)
{
	unsigned int decoded_slot = handle & CVM_ENCLAVE_HANDLE_SLOT_MASK;
	unsigned int generation = handle >> CVM_ENCLAVE_HANDLE_SLOT_BITS;

	if (!slot || decoded_slot >= MAX_TEES ||
	    cvm->tee_generation[decoded_slot] != generation)
		return -1;
	*slot = decoded_slot;
	return 0;
}

static void reset_cvm_metadata(unsigned int rtid)
{
	if (rtid >= MAX_CVMS)
		return;

	sbi_memset(&cvms[rtid], 0, sizeof(cvms[rtid]));
	cvms[rtid].owner_rtid = (unsigned int)-1;

	for (size_t i = 0; i < MAX_CVM_VCPUS; i++) {
		cvms[rtid].vcpus[i].exit_cause = TEE_INIT;
		cvms[rtid].vcpus[i].running_hart_index = (unsigned int)-1;
	}
}

static bool cvm_rtid_allocated_locked(unsigned int rtid)
{
	return rtid < CVM_NUM && (cvms_alloc_bitmap & (1UL << rtid));
}

static int alloc_cvm_rtid_locked(unsigned int *rtid)
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

static void free_cvm_rtid_locked(unsigned int rtid)
{
	if (rtid < CVM_NUM)
		cvms_alloc_bitmap &= ~(1UL << rtid);
}

static bool ree_tee_allocated_locked(unsigned int tid)
{
	return tid < MAX_TEES && (ree_tee_alloc_bitmap & (1UL << tid));
}

static int alloc_ree_tee_id_locked(unsigned int *tid)
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

static void free_ree_tee_id_locked(unsigned int tid)
{
	if (tid >= MAX_TEES)
		return;

	sbi_memset(&ree.tees[tid], 0, sizeof(ree.tees[tid]));
	ree_tee_alloc_bitmap &= ~(1UL << tid);
}

static bool pte_is_leaf(pte_t pte)
{
	return pte & (PTE_R | PTE_W | PTE_X);
}

static int translate_cvm_gpa_locked(unsigned int rtid, uint64_t gpa,
				    bool write, uint64_t *hpa,
				    size_t *contiguous)
{
	pte_t *pt;

	if (rtid >= CVM_NUM || !hpa || !contiguous)
		return -1;

	pt = (pte_t *)cvms[rtid].pgd;
	if (!pt)
		return -1;

	for (int level = 3; level >= 0; level--) {
		uint64_t mask = level == 3 ? CVM_ROOT_PT_INDEX_MASK :
					       ZION_PTE_INDEX_MASK;
		uint64_t index = (gpa >> (PAGE_SHIFT + level * gstage_index_bits)) &
				 mask;
		pte_t pte = pt[index];

		if (!(pte & PTE_V))
			return -1;

		if (pte_is_leaf(pte)) {
			uint64_t page_size = PAGE_SIZE <<
					     (level * gstage_index_bits);
			uint64_t offset = gpa & (page_size - 1);

			if (!(pte & PTE_R) || (write && !(pte & PTE_W)))
				return -1;

			*hpa = ((pte & ZION_PTE_ADDR_MASK) >>
				ZION_PTE_PPN_SHIFT << PAGE_SHIFT) + offset;
			*contiguous = page_size - offset;
			return 0;
		}

		pt = (pte_t *)(((pte & ZION_PTE_ADDR_MASK) >>
				    ZION_PTE_PPN_SHIFT) << PAGE_SHIFT);
	}

	return -1;
}

int cvm_translate_gpa(unsigned int rtid, uint64_t gpa, bool write,
		      uint64_t *hpa, size_t *contiguous)
{
	int ret;
	size_t owner_contiguous;

	if (rtid >= CVM_NUM)
		return -1;

	spin_lock(&cvm_map_locks[rtid]);
	ret = translate_cvm_gpa_locked(rtid, gpa, write, hpa, contiguous);
	if (!ret) {
		if (!data_block_owned_range(&g_mem_pool.data_pool, *hpa,
					    DATA_BLOCK_CVM_OWNER(rtid),
					    &owner_contiguous)) {
			ret = -1;
		} else if (*contiguous > owner_contiguous) {
			*contiguous = owner_contiguous;
		}
	}
	spin_unlock(&cvm_map_locks[rtid]);

	return ret;
}

int cvm_copy_from_gpa(unsigned int rtid, void *dest, uint64_t src_gpa,
		      size_t size)
{
	uint8_t *cursor = dest;

	if (!dest && size)
		return -1;

	while (size) {
		uint64_t hpa;
		size_t contiguous;
		size_t chunk;

		if (cvm_translate_gpa(rtid, src_gpa, false, &hpa,
				      &contiguous))
			return -1;
		chunk = size < contiguous ? size : contiguous;
		sbi_memcpy(cursor, (void *)hpa, chunk);
		cursor += chunk;
		src_gpa += chunk;
		size -= chunk;
	}

	return 0;
}

int cvm_zero_gpa(unsigned int rtid, uint64_t gpa, size_t size)
{
	while (size) {
		uint64_t hpa;
		size_t contiguous;
		size_t chunk;

		if (cvm_translate_gpa(rtid, gpa, true, &hpa, &contiguous))
			return -1;
		chunk = size < contiguous ? size : contiguous;
		sbi_memset((void *)hpa, 0, chunk);
		gpa += chunk;
		size -= chunk;
	}

	return 0;
}

int cvm_register_enclave(unsigned int rtid, unsigned int eid,
			 unsigned int *handle)
{
	if (rtid >= CVM_NUM || !handle)
		return -1;

	spin_lock(&cvm_table_lock);
	spin_lock(&cvm_locks[rtid]);
	if (!cvm_rtid_allocated_locked(rtid) ||
	    cvms[rtid].lifecycle != CVM_LIFECYCLE_READY)
		goto fail;

	for (unsigned int i = 0; i < MAX_TEES; i++) {
		if ((cvms[rtid].tee_alloc_bitmap & (1UL << i)) ||
		    (cvms[rtid].tee_retired_bitmap & (1UL << i)))
			continue;

		cvms[rtid].tee_alloc_bitmap |= 1UL << i;
		cvms[rtid].tees[i].id = eid;
		cvms[rtid].tees[i].mode = ENCLAVE;
		cvms[rtid].tee_id_next++;
		*handle = cvm_enclave_handle(i,
					       cvms[rtid].tee_generation[i]);
		spin_unlock(&cvm_locks[rtid]);
		spin_unlock(&cvm_table_lock);
		return 0;
	}

fail:
	spin_unlock(&cvm_locks[rtid]);
	spin_unlock(&cvm_table_lock);
	return -1;
}

int cvm_resolve_enclave(unsigned int rtid, unsigned int handle,
			unsigned int *eid)
{
	unsigned int slot;

	if (rtid >= CVM_NUM || !eid)
		return -1;

	spin_lock(&cvm_table_lock);
	spin_lock(&cvm_locks[rtid]);
	if (cvm_decode_enclave_handle_locked(&cvms[rtid], handle, &slot) ||
	    !cvm_rtid_allocated_locked(rtid) ||
	    cvms[rtid].lifecycle != CVM_LIFECYCLE_READY ||
	    !(cvms[rtid].tee_alloc_bitmap & (1UL << slot)) ||
	    (cvms[rtid].tee_destroy_bitmap & (1UL << slot)) ||
	    cvms[rtid].tees[slot].mode != ENCLAVE) {
		spin_unlock(&cvm_locks[rtid]);
		spin_unlock(&cvm_table_lock);
		return -1;
	}
	*eid = cvms[rtid].tees[slot].id;
	spin_unlock(&cvm_locks[rtid]);
	spin_unlock(&cvm_table_lock);
	return 0;
}

int cvm_begin_enclave_destroy(unsigned int rtid, unsigned int handle,
			      unsigned int *eid)
{
	unsigned int slot;

	if (rtid >= CVM_NUM || !eid)
		return -1;

	spin_lock(&cvm_table_lock);
	spin_lock(&cvm_locks[rtid]);
	if (cvm_decode_enclave_handle_locked(&cvms[rtid], handle, &slot) ||
	    !cvm_rtid_allocated_locked(rtid) ||
	    cvms[rtid].lifecycle != CVM_LIFECYCLE_READY ||
	    !(cvms[rtid].tee_alloc_bitmap & (1UL << slot)) ||
	    (cvms[rtid].tee_destroy_bitmap & (1UL << slot)) ||
	    cvms[rtid].tees[slot].mode != ENCLAVE) {
		spin_unlock(&cvm_locks[rtid]);
		spin_unlock(&cvm_table_lock);
		return -1;
	}
	*eid = cvms[rtid].tees[slot].id;
	cvms[rtid].tee_destroy_bitmap |= 1UL << slot;
	spin_unlock(&cvm_locks[rtid]);
	spin_unlock(&cvm_table_lock);
	return 0;
}

void cvm_cancel_enclave_destroy(unsigned int rtid, unsigned int handle,
				unsigned int eid)
{
	unsigned int slot;

	if (rtid >= CVM_NUM)
		return;

	spin_lock(&cvm_table_lock);
	spin_lock(&cvm_locks[rtid]);
	if (!cvm_decode_enclave_handle_locked(&cvms[rtid], handle, &slot) &&
	    cvm_rtid_allocated_locked(rtid) &&
	    (cvms[rtid].tee_alloc_bitmap & (1UL << slot)) &&
	    (cvms[rtid].tee_destroy_bitmap & (1UL << slot)) &&
	    cvms[rtid].tees[slot].mode == ENCLAVE &&
	    cvms[rtid].tees[slot].id == eid)
		cvms[rtid].tee_destroy_bitmap &= ~(1UL << slot);
	spin_unlock(&cvm_locks[rtid]);
	spin_unlock(&cvm_table_lock);
}

int cvm_finish_enclave_destroy(unsigned int rtid, unsigned int handle,
			       unsigned int eid)
{
	unsigned int slot;

	if (rtid >= CVM_NUM)
		return -1;

	spin_lock(&cvm_table_lock);
	spin_lock(&cvm_locks[rtid]);
	if (cvm_decode_enclave_handle_locked(&cvms[rtid], handle, &slot) ||
	    !cvm_rtid_allocated_locked(rtid) ||
	    !(cvms[rtid].tee_alloc_bitmap & (1UL << slot)) ||
	    !(cvms[rtid].tee_destroy_bitmap & (1UL << slot)) ||
	    cvms[rtid].tees[slot].mode != ENCLAVE ||
	    cvms[rtid].tees[slot].id != eid) {
		spin_unlock(&cvm_locks[rtid]);
		spin_unlock(&cvm_table_lock);
		return -1;
	}
	sbi_memset(&cvms[rtid].tees[slot], 0, sizeof(cvms[rtid].tees[slot]));
	cvms[rtid].tee_alloc_bitmap &= ~(1UL << slot);
	cvms[rtid].tee_destroy_bitmap &= ~(1UL << slot);
	if (cvms[rtid].tee_generation[slot] ==
	    CVM_ENCLAVE_HANDLE_GENERATION_MAX)
		cvms[rtid].tee_retired_bitmap |= 1UL << slot;
	else
		cvms[rtid].tee_generation[slot]++;
	if (cvms[rtid].tee_id_next)
		cvms[rtid].tee_id_next--;
	spin_unlock(&cvm_locks[rtid]);
	spin_unlock(&cvm_table_lock);
	return 0;
}

static int cvm_tid_to_rtid_locked(unsigned int tid, unsigned int *rtid)
{
	if (!rtid || !ree_tee_allocated_locked(tid) ||
	    ree.tees[tid].mode != CVM)
		return -1;

	*rtid = ree.tees[tid].id;
	if (!cvm_rtid_allocated_locked(*rtid))
		return -1;

	return 0;
}

int cvm_get_by_tid(unsigned int tid, unsigned int *rtid)
{
	unsigned int resolved_rtid;
	if (!rtid)
		return -1;

	spin_lock(&cvm_table_lock);
	if (cvm_tid_to_rtid_locked(tid, &resolved_rtid) != 0) {
		spin_unlock(&cvm_table_lock);
		return -1;
	}

	spin_lock(&cvm_locks[resolved_rtid]);
	if (cvms[resolved_rtid].lifecycle != CVM_LIFECYCLE_READY) {
		spin_unlock(&cvm_locks[resolved_rtid]);
		spin_unlock(&cvm_table_lock);
		return -1;
	}
	cvms[resolved_rtid].active_ops++;
	spin_unlock(&cvm_locks[resolved_rtid]);
	spin_unlock(&cvm_table_lock);

	*rtid = resolved_rtid;
	return 0;
}

int cvm_get_by_rtid(unsigned int rtid)
{
	if (rtid >= CVM_NUM)
		return -1;

	spin_lock(&cvm_table_lock);
	if (!cvm_rtid_allocated_locked(rtid)) {
		spin_unlock(&cvm_table_lock);
		return -1;
	}

	spin_lock(&cvm_locks[rtid]);
	if (cvms[rtid].lifecycle != CVM_LIFECYCLE_READY) {
		spin_unlock(&cvm_locks[rtid]);
		spin_unlock(&cvm_table_lock);
		return -1;
	}
	cvms[rtid].active_ops++;
	spin_unlock(&cvm_locks[rtid]);
	spin_unlock(&cvm_table_lock);

	return 0;
}

void cvm_put(unsigned int rtid)
{
	if (rtid >= CVM_NUM)
		return;

	spin_lock(&cvm_locks[rtid]);
	if (cvms[rtid].active_ops)
		cvms[rtid].active_ops--;
	spin_unlock(&cvm_locks[rtid]);
}

static int cvm_hfence_active_harts(unsigned int rtid, unsigned long start,
				   unsigned long size)
{
	struct sbi_hartmask targets;
	unsigned long vmid;
	u32 hart_index;
	int ret = 0;

	if (rtid >= CVM_NUM)
		return -1;

	spin_lock(&cvm_locks[rtid]);
	targets = cvms[rtid].active_harts;
	vmid = (cvms[rtid].hgatp & HGATP_VMID_MASK) >> HGATP_VMID_SHIFT;
	spin_unlock(&cvm_locks[rtid]);

	sbi_hartmask_for_each_hartindex(hart_index, &targets) {
		struct sbi_tlb_info tlb_info;
		u32 hartid = sbi_hartindex_to_hartid(hart_index);

		SBI_TLB_INFO_INIT(&tlb_info, start, size, 0, vmid,
				  SBI_TLB_HFENCE_GVMA_VMID, current_hartid());
		ret = sbi_tlb_request(1UL, hartid, &tlb_info);
		if (ret)
			return ret;
		if (hartid != current_hartid())
			zion_printf(
				"[SM] remote G-stage fence: rtid=%u vmid=%lu hart=%u\n",
				rtid, vmid, hartid);
	}

	return 0;
}

int cvm_map_gpa(unsigned int rtid, uint64_t gpa, uint64_t hpa,
		size_t size, int target_level, uint64_t permissions)
{
	int ret;

	if (rtid >= CVM_NUM)
		return -1;

	spin_lock(&cvm_map_locks[rtid]);
	ret = map_gpa_to_hpa(&g_mem_pool, rtid, gpa, hpa, size,
			     target_level, permissions);
	spin_unlock(&cvm_map_locks[rtid]);
	if (ret)
		return ret;

	return cvm_hfence_active_harts(rtid, gpa, size);
}

int cvm_remap_gpa(unsigned int rtid, uint64_t gpa, uint64_t hpa,
		  size_t size, int target_level, uint64_t permissions)
{
	int ret;

	if (rtid >= CVM_NUM)
		return -1;

	spin_lock(&cvm_map_locks[rtid]);
	ret = remap_gpa_to_hpa(&g_mem_pool, rtid, gpa, hpa, size,
			       target_level, permissions);
	spin_unlock(&cvm_map_locks[rtid]);
	if (ret)
		return ret;

	return cvm_hfence_active_harts(rtid, gpa, size);
}

static bool cvm_pt_page_is_private(unsigned int rtid, uint64_t address)
{
	if (rtid >= CVM_NUM || address & (PAGE_SIZE - 1))
		return false;
	return cvm_pt_page_owned_by(&g_mem_pool, rtid, address);
}

static bool cvm_pt_overlaps_hpa_locked(unsigned int rtid, pte_t *pt,
				       int level, uint64_t start,
				       uint64_t end, bool root)
{
	size_t entries = root ? 1UL << CVM_ROOT_PT_INDEX_BITS :
				1UL << gstage_index_bits;

	for (size_t i = 0; i < entries; i++) {
		pte_t pte = pt[i];
		uint64_t mapped_start;
		uint64_t mapped_end;

		if (!(pte & PTE_V))
			continue;
		mapped_start = ((pte & ZION_PTE_ADDR_MASK) >>
				ZION_PTE_PPN_SHIFT) << PAGE_SHIFT;
		if (pte_is_leaf(pte)) {
			uint64_t mapped_size = PAGE_SIZE <<
					       (level * gstage_index_bits);

			mapped_end = mapped_start + mapped_size;
			if (mapped_end < mapped_start ||
			    (mapped_start < end && start < mapped_end))
				return true;
			continue;
		}

		/* Only monitor-owned page-table pages may be followed. Treat a
		 * malformed non-leaf as conflicting with every candidate extent. */
		if (!level || !cvm_pt_page_is_private(rtid, mapped_start) ||
		    cvm_pt_overlaps_hpa_locked(rtid, (pte_t *)mapped_start,
					       level - 1, start, end, false))
			return true;
	}
	return false;
}

bool cvm_hpa_range_is_mapped(uint64_t hpa, size_t size)
{
	uint64_t end;

	if (!size || hpa + size < hpa)
		return true;
	end = hpa + size;
	for (unsigned int rtid = 0; rtid < CVM_NUM; rtid++) {
		pte_t *root_pt;
		bool overlap = false;

		spin_lock(&cvm_map_locks[rtid]);
		root_pt = (pte_t *)cvms[rtid].pgd;
		if (root_pt)
			overlap = cvm_pt_overlaps_hpa_locked(rtid, root_pt, 3,
						    hpa, end, true);
		spin_unlock(&cvm_map_locks[rtid]);
		if (overlap)
			return true;
	}
	return false;
}

int cvm_resolve_private_block(unsigned int rtid, uint64_t gpa,
			      uint64_t *block_hpa, bool *created)
{
	pte_t *root_pt;
	pte_t *pte;
	uint64_t hpa;
	uint64_t block_gpa;
	int ret = 0;

	if (rtid >= CVM_NUM || !block_hpa)
		return -1;
	block_gpa = gpa & ~(BLOCK_SIZE - 1);

	spin_lock(&cvm_map_locks[rtid]);
	root_pt = (pte_t *)get_cvm_root_pt(&g_mem_pool, rtid);
	if (!root_pt) {
		spin_unlock(&cvm_map_locks[rtid]);
		return -1;
	}
	pte = get_pte_entry(NULL, root_pt, block_gpa, false, 0, 1,
			    get_cvm_pt_mode(&g_mem_pool, rtid));
	if (pte && (*pte & PTE_V)) {
		size_t owner_contiguous;

		hpa = ((*pte & ZION_PTE_ADDR_MASK) >>
		       ZION_PTE_PPN_SHIFT) << PAGE_SHIFT;
		if (!pte_is_leaf(*pte) || !(*pte & PTE_W) ||
		    (hpa & (BLOCK_SIZE - 1)) ||
		    !data_block_owned_range(&g_mem_pool.data_pool, hpa,
					    DATA_BLOCK_CVM_OWNER(rtid),
					    &owner_contiguous) ||
		    owner_contiguous < BLOCK_SIZE) {
			spin_unlock(&cvm_map_locks[rtid]);
			return -1;
		}
		*block_hpa = hpa;
		if (created)
			*created = false;
		spin_unlock(&cvm_map_locks[rtid]);
		return 0;
	}

	hpa = alloc_data_block(&g_mem_pool.data_pool,
			       DATA_BLOCK_CVM_OWNER(rtid));
	if (hpa == (uint64_t)-1 ||
	    map_gpa_to_hpa(&g_mem_pool, rtid, block_gpa, hpa, BLOCK_SIZE,
			   1, PTE_R | PTE_W | PTE_X)) {
		ret = -1;
	} else {
		*block_hpa = hpa;
		if (created)
			*created = true;
	}
	spin_unlock(&cvm_map_locks[rtid]);

	if (ret)
		return ret;
	return cvm_hfence_active_harts(rtid, block_gpa, BLOCK_SIZE);
}

int cvm_set_pt_mode(unsigned int rtid, uint8_t mode)
{
	if (rtid >= CVM_NUM)
		return -1;

	spin_lock(&cvm_map_locks[rtid]);
	set_cvm_pt_mode(&g_mem_pool, rtid, mode);
	spin_unlock(&cvm_map_locks[rtid]);
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
	guest_csrs->hgatp = hgatp;
}

unsigned long create_cvm(struct sbi_trap_regs *regs, unsigned int *_tid)
{
	unsigned int rtid;
	unsigned int tid;
	struct tee *tee;
	unsigned long pgd;
	unsigned long hgatp;

	(void)regs;
	if (!_tid)
		return -1;

	spin_lock(&cvm_table_lock);
	if (alloc_ree_tee_id_locked(&tid) != 0) {
		spin_unlock(&cvm_table_lock);
		return -1;
	}

	if (alloc_cvm_rtid_locked(&rtid) != 0) {
		free_ree_tee_id_locked(tid);
		spin_unlock(&cvm_table_lock);
		return -1;
	}

	reset_cvm_metadata(rtid);
	cvms[rtid].lifecycle = CVM_LIFECYCLE_INITIALIZING;
	tee = &ree.tees[tid];
	tee->id = rtid;
	tee->mode = CVM;
	spin_unlock(&cvm_table_lock);

	spin_lock(&cvm_map_locks[rtid]);
	reset_cvm_pt_pool(&g_mem_pool, rtid);
	pgd = (unsigned long)alloc_cvm_root_pt(&g_mem_pool, rtid);
	spin_unlock(&cvm_map_locks[rtid]);
	if (!pgd) {
		goto fail;
	}

	hgatp = GSTAGE_MODE;

	/* VMID zero is reserved for non-Zion/host contexts. */
	hgatp |= ((unsigned long)(rtid + 1) << HGATP_VMID_SHIFT) &
		 HGATP_VMID_MASK;
	hgatp |= (pgd >> PAGE_SHIFT) & HGATP_PPN;

	zion_printf("[SM] create_cvm(): hgatp=%lx, pgd=%lx\n", hgatp, pgd);

	cvms[rtid].hgatp = hgatp;
	cvms[rtid].pgd	 = pgd;

	cvms[rtid].owner_rtid = (unsigned int)-1;

	spin_lock(&cvm_table_lock);
	spin_lock(&cvm_locks[rtid]);
	if (cvms[rtid].lifecycle != CVM_LIFECYCLE_INITIALIZING) {
		spin_unlock(&cvm_locks[rtid]);
		spin_unlock(&cvm_table_lock);
		goto fail;
	}
	cvms[rtid].lifecycle = CVM_LIFECYCLE_READY;
	spin_unlock(&cvm_locks[rtid]);
	spin_unlock(&cvm_table_lock);

	*_tid = tid;

	zion_printf("[SBI] create_cvm(): pgd=%lx, tid=%u, rtid=%u\n", pgd, tid,
		   rtid);

	return 0;

fail:
	spin_lock(&cvm_map_locks[rtid]);
	reset_cvm_pt_pool(&g_mem_pool, rtid);
	spin_unlock(&cvm_map_locks[rtid]);
	spin_lock(&cvm_table_lock);
	spin_lock(&cvm_locks[rtid]);
	reset_cvm_metadata(rtid);
	free_cvm_rtid_locked(rtid);
	free_ree_tee_id_locked(tid);
	spin_unlock(&cvm_locks[rtid]);
	spin_unlock(&cvm_table_lock);
	return -1;
}

unsigned long init_cvm_vcpu(struct sbi_trap_regs *regs, unsigned int tid,
			    unsigned int *_ttid,
			    struct kvm_vcpu_channel *_shared_mem)
{
	unsigned int rtid, ttid;
	struct tee_thread *tthread;
	struct cvm_vcpu *vcpu;
	int illegal;

	(void)regs;
	if (!_ttid || !_shared_mem || cvm_get_by_tid(tid, &rtid) != 0)
		return -1;

	spin_lock(&cvm_locks[rtid]);
	for (ttid = 0; ttid < MAX_CVM_VCPUS; ttid++) {
		if (cvms[rtid].vcpus[ttid].lifecycle == CVM_VCPU_FREE)
			break;
	}
	if (ttid >= MAX_CVM_VCPUS) {
		spin_unlock(&cvm_locks[rtid]);
		cvm_put(rtid);
		return -1;
	}
	vcpu = &cvms[rtid].vcpus[ttid];
	sbi_memset(vcpu, 0, sizeof(*vcpu));
	vcpu->exit_cause = TEE_INIT;
	vcpu->running_hart_index = (unsigned int)-1;
	vcpu->lifecycle = CVM_VCPU_INITIALIZING;
	spin_unlock(&cvm_locks[rtid]);

	tthread = tee_thread_alloc();
	if (!tthread)
		goto fail_vcpu;
	tthread->master		   = (void *)vcpu;

	save_tthread_state(&tthread->state, rtid, ttid, tthread, CVM);
	tthread->prev_state = NULL;
	vcpu->tthread	    = tthread;

	illegal = copy_to_sm((void *)&vcpu->channel, (uintptr_t)_shared_mem,
			     sizeof(struct kvm_vcpu_channel));
	if (illegal) {
		tee_log(
			"[SBI] !!!ERROR!!! in tvm_vcpu_init(): copy_to_sm()\n");
		goto fail_thread;
	}

	zion_printf(
		"[SBI] tvm_vcpu_init(): guest_context=%lx, guest_csr=%lx, extra_trap=%lx\n",
		(unsigned long)vcpu->channel.guest_context,
		(unsigned long)vcpu->channel.guest_csr,
		(unsigned long)vcpu->channel.extra_trap);

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

	spin_lock(&cvm_locks[rtid]);
	vcpu->lifecycle = CVM_VCPU_READY;
	cvms[rtid].ttid_next++;
	spin_unlock(&cvm_locks[rtid]);
	*_ttid = ttid;
	cvm_put(rtid);

	tee_log("[SM] CVM vcpu: tid=%u, rtid=%u, ttid=%u\n",
		   tid, rtid, ttid);
	return 0;

fail_thread:
	vcpu->tthread = NULL;
	tee_thread_free(tthread);
fail_vcpu:
	spin_lock(&cvm_locks[rtid]);
	sbi_memset(vcpu, 0, sizeof(*vcpu));
	spin_unlock(&cvm_locks[rtid]);
	cvm_put(rtid);
	return -1;
}

unsigned long enter_cvm(struct sbi_trap_regs *regs, unsigned int tid,
			unsigned int ttid)
{
	unsigned int rtid;
	unsigned int hart_index;
	struct cvm_vcpu *vcpu;
	struct tee_thread *tthread;

	if (hart_get_mode() != REE || cvm_get_by_tid(tid, &rtid) != 0)
		return -1;

	spin_lock(&cvm_locks[rtid]);
	if (ttid >= MAX_CVM_VCPUS ||
	    cvms[rtid].vcpus[ttid].lifecycle != CVM_VCPU_READY ||
	    !cvms[rtid].vcpus[ttid].tthread) {
		spin_unlock(&cvm_locks[rtid]);
		cvm_put(rtid);
		return -1;
	}
	vcpu = &cvms[rtid].vcpus[ttid];
	hart_index = zion_current_hart_index();
	if (sbi_hartmask_test_hartindex(hart_index,
					&cvms[rtid].active_harts)) {
		spin_unlock(&cvm_locks[rtid]);
		cvm_put(rtid);
		return -1;
	}
	vcpu->lifecycle = CVM_VCPU_RUNNING;
	vcpu->running_hart_index = hart_index;
	cvms[rtid].active_vcpus++;
	sbi_hartmask_set_hartindex(hart_index, &cvms[rtid].active_harts);
	tthread = vcpu->tthread;
	spin_unlock(&cvm_locks[rtid]);
	cvm_put(rtid);

	context_switch_to(regs, ree.harts[zion_current_hart_index()].tthread,
			  tthread, REE_TO_CVM, vcpu->exit_cause,
			  &vcpu->exit_mmio_reg, &vcpu->channel);

	return 0;
}
unsigned long exit_cvm(struct sbi_trap_regs *regs, unsigned int rtid,
		       unsigned int ttid, tee_quit_cause exit_cause,
		       struct sbi_trap_info *trap,
		       struct cvm_extra_trap_info *extra_trap)
{
	struct tee_thread *s_tthread, *d_tthread;

	(void)trap;
	if (rtid >= CVM_NUM || hart_get_mode() != CVM ||
	    hart_get_caller_rtid() != rtid ||
	    hart_get_caller_ttid() != ttid)
		return -1;

	spin_lock(&cvm_locks[rtid]);
	if (cvms[rtid].lifecycle != CVM_LIFECYCLE_READY ||
	    ttid >= MAX_CVM_VCPUS ||
	    cvms[rtid].vcpus[ttid].lifecycle != CVM_VCPU_RUNNING ||
	    cvms[rtid].vcpus[ttid].running_hart_index !=
		zion_current_hart_index() ||
	    !cvms[rtid].vcpus[ttid].tthread) {
		spin_unlock(&cvm_locks[rtid]);
		return -1;
	}
	struct cvm_vcpu *vcpu = &cvms[rtid].vcpus[ttid];
	vcpu->exit_cause      = exit_cause;

	s_tthread = vcpu->tthread;
	d_tthread = s_tthread->prev_state->tthread;
	spin_unlock(&cvm_locks[rtid]);

	context_switch_from(regs, s_tthread, d_tthread, REE_FROM_CVM,
			    vcpu->exit_cause, &vcpu->exit_mmio_reg, extra_trap,
			    &vcpu->channel, 1);

	spin_lock(&cvm_locks[rtid]);
	vcpu->lifecycle = CVM_VCPU_READY;
	sbi_hartmask_clear_hartindex(vcpu->running_hart_index,
				     &cvms[rtid].active_harts);
	vcpu->running_hart_index = (unsigned int)-1;
	if (cvms[rtid].active_vcpus)
		cvms[rtid].active_vcpus--;
	spin_unlock(&cvm_locks[rtid]);

	return 0;
}

unsigned long destroy_cvm(unsigned int tid)
{
	unsigned int rtid;

	spin_lock(&cvm_table_lock);
	if (cvm_tid_to_rtid_locked(tid, &rtid) != 0) {
		spin_unlock(&cvm_table_lock);
		return -1;
	}

	spin_lock(&cvm_locks[rtid]);
	if (cvms[rtid].lifecycle != CVM_LIFECYCLE_READY ||
	    cvms[rtid].active_ops || cvms[rtid].active_vcpus ||
	    cvms[rtid].tee_alloc_bitmap) {
		spin_unlock(&cvm_locks[rtid]);
		spin_unlock(&cvm_table_lock);
		return -1;
	}
	cvms[rtid].lifecycle = CVM_LIFECYCLE_DESTROYING;
	spin_unlock(&cvm_locks[rtid]);
	spin_unlock(&cvm_table_lock);

	zion_printf("[SM] Destroy CVM: tid=%u, rtid=%u\n", tid, rtid);

	free_cvm_vcpu_threads(rtid);
	free_data_blocks_per_owner(&g_mem_pool.data_pool,
				   DATA_BLOCK_CVM_OWNER(rtid));
	spin_lock(&cvm_map_locks[rtid]);
	reset_cvm_pt_pool(&g_mem_pool, rtid);
	spin_unlock(&cvm_map_locks[rtid]);
	__sbi_hfence_gvma_all();

	spin_lock(&cvm_table_lock);
	spin_lock(&cvm_locks[rtid]);
	reset_cvm_metadata(rtid);
	free_cvm_rtid_locked(rtid);
	free_ree_tee_id_locked(tid);
	spin_unlock(&cvm_locks[rtid]);
	spin_unlock(&cvm_table_lock);
	return 0;
}

int set_cvm_mem_info(unsigned int tid, struct cvm_mem_info *mem_info)
{
	unsigned int rtid;

	if (!mem_info || cvm_get_by_tid(tid, &rtid) != 0)
		return -1;

	spin_lock(&cvm_locks[rtid]);
	struct cvm_mem_info *dest = &cvms[rtid].mem_info;

	*dest = *mem_info;
	spin_unlock(&cvm_locks[rtid]);

	tee_log("[SM] CVM mem: tid=%u, slot=%u, gpa=0x%lx, size=0x%lx, private=%u\n",
		   tid, dest->slot, dest->guest_phys_addr, dest->memory_size,
		   dest->private);
	cvm_put(rtid);
	return 0;
}
