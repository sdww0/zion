
#include "tee-mem.h"
#include "zion.h"
#include "tee.h"
#include "sm.h"
#include "sbi/riscv_encoding.h"
#include "sbi/sbi_hfence.h"
#include TARGET_PLATFORM_HEADER

mem_pool_t g_mem_pool;
static data_block_t data_blocks_arr[MAX_DATA_BLOCKS];
static spinlock_t pt_pool_lock = SPIN_LOCK_INITIALIZER;
static spinlock_t data_pool_lock = SPIN_LOCK_INITIALIZER;
static spinlock_t memory_policy_lock = SPIN_LOCK_INITIALIZER;
static unsigned int active_tee_contexts;
extern struct tee_thread tee_threads[MAX_TEE_THREADS];

// Return the current number of free blocks.
static inline int get_free_data_block_count(data_pool_t *dp)
{
	return dp->free_count;
}

// Return the current number of allocated blocks.
static inline int get_allocated_data_block_count(data_pool_t *dp)
{
	return dp->total_count - dp->free_count;
}

static inline void tee_mem_status(data_pool_t *dp)
{
#ifdef DEBUG
	// Gather data-pool statistics for logging.
	int free_blocks		= get_free_data_block_count(dp);
	int allocated_blocks	= get_allocated_data_block_count(dp);

	// zion_printf("[SM] Data Pool -- Free blocks: %d, Allocated blocks: %d\n",
	// 	    free_blocks, allocated_blocks);
	(void)free_blocks;
	(void)allocated_blocks;
#else
	(void)dp;
#endif
}

static int pt_owner_from_combined_id(int cvm_id)
{
	if (cvm_id >= 0 && cvm_id < CVM_NUM)
		return cvm_id;
	if (cvm_id >= CVM_NUM && cvm_id < CVM_NUM + MAX_ENCLAVES)
		return cvm_id;
	return -1;
}

static int pt_owner_from_enclave_id(uint32_t enclave_id)
{
	if (enclave_id >= MAX_ENCLAVES)
		return -1;
	return CVM_NUM + enclave_id;
}

// Initialize the shared page-table pool.
static void init_pt_pool(pt_pool_t *pt_pool, uint8_t *base, size_t total_size)
{
	size_t total_pages = total_size / PAGE_SIZE;
	size_t root_pages = PT_OWNER_COUNT * ROOT_PT_PAGES;

	pt_pool->base = base;
	pt_pool->total_size = total_size;
	pt_pool->total_pages = total_pages > PT_POOL_MAX_PAGES ?
			       PT_POOL_MAX_PAGES : total_pages;
	pt_pool->mid_start_page = root_pages;

	for (size_t i = 0; i < PT_POOL_MAX_PAGES; i++)
		pt_pool->page_owner[i] = PT_OWNER_INVALID;
	for (size_t owner = 0; owner < PT_OWNER_COUNT; owner++) {
		pt_pool->roots[owner].base =
			base + owner * ROOT_PT_PAGES * PAGE_SIZE;
		pt_pool->roots[owner].pt_mode = CVM_GSTAGE_MODE;
		pt_pool->roots[owner].in_use = false;
	}
}

static void *alloc_pt_root(mem_pool_t *mp, uint32_t owner, uint8_t mode)
{
	pt_root_slot_t *root;
	void *base;

	if (!mp || owner >= PT_OWNER_COUNT)
		return NULL;

	spin_lock(&pt_pool_lock);
	root = &mp->pt_pool.roots[owner];
	base = root->base;
	if (!base ||
	    owner * ROOT_PT_PAGES + ROOT_PT_PAGES > mp->pt_pool.mid_start_page ||
	    owner * ROOT_PT_PAGES + ROOT_PT_PAGES > mp->pt_pool.total_pages) {
		spin_unlock(&pt_pool_lock);
		return NULL;
	}
	if (!root->in_use)
		sbi_memset(base, 0, ROOT_PT_PAGES * PAGE_SIZE);
	root->pt_mode = mode;
	root->in_use = true;
	spin_unlock(&pt_pool_lock);
	return base;
}

static void reset_pt_owner(mem_pool_t *mp, uint32_t owner)
{
	if (!mp || owner >= PT_OWNER_COUNT)
		return;

	spin_lock(&pt_pool_lock);
	if (mp->pt_pool.roots[owner].base) {
		sbi_memset(mp->pt_pool.roots[owner].base, 0,
			   ROOT_PT_PAGES * PAGE_SIZE);
		mp->pt_pool.roots[owner].pt_mode = CVM_GSTAGE_MODE;
		mp->pt_pool.roots[owner].in_use = false;
	}
	for (size_t i = mp->pt_pool.mid_start_page;
	     i < mp->pt_pool.total_pages; i++) {
		if (mp->pt_pool.page_owner[i] == owner) {
			sbi_memset(mp->pt_pool.base + i * PAGE_SIZE, 0,
				   PAGE_SIZE);
			mp->pt_pool.page_owner[i] = PT_OWNER_INVALID;
		}
	}
	spin_unlock(&pt_pool_lock);
}

// Allocate one 4KB intermediate page from the shared page-table pool.
static void *alloc_pt_page(mem_pool_t *mp, uint32_t owner)
{
	if (!mp || owner >= PT_OWNER_COUNT)
		return NULL;

	spin_lock(&pt_pool_lock);
	for (size_t i = mp->pt_pool.mid_start_page;
	     i < mp->pt_pool.total_pages; i++) {
		if (mp->pt_pool.page_owner[i] == PT_OWNER_INVALID) {
			void *page = mp->pt_pool.base + i * PAGE_SIZE;

			mp->pt_pool.page_owner[i] = owner;
			sbi_memset(page, 0, PAGE_SIZE);
			spin_unlock(&pt_pool_lock);
			return page;
		}
	}
	spin_unlock(&pt_pool_lock);
	return NULL;
}

// Return the root page-table address for the selected CVM.
void *get_cvm_root_pt(mem_pool_t *mp, uint32_t cvm_id)
{
	if (!mp || cvm_id >= CVM_NUM ||
	    !mp->pt_pool.roots[cvm_id].in_use)
		return NULL;
	return mp->pt_pool.roots[cvm_id].base;
}

void *alloc_cvm_root_pt(mem_pool_t *mp, uint32_t cvm_id)
{
	if (cvm_id >= CVM_NUM)
		return NULL;
	return alloc_pt_root(mp, cvm_id, CVM_GSTAGE_MODE);
}

uint8_t get_cvm_pt_mode(mem_pool_t *mp, uint32_t cvm_id)
{
	if (cvm_id >= CVM_NUM)
		return CVM_GSTAGE_MODE;
	return mp->pt_pool.roots[cvm_id].pt_mode;
}

void set_cvm_pt_mode(mem_pool_t *mp, uint32_t cvm_id, uint8_t mode)
{
	if (cvm_id >= CVM_NUM)
		return;
	mp->pt_pool.roots[cvm_id].pt_mode = mode;
}

void reset_cvm_pt_pool(mem_pool_t *mp, uint32_t cvm_id)
{
	if (!mp || cvm_id >= CVM_NUM)
		return;
	reset_pt_owner(mp, cvm_id);
}

bool cvm_pt_page_owned_by(mem_pool_t *mp, uint32_t cvm_id, uint64_t address)
{
	bool owned = false;
	uint64_t base;
	size_t page_index;

	if (!mp || cvm_id >= CVM_NUM || address & (PAGE_SIZE - 1))
		return false;

	spin_lock(&pt_pool_lock);
	base = (uint64_t)mp->pt_pool.base;
	if (base && address >= base &&
	    address < base + mp->pt_pool.total_pages * PAGE_SIZE) {
		page_index = (address - base) / PAGE_SIZE;
		if (page_index < mp->pt_pool.mid_start_page) {
			uint64_t root_start =
				(uint64_t)mp->pt_pool.roots[cvm_id].base;
			uint64_t root_end =
				root_start + ROOT_PT_PAGES * PAGE_SIZE;

			owned = mp->pt_pool.roots[cvm_id].in_use &&
				address >= root_start && address < root_end;
		} else if (page_index < mp->pt_pool.total_pages) {
			owned = mp->pt_pool.page_owner[page_index] == cvm_id;
		}
	}
	spin_unlock(&pt_pool_lock);
	return owned;
}

/* Return the root page-table address for the selected Enclave. */
void *get_enclave_root_pt(mem_pool_t *mp, uint32_t enclave_id)
{
	int owner = pt_owner_from_enclave_id(enclave_id);

	if (!mp || owner < 0 || !mp->pt_pool.roots[owner].in_use)
		return NULL;
	return mp->pt_pool.roots[owner].base;
}

void *alloc_enclave_root_pt(mem_pool_t *mp, uint32_t enclave_id)
{
	int owner = pt_owner_from_enclave_id(enclave_id);

	if (owner < 0)
		return NULL;
	return alloc_pt_root(mp, (uint32_t)owner, CVM_GSTAGE_MODE);
}

/* Reset the page-table sub-pool for the selected Enclave. */
void reset_enclave_pt_pool(mem_pool_t *mp, uint32_t enclave_id)
{
	int owner = pt_owner_from_enclave_id(enclave_id);

	if (!mp || owner < 0)
		return;
	reset_pt_owner(mp, (uint32_t)owner);
}

static int data_owner_slot(uint32_t owner)
{
	if (owner & 0x80000000U) {
		uint32_t eid = owner & ~0x80000000U;

		return eid < MAX_ENCLAVES ? (int)(CVM_NUM + eid) : -1;
	}

	return owner < CVM_NUM ? (int)owner : -1;
}

static trusted_extent_t *find_extent_by_id(mem_pool_t *mp, uint32_t extent_id)
{
	if (!mp)
		return NULL;

	for (int i = 0; i < MAX_TRUSTED_EXTENTS; i++) {
		trusted_extent_t *extent = &mp->extents[i];

		if (extent->info.state != TRUSTED_EXTENT_FREE &&
		    extent->info.id == extent_id)
			return extent;
	}

	return NULL;
}

static trusted_extent_t *find_extent_for_hpa(data_pool_t *dp, uint64_t hpa)
{
	if (!dp || !dp->extents)
		return NULL;

	for (int i = 0; i < MAX_TRUSTED_EXTENTS; i++) {
		trusted_extent_t *extent = &dp->extents[i];
		uint32_t state = extent->info.state;

		if (state != TRUSTED_EXTENT_ONLINE &&
		    state != TRUSTED_EXTENT_DRAINING)
			continue;
		if (hpa >= extent->info.data_base &&
		    hpa < extent->info.data_base + extent->info.data_size)
			return extent;
	}

	return NULL;
}

static void free_list_add(data_pool_t *dp, data_block_t *block)
{
	block->prev = NULL;
	block->next = dp->head;
	if (dp->head)
		dp->head->prev = block;
	dp->head = block;
}

static void free_list_remove(data_pool_t *dp, data_block_t *block)
{
	if (block->prev)
		block->prev->next = block->next;
	else
		dp->head = block->next;
	if (block->next)
		block->next->prev = block->prev;
	block->prev = NULL;
	block->next = NULL;
}

static void owner_list_add(data_pool_t *dp, data_block_t *block, int owner_slot)
{
	block->owner_prev = NULL;
	block->owner_next = dp->owner_heads[owner_slot];
	if (block->owner_next)
		block->owner_next->owner_prev = block;
	dp->owner_heads[owner_slot] = block;
}

static void owner_list_remove(data_pool_t *dp, data_block_t *block,
			      int owner_slot)
{
	if (block->owner_prev)
		block->owner_prev->owner_next = block->owner_next;
	else
		dp->owner_heads[owner_slot] = block->owner_next;
	if (block->owner_next)
		block->owner_next->owner_prev = block->owner_prev;
	block->owner_prev = NULL;
	block->owner_next = NULL;
}

static int find_free_block_metadata(data_pool_t *dp, uint32_t block_count)
{
	uint32_t run = 0;

	for (int i = 0; i < dp->max_blocks; i++) {
		if (dp->blocks[i].extent_id == DATA_BLOCK_INVALID_EXTENT)
			run++;
		else
			run = 0;
		if (run == block_count)
			return i + 1 - block_count;
	}

	return -1;
}

static int add_extent_blocks(data_pool_t *dp, trusted_extent_t *extent)
{
	uint32_t block_count = extent->info.data_size / BLOCK_SIZE;
	int first_block;

	if (!block_count || block_count > (uint32_t)dp->max_blocks)
		return -1;
	first_block = find_free_block_metadata(dp, block_count);
	if (first_block < 0)
		return -1;

	extent->first_block = first_block;
	extent->info.total_blocks = block_count;
	extent->info.free_blocks = block_count;
	for (uint32_t i = 0; i < block_count; i++) {
		data_block_t *block = &dp->blocks[first_block + i];

		sbi_memset(block, 0, sizeof(*block));
		block->start_addr = extent->info.data_base +
				    (uint64_t)i * BLOCK_SIZE;
		block->owner = DATA_BLOCK_FREE_OWNER;
		block->pending_owner = DATA_BLOCK_FREE_OWNER;
		block->size = BLOCK_SIZE;
		block->extent_id = extent->info.id;
		free_list_add(dp, block);
	}
	dp->total_count += block_count;
	dp->free_count += block_count;
	return 0;
}

uint64_t alloc_data_block(data_pool_t *dp, uint32_t owner)
{
	data_block_t *block;
	trusted_extent_t *extent;
	int owner_slot = data_owner_slot(owner);

	if (!dp || owner_slot < 0 || owner >= DATA_BLOCK_ALLOCATING_OWNER)
		return (uint64_t)-1;

	spin_lock(&data_pool_lock);
	block = dp->head;
	if (!block) {
		spin_unlock(&data_pool_lock);
		return (uint64_t)-1;
	}

	extent = find_extent_by_id(&g_mem_pool, block->extent_id);
	if (!extent || extent->info.state != TRUSTED_EXTENT_ONLINE) {
		spin_unlock(&data_pool_lock);
		return (uint64_t)-1;
	}
	free_list_remove(dp, block);
	block->owner = DATA_BLOCK_ALLOCATING_OWNER;
	block->pending_owner = owner;
	owner_list_add(dp, block, owner_slot);
	dp->free_count--;
	extent->info.free_blocks--;
	spin_unlock(&data_pool_lock);

	/* A newly assigned private block must not expose stale host or CVM
	 * contents. Keep the block off the free list while zeroing so unrelated
	 * allocations can proceed without waiting on a 2 MiB memset. */
	sbi_memset((void *)block->start_addr, 0, block->size);

	spin_lock(&data_pool_lock);
	if (block->owner != DATA_BLOCK_ALLOCATING_OWNER ||
	    block->pending_owner != owner) {
		spin_unlock(&data_pool_lock);
		return (uint64_t)-1;
	}
	block->owner = owner;
	block->pending_owner = DATA_BLOCK_FREE_OWNER;
	tee_mem_status(dp);
	spin_unlock(&data_pool_lock);

	return block->start_addr;
}

void free_data_blocks_per_owner(data_pool_t *dp, uint32_t owner)
{
	int owner_slot = data_owner_slot(owner);

	if (!dp || owner_slot < 0 || owner >= DATA_BLOCK_ALLOCATING_OWNER)
		return;

	for (;;) {
		data_block_t *block;
		trusted_extent_t *extent;

		spin_lock(&data_pool_lock);
		block = dp->owner_heads[owner_slot];
		if (block) {
			owner_list_remove(dp, block, owner_slot);
			block->owner = DATA_BLOCK_RECLAIMING_OWNER;
			block->pending_owner = DATA_BLOCK_FREE_OWNER;
		}
		spin_unlock(&data_pool_lock);

		if (!block)
			break;

		/* Publish the block to the free list only after its previous
		 * owner's contents have been erased. */
		sbi_memset((void *)block->start_addr, 0, block->size);

		spin_lock(&data_pool_lock);
		if (block->owner == DATA_BLOCK_RECLAIMING_OWNER) {
			extent = find_extent_by_id(&g_mem_pool, block->extent_id);
			block->owner = DATA_BLOCK_FREE_OWNER;
			if (extent) {
				extent->info.free_blocks++;
				if (extent->info.state == TRUSTED_EXTENT_ONLINE) {
					free_list_add(dp, block);
					dp->free_count++;
				}
			}
		}
		spin_unlock(&data_pool_lock);
	}

	spin_lock(&data_pool_lock);
	tee_mem_status(dp);
	spin_unlock(&data_pool_lock);
}

bool data_block_owned_range(data_pool_t *dp, uint64_t hpa, uint32_t owner,
			    size_t *contiguous)
{
	bool owned = false;
	trusted_extent_t *extent;
	data_block_t *block;
	uint64_t block_index;

	if (!dp || !contiguous || owner >= DATA_BLOCK_ALLOCATING_OWNER)
		return false;

	spin_lock(&data_pool_lock);
	extent = find_extent_for_hpa(dp, hpa);
	if (extent) {
		block_index = (hpa - extent->info.data_base) / BLOCK_SIZE;
		block = &dp->blocks[extent->first_block + block_index];
		if (block->extent_id == extent->info.id && block->owner == owner) {
			*contiguous = block->start_addr + block->size - hpa;
			owned = true;
		}
	}
	spin_unlock(&data_pool_lock);

	return owned;
}

static int gstage_levels(uint8_t page_table_mode)
{
	switch (page_table_mode) {
	case HGATP_MODE_SV39X4:
		return 3;
	case HGATP_MODE_SV48X4:
		return 4;
	case HGATP_MODE_SV57X4:
		return 5;
	default:
		return -1;
	}
}

static bool pte_is_leaf_value(pte_t pte)
{
	return pte & (PTE_R | PTE_W | PTE_X);
}

static int split_leaf_entry(mem_pool_t *mp, int cvm_id, pte_t *entry,
			    int level)
{
	pte_t old_entry = *entry;
	pte_t *new_pt;
	uint64_t old_hpa;
	uint64_t flags;
	uint64_t child_size;
	int owner;

	if (!mp || !entry || level <= 0)
		return -1;

	owner = pt_owner_from_combined_id(cvm_id);
	if (owner < 0)
		return -1;
	new_pt = alloc_pt_page(mp, (uint32_t)owner);
	if (!new_pt)
		return -1;

	old_hpa = ((old_entry & ZION_PTE_ADDR_MASK) >> ZION_PTE_PPN_SHIFT)
		  << PAGE_SHIFT;
	flags = old_entry & ZION_PTE_FLAG_MASK;
	child_size = PAGE_SIZE << ((level - 1) * gstage_index_bits);

	sbi_memset(new_pt, 0, PAGE_SIZE);
	for (int i = 0; i <= ZION_PTE_INDEX_MASK; i++) {
		uint64_t child_hpa = old_hpa + i * child_size;

		new_pt[i] = ((child_hpa >> PAGE_SHIFT)
			     << ZION_PTE_PPN_SHIFT) | flags;
	}

	*entry = (((uint64_t)new_pt >> PAGE_SHIFT) << ZION_PTE_PPN_SHIFT) |
		 PTE_V;
	return 0;
}

static pte_t *get_pte_entry_internal(mem_pool_t *mp, pte_t *root_pt,
				     uint64_t va, bool allocate, int cvm_id,
				     int target_level,
				     uint8_t page_table_mode,
				     bool allow_split)
{
	int levels = gstage_levels(page_table_mode);
	pte_t *pt = root_pt;

	if (!root_pt || levels < 0 || target_level < 0 ||
	    target_level >= levels || (allocate && !mp))
		return NULL;

	for (int level = levels - 1; level >= 0; level--) {
		uint64_t mask = level == levels - 1 ?
				CVM_ROOT_PT_INDEX_MASK : ZION_PTE_INDEX_MASK;
		uint64_t index = (va >> (PAGE_SHIFT + level * gstage_index_bits))
					 & mask;
		pte_t *entry = &pt[index];

		if (level == target_level)
			return entry;

		if (*entry & PTE_V) {
			if (pte_is_leaf_value(*entry)) {
				if (!allow_split ||
				    split_leaf_entry(mp, cvm_id, entry, level))
					return NULL;
			}
			pt = (pte_t *)(((uint64_t)(*entry & ZION_PTE_ADDR_MASK)
					>> ZION_PTE_PPN_SHIFT) << PAGE_SHIFT);
		} else if (allocate) {
			/* Allocate a new intermediate page */
			int owner = pt_owner_from_combined_id(cvm_id);
			void *new_page = owner >= 0 ?
				alloc_pt_page(mp, (uint32_t)owner) : NULL;

			if (!new_page)
				return NULL;
			*entry = (((uint64_t)new_page >> PAGE_SHIFT)
				  << ZION_PTE_PPN_SHIFT) | PTE_V;
			pt = (pte_t *)new_page;
		} else {
			return NULL;
		}
	}

	return NULL;
}

pte_t *get_pte_entry(mem_pool_t *mp, pte_t *root_pt, uint64_t va, bool allocate,
			     int cvm_id, int target_level, uint8_t page_table_mode)
{
	return get_pte_entry_internal(mp, root_pt, va, allocate, cvm_id,
				      target_level, page_table_mode, false);
}

static int map_gpa_to_hpa_internal(mem_pool_t *mp, int cvm_id, uint64_t gpa,
				   uint64_t hpa, size_t size,
				   int target_level, uint64_t permissions,
				   bool replace)
{
	pte_t *root_pt = NULL;
	uint8_t page_table_mode;
	uint64_t page_size;
	uint64_t flags;

	/* For CVM IDs 0..CVM_NUM-1, use CVM sub-pool.
	   For enclave IDs, offset into enclave sub-pool. */
	if (cvm_id >= 0 && cvm_id < CVM_NUM) {
		root_pt = (pte_t *)get_cvm_root_pt(mp, (uint32_t)cvm_id);
		page_table_mode = get_cvm_pt_mode(mp, (uint32_t)cvm_id);
	} else if (cvm_id >= CVM_NUM && cvm_id < CVM_NUM + MAX_ENCLAVES) {
		int owner = pt_owner_from_combined_id(cvm_id);

		root_pt = (pte_t *)get_enclave_root_pt(mp,
			(uint32_t)(cvm_id - CVM_NUM));
		page_table_mode = owner >= 0 ?
			mp->pt_pool.roots[owner].pt_mode : CVM_GSTAGE_MODE;
	} else {
		return -1;
	}

	if (!root_pt || gstage_levels(page_table_mode) < 0 || target_level < 0 ||
	    target_level >= gstage_levels(page_table_mode) ||
	    (permissions & ~PTE_LEAF_PERM_MASK) || !(permissions & PTE_R) ||
	    ((permissions & PTE_W) && !(permissions & PTE_R)))
		return -1;

	page_size = PAGE_SIZE << (target_level * gstage_index_bits);
	if (!size || size % page_size || (gpa & (page_size - 1)) ||
	    (hpa & (page_size - 1)) || gpa + size < gpa || hpa + size < hpa)
		return -1;

	/* G-stage accesses use user permissions, matching Linux KVM's
	 * _PAGE_BASE mappings. PTE_U is therefore architectural here, not a
	 * request to expose the page to the host. */
	flags = PTE_V | PTE_U | PTE_A | permissions;
	if (permissions & PTE_W)
		flags |= PTE_D;

	for (size_t offset = 0; offset < size; offset += page_size) {
		pte_t *entry = get_pte_entry_internal(
			mp, root_pt, gpa + offset, true, cvm_id, target_level,
			page_table_mode, replace);
		pte_t new_entry;

		if (!entry)
			return -1;
		new_entry = (((hpa + offset) >> PAGE_SHIFT)
			     << ZION_PTE_PPN_SHIFT) | flags;
		if (!replace && *entry && *entry != new_entry)
			return -1;
		*entry = new_entry;
	}

	return 0;
}

int map_gpa_to_hpa(mem_pool_t *mp, int cvm_id, uint64_t gpa, uint64_t hpa,
			   size_t size, int target_level, uint64_t permissions)
{
	return map_gpa_to_hpa_internal(mp, cvm_id, gpa, hpa, size,
				       target_level, permissions, false);
}

int remap_gpa_to_hpa(mem_pool_t *mp, int cvm_id, uint64_t gpa, uint64_t hpa,
			     size_t size, int target_level, uint64_t permissions)
{
	return map_gpa_to_hpa_internal(mp, cvm_id, gpa, hpa, size,
				       target_level, permissions, true);
}

static int satp_levels(unsigned long mode)
{
	switch (mode) {
	case SATP_MODE_SV39:
		return 3;
	case SATP_MODE_SV48:
		return 4;
	case SATP_MODE_SV57:
		return 5;
	default:
		return -1;
	}
}

static bool resolve_hpa_for_security_check(uintptr_t root_pt, unsigned long mode,
					   unsigned long mtval, uint64_t *hpa,
					   pte_t **resolved_pte)
{
	int levels = satp_levels(mode);
	pte_t *pt = (pte_t *)root_pt;

	if (!root_pt || levels < 0 || !hpa || !resolved_pte)
		return false;

	for (int level = levels - 1; level >= 0; level--) {
		uint64_t index = (mtval >> (PAGE_SHIFT + level * gstage_index_bits)) &
				 ZION_PTE_INDEX_MASK;
		pte_t *pte = &pt[index];
		uint64_t page_size;
		uint64_t base;

		if (!(*pte & PTE_V))
			return false;
		if (!pte_is_leaf_value(*pte)) {
			pt = (pte_t *)(((*pte & ZION_PTE_ADDR_MASK) >>
					    ZION_PTE_PPN_SHIFT) << PAGE_SHIFT);
			continue;
		}

		page_size = PAGE_SIZE << (level * gstage_index_bits);
		base = ((*pte & ZION_PTE_ADDR_MASK) >> ZION_PTE_PPN_SHIFT)
		       << PAGE_SHIFT;
		if (base & (page_size - 1))
			return false;
		*hpa = base + (mtval & (page_size - 1));
		*resolved_pte = pte;
		return true;
	}

	return false;
}

static bool address_in_range(uint64_t addr, uint64_t start, uint64_t end)
{
	return addr >= start && addr < end;
}

static void report_smm_region_access(uint64_t hpa)
{
	uint64_t vcpu_start = (uint64_t)&tee_threads[0];
	uint64_t vcpu_end = (uint64_t)&tee_threads[MAX_TEE_THREADS];

	tee_log(
		"[SM] TEE security check: The hypervisor is trying to access the SM region\n");

	if (address_in_range(hpa, vcpu_start, vcpu_end)) {
		tee_log(
			"[SM] TEE security check: The hypervisor is trying to access the vCPU region\n");
	}
}

static void report_protected_region_access(uint64_t hpa, unsigned long mcause)
{
	trusted_extent_t *matched = NULL;
	uintptr_t page_table_end;

	for (int i = 0; i < MAX_TRUSTED_EXTENTS; i++) {
		trusted_extent_t *extent = &g_mem_pool.extents[i];
		uint32_t state = extent->info.state;

		if (state != TRUSTED_EXTENT_ONLINE &&
		    state != TRUSTED_EXTENT_DRAINING &&
		    state != TRUSTED_EXTENT_REMOVING)
			continue;
		if (address_in_range(hpa, extent->info.base,
				     extent->info.base + extent->info.size)) {
			matched = extent;
			break;
		}
	}
	if (!matched)
		return;

	tee_log(
		"[SM] TEE security check: the hypervisor is trying to r/w the protected region\n");
	tee_log("[SM] TEE security check: extent=%u physical address=%lx\n",
		matched->info.id, hpa);

	page_table_end = (uintptr_t)g_mem_pool.pt_pool.base +
			 g_mem_pool.pt_pool.total_size;
	if (matched->is_core &&
	    address_in_range(hpa, (uintptr_t)g_mem_pool.pt_pool.base,
			     page_table_end)) {
		if (mcause == CAUSE_LOAD_ACCESS) {
			tee_log(
				"[SM] TEE security check: The hypervisor is trying to read the page table region\n");
		} else if (mcause == CAUSE_STORE_ACCESS) {
			tee_log(
				"[SM] TEE security check: The hypervisor is trying to write the page table region\n");
		}
		return;
	}

	if (mcause == CAUSE_LOAD_ACCESS) {
		tee_log(
			"[SM] TEE security check: The hypervisor is trying to read the CVM private memory\n");
	} else if (mcause == CAUSE_STORE_ACCESS) {
		tee_log(
			"[SM] TEE security check: The hypervisor is trying to write the CVM private memory\n");
	}
}

static int init_mem_pool(mem_pool_t *mp, uint8_t *base, size_t n_page,
			 data_block_t blocks_arr[], int max_blocks)
{
	size_t total_mem_bytes;
	size_t align = HUGE_PAGE_SIZE;
	// Reserve page table memory for CVMs and Enclaves.
	size_t pt_total_bytes = PT_POOL_DYNAMIC_MB * MB;
	size_t min_pt_bytes = PT_OWNER_COUNT * ROOT_PT_PAGES * PAGE_SIZE +
			      PAGE_SIZE;
	uint64_t data_pool_start;
	size_t data_pool_size;

	if (!mp || !base || !n_page || n_page > (~(size_t)0) / PAGE_SIZE ||
	    (uintptr_t)base & (PAGE_SIZE - 1))
		return -1;
	total_mem_bytes = n_page * PAGE_SIZE;
	if ((uintptr_t)base + total_mem_bytes < (uintptr_t)base)
		return -1;
	pt_total_bytes = (pt_total_bytes + align - 1) & ~(align - 1);

	if (pt_total_bytes > PT_POOL_MAX_PAGES * PAGE_SIZE ||
	    pt_total_bytes < min_pt_bytes ||
	    total_mem_bytes < pt_total_bytes + BLOCK_SIZE)
		return -1;

	sbi_memset(mp, 0, sizeof(*mp));
	for (int i = 0; i < max_blocks; i++) {
		sbi_memset(&blocks_arr[i], 0, sizeof(blocks_arr[i]));
		blocks_arr[i].extent_id = DATA_BLOCK_INVALID_EXTENT;
	}
	mp->base_addr = base;
	mp->total_pages = n_page;
	mp->data_pool.blocks = blocks_arr;
	mp->data_pool.max_blocks = max_blocks;
	mp->data_pool.extents = mp->extents;
	mp->next_extent_generation = 1;

	init_pt_pool(&mp->pt_pool, base, pt_total_bytes);

	// Use the remaining aligned memory as the data pool in 2MB blocks.
	data_pool_start = (uint64_t)(base + pt_total_bytes);
	data_pool_start		 = (data_pool_start + align - 1) & ~(align - 1);
	if (data_pool_start < (uint64_t)base ||
	    data_pool_start - (uint64_t)base > total_mem_bytes)
		return -1;
	data_pool_size = total_mem_bytes - (data_pool_start - (uint64_t)base);
	if (data_pool_size / BLOCK_SIZE > (size_t)max_blocks)
		return -1;

	trusted_extent_t *core = &mp->extents[TRUSTED_CORE_EXTENT_ID];
	core->info.base = (uint64_t)base;
	core->info.size = total_mem_bytes;
	core->info.data_base = data_pool_start;
	core->info.data_size = data_pool_size & ~(BLOCK_SIZE - 1);
	core->info.id = TRUSTED_CORE_EXTENT_ID;
	core->info.generation = 0;
	core->info.state = TRUSTED_EXTENT_PREPARING;
	core->info.pmp_region_id = -1;
	core->is_core = true;
	if (add_extent_blocks(&mp->data_pool, core))
		return -1;
	return mp->data_pool.total_count ? 0 : -1;
}

static int validate_new_extent_locked(uint64_t base, size_t size,
				      uint64_t *data_base,
				      uint64_t *data_size)
{
	uint64_t end;
	uint64_t aligned_start;
	uint64_t aligned_end;
	bool have_slot = false;

	if (!base || !size || (base & (PAGE_SIZE - 1)) ||
	    (size & (PAGE_SIZE - 1)) || base + size < base)
		return -1;
	end = base + size;
	aligned_start = (base + BLOCK_SIZE - 1) & ~(BLOCK_SIZE - 1);
	aligned_end = end & ~(BLOCK_SIZE - 1);
	if (aligned_start < base || aligned_end <= aligned_start)
		return -1;

	for (int i = 0; i < MAX_TRUSTED_EXTENTS; i++) {
		trusted_extent_t *extent = &g_mem_pool.extents[i];

		if (extent->info.state == TRUSTED_EXTENT_FREE) {
			have_slot = true;
			continue;
		}
		if (base < extent->info.base + extent->info.size &&
		    extent->info.base < end)
			return -1;
	}
	if (!have_slot || (aligned_end - aligned_start) / BLOCK_SIZE >
			 (uint64_t)g_mem_pool.data_pool.max_blocks)
		return -1;
	if (find_free_block_metadata(&g_mem_pool.data_pool,
			(aligned_end - aligned_start) / BLOCK_SIZE) < 0)
		return -1;

	if (data_base)
		*data_base = aligned_start;
	if (data_size)
		*data_size = aligned_end - aligned_start;
	return 0;
}

int tee_mem_validate_new_extent(uint64_t base, size_t size)
{
	int ret;

	spin_lock(&data_pool_lock);
	ret = validate_new_extent_locked(base, size, NULL, NULL);
	spin_unlock(&data_pool_lock);
	return ret;
}

int tee_mem_set_core_pmp_region(int pmp_region_id)
{
	trusted_extent_t *core = &g_mem_pool.extents[TRUSTED_CORE_EXTENT_ID];

	if (pmp_region_id < 0)
		return -1;
	spin_lock(&data_pool_lock);
	if (core->info.state != TRUSTED_EXTENT_PREPARING || !core->is_core) {
		spin_unlock(&data_pool_lock);
		return -1;
	}
	core->info.pmp_region_id = pmp_region_id;
	core->info.state = TRUSTED_EXTENT_ONLINE;
	spin_unlock(&data_pool_lock);
	return 0;
}

int tee_mem_add_extent(uint64_t base, size_t size, int pmp_region_id,
		       uint32_t *extent_id)
{
	trusted_extent_t *extent = NULL;
	uint64_t data_base;
	uint64_t data_size;
	uint32_t generation;
	int slot = -1;

	if (pmp_region_id < 0 || !extent_id)
		return -1;
	spin_lock(&data_pool_lock);
	if (validate_new_extent_locked(base, size, &data_base, &data_size))
		goto fail;
	for (int i = 1; i < MAX_TRUSTED_EXTENTS; i++) {
		if (g_mem_pool.extents[i].info.state == TRUSTED_EXTENT_FREE) {
			slot = i;
			break;
		}
	}
	if (slot < 0)
		goto fail;

	extent = &g_mem_pool.extents[slot];
	if (g_mem_pool.next_extent_generation > (~(uint32_t)0 >> 8))
		goto fail;
	generation = g_mem_pool.next_extent_generation++;
	sbi_memset(extent, 0, sizeof(*extent));
	extent->info.base = base;
	extent->info.size = size;
	extent->info.data_base = data_base;
	extent->info.data_size = data_size;
	extent->info.generation = generation;
	extent->info.id = (generation << 8) | slot;
	extent->info.state = TRUSTED_EXTENT_PREPARING;
	extent->info.pmp_region_id = pmp_region_id;
	if (add_extent_blocks(&g_mem_pool.data_pool, extent)) {
		sbi_memset(extent, 0, sizeof(*extent));
		goto fail;
	}
	extent->info.state = TRUSTED_EXTENT_ONLINE;
	*extent_id = extent->info.id;
	spin_unlock(&data_pool_lock);
	return 0;

fail:
	spin_unlock(&data_pool_lock);
	return -1;
}

int tee_mem_prepare_remove_extent(uint32_t extent_id,
				  tee_mem_extent_info_t *info)
{
	trusted_extent_t *extent;
	data_pool_t *dp = &g_mem_pool.data_pool;

	if (!info || extent_id == TRUSTED_CORE_EXTENT_ID)
		return -1;
	spin_lock(&data_pool_lock);
	extent = find_extent_by_id(&g_mem_pool, extent_id);
	if (!extent || extent->is_core ||
	    (extent->info.state != TRUSTED_EXTENT_ONLINE &&
	     extent->info.state != TRUSTED_EXTENT_DRAINING))
		goto fail;

	if (extent->info.state == TRUSTED_EXTENT_ONLINE) {
		for (uint32_t i = 0; i < extent->info.total_blocks; i++) {
			data_block_t *block = &dp->blocks[extent->first_block + i];

			if (block->owner == DATA_BLOCK_FREE_OWNER) {
				free_list_remove(dp, block);
				dp->free_count--;
			}
		}
		extent->info.state = TRUSTED_EXTENT_DRAINING;
	}

	if (extent->info.free_blocks != extent->info.total_blocks) {
		*info = extent->info;
		spin_unlock(&data_pool_lock);
		return -2;
	}
	for (uint32_t i = 0; i < extent->info.total_blocks; i++) {
		data_block_t *block = &dp->blocks[extent->first_block + i];

		if (block->owner != DATA_BLOCK_FREE_OWNER)
			goto fail;
	}

	extent->info.state = TRUSTED_EXTENT_REMOVING;
	*info = extent->info;
	spin_unlock(&data_pool_lock);
	return 0;

fail:
	spin_unlock(&data_pool_lock);
	return -1;
}

void tee_mem_cancel_remove_extent(uint32_t extent_id)
{
	trusted_extent_t *extent;

	spin_lock(&data_pool_lock);
	extent = find_extent_by_id(&g_mem_pool, extent_id);

	if (extent && extent->info.state == TRUSTED_EXTENT_REMOVING)
		extent->info.state = TRUSTED_EXTENT_DRAINING;
	spin_unlock(&data_pool_lock);
}

void tee_mem_finish_remove_extent(uint32_t extent_id)
{
	data_pool_t *dp = &g_mem_pool.data_pool;
	trusted_extent_t *extent;

	spin_lock(&data_pool_lock);
	extent = find_extent_by_id(&g_mem_pool, extent_id);

	if (extent && extent->info.state == TRUSTED_EXTENT_REMOVING) {
		for (uint32_t i = 0; i < extent->info.total_blocks; i++) {
			data_block_t *block = &dp->blocks[extent->first_block + i];

			sbi_memset(block, 0, sizeof(*block));
			block->extent_id = DATA_BLOCK_INVALID_EXTENT;
		}
		dp->total_count -= extent->info.total_blocks;
		sbi_memset(extent, 0, sizeof(*extent));
	}
	spin_unlock(&data_pool_lock);
}

int tee_mem_query_extent(uint32_t extent_id, tee_mem_extent_info_t *info)
{
	trusted_extent_t *extent;

	if (!info)
		return -1;
	spin_lock(&data_pool_lock);
	extent = find_extent_by_id(&g_mem_pool, extent_id);
	if (!extent) {
		spin_unlock(&data_pool_lock);
		return -1;
	}
	*info = extent->info;
	spin_unlock(&data_pool_lock);
	return 0;
}

void tee_mem_context_enter_begin(void)
{
	spin_lock(&memory_policy_lock);
	active_tee_contexts++;
}

void tee_mem_context_enter_end(void)
{
	spin_unlock(&memory_policy_lock);
}

void tee_mem_context_exit_begin(void)
{
	spin_lock(&memory_policy_lock);
}

void tee_mem_context_exit_end(void)
{
	if (active_tee_contexts)
		active_tee_contexts--;
	spin_unlock(&memory_policy_lock);
}

int tee_mem_maintenance_begin(void)
{
	spin_lock(&memory_policy_lock);
	if (active_tee_contexts) {
		spin_unlock(&memory_policy_lock);
		return -1;
	}
	return 0;
}

void tee_mem_maintenance_end(void)
{
	spin_unlock(&memory_policy_lock);
}

int tee_mem_set_local_pmp_permissions(uint8_t permissions)
{
	int ret = 0;

	for (int i = 0; i < MAX_TRUSTED_EXTENTS; i++) {
		trusted_extent_t *extent = &g_mem_pool.extents[i];
		uint32_t state = extent->info.state;

		if ((state != TRUSTED_EXTENT_ONLINE &&
		     state != TRUSTED_EXTENT_DRAINING &&
		     state != TRUSTED_EXTENT_REMOVING) ||
		    extent->info.pmp_region_id < 0)
			continue;
		if (pmp_set_zion(extent->info.pmp_region_id, permissions))
			ret = -1;
	}
	return ret;
}

int tee_mem_replay_local_pmp_permissions(uint8_t permissions)
{
	int ret;

	spin_lock(&memory_policy_lock);
	ret = tee_mem_set_local_pmp_permissions(permissions);
	spin_unlock(&memory_policy_lock);
	return ret;
}

void tee_security_check(unsigned long mtval, unsigned long mcause,
			unsigned long raw_root_pt)
{
	if (raw_root_pt == 0) {
		raw_root_pt = csr_read(CSR_SATP);
	}
	uintptr_t root_pt =
		(raw_root_pt & ZION_SATP_PPN_MASK) << PAGE_SHIFT;
	unsigned long mode = (raw_root_pt >> ZION_SATP_MODE_SHIFT) &
			      ZION_SATP_MODE_MASK;

	tee_log(
		"[SM] TEE security check: Info: mtval=%lx, mcause=%lx, root_pt: %lx, mode: %lx\n",
		mtval, mcause, root_pt, mode);

	pte_t *pte = NULL;
	uint64_t hpa = 0;

	if (!resolve_hpa_for_security_check(root_pt, mode, mtval, &hpa, &pte))
		return;
	tee_log("[SM] The hpa: 0x%lx, with permission: %lx\n", hpa,
		   *pte & ZION_PTE_FLAG_MASK);

	uint64_t smm_start = SMM_BASE;
	uint64_t smm_end   = SMM_BASE + SMM_SIZE;
	if (address_in_range(hpa, smm_start, smm_end)) {
		report_smm_region_access(hpa);
		return;
	}

	report_protected_region_access(hpa, mcause);
}

int tee_mem_init(uint8_t *mem_base, size_t n_page)
{

	/* Do not erase the region here: reserve_mem() has not installed its PMP
	 * deny policy yet. Page-table sub-pools and data blocks are erased before
	 * first assignment, after the core extent is protected. */
	//sbi_memset((void *)mem_base, 0, n_page * PAGE_SIZE);

	if (init_mem_pool(&g_mem_pool, mem_base, n_page, data_blocks_arr,
			  MAX_DATA_BLOCKS))
		return -1;

	tee_mem_status(&g_mem_pool.data_pool);

	return 0;
}
