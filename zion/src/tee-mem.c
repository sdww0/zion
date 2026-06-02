
#include "tee-mem.h"
#include "zion.h"
#include "tee.h"
#include "sm.h"
#include "sbi/riscv_encoding.h"
#include "sbi/sbi_hfence.h"
#include TARGET_PLATFORM_HEADER

mem_pool_t g_mem_pool;
static data_block_t data_blocks_arr[MAX_DATA_BLOCKS];
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

// Initialize the page-table pool. The provided base must point to a
// region large enough for CVM_NUM + MAX_ENCLAVES sub-pools.
static void init_pt_pool(pt_pool_t *pt_pool, uint8_t *base, size_t total_size)
{
	pt_pool->base	    = base;
	pt_pool->total_size = total_size;
	uint8_t *cursor	    = base;

	/* CVM sub-pools: CVM_NUM * PT_MEM_PER_CVM_MB each */
	size_t cvm_subpool_size = PT_MEM_PER_CVM_MB * MB;
	for (int i = 0; i < CVM_NUM; i++) {
		pt_pool->cvm[i].base	= cursor;
		pt_pool->cvm[i].pt_mode = CVM_GSTAGE_MODE;
		pt_pool->cvm[i].size	= cvm_subpool_size;
		pt_pool->cvm[i].offset	= ROOT_PT_PAGES;
		cursor += cvm_subpool_size;
	}

	/* Enclave sub-pools: MAX_ENCLAVES * PT_MEM_PER_ENCLAVE_MB each */
	size_t enc_subpool_size = PT_MEM_PER_ENCLAVE_MB * MB;
	for (int i = 0; i < MAX_ENCLAVES; i++) {
		pt_pool->enclave[i].base	= cursor;
		pt_pool->enclave[i].pt_mode	= CVM_GSTAGE_MODE;
		pt_pool->enclave[i].size	= enc_subpool_size;
		pt_pool->enclave[i].offset	= ROOT_PT_PAGES;
		cursor += enc_subpool_size;
	}
}

// Allocate one 4KB page from the selected CVM page-table sub-pool.
static void *alloc_pt_page(mem_pool_t *mp, uint32_t cvm_id)
{
	if (cvm_id >= CVM_NUM)
		return NULL;
	pt_subpool_t *subpool = &mp->pt_pool.cvm[cvm_id];
	size_t total_pages    = subpool->size / PAGE_SIZE;
	if (subpool->offset >= total_pages)
		return NULL;
	void *page = subpool->base + (subpool->offset * PAGE_SIZE);
	subpool->offset++;
	return page;
}

// Allocate one 4KB page from the selected Enclave page-table sub-pool.
static void *alloc_pt_page_enclave(mem_pool_t *mp, uint32_t enclave_id)
{
	if (enclave_id >= MAX_ENCLAVES)
		return NULL;
	pt_subpool_t *subpool = &mp->pt_pool.enclave[enclave_id];
	size_t total_pages    = subpool->size / PAGE_SIZE;
	if (subpool->offset >= total_pages)
		return NULL;
	void *page = subpool->base + (subpool->offset * PAGE_SIZE);
	subpool->offset++;
	return page;
}

static int split_leaf_entry(mem_pool_t *mp, uint32_t cvm_id, pte_t *entry,
			    int level)
{
	pte_t old_entry = *entry;
	pte_t *new_pt;
	uint64_t old_hpa;
	uint64_t flags;
	uint64_t child_size;

	if (!mp || !entry || level <= 0)
		return -1;

	new_pt = alloc_pt_page(mp, cvm_id);
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

// Return the root page-table address for the selected CVM.
void *get_cvm_root_pt(mem_pool_t *mp, uint32_t cvm_id)
{
	if (cvm_id >= CVM_NUM)
		return NULL;
	return mp->pt_pool.cvm[cvm_id].base;
}

uint8_t get_cvm_pt_mode(mem_pool_t *mp, uint32_t cvm_id)
{
	if (cvm_id >= CVM_NUM)
		return CVM_GSTAGE_MODE;
	return mp->pt_pool.cvm[cvm_id].pt_mode;
}

void set_cvm_pt_mode(mem_pool_t *mp, uint32_t cvm_id, uint8_t mode)
{
	if (cvm_id >= CVM_NUM)
		return;
	mp->pt_pool.cvm[cvm_id].pt_mode = mode;
}

void reset_cvm_pt_pool(mem_pool_t *mp, uint32_t cvm_id)
{
	if (!mp || cvm_id >= CVM_NUM)
		return;

	pt_subpool_t *subpool = &mp->pt_pool.cvm[cvm_id];
	if (!subpool->base)
		return;

	sbi_memset(subpool->base, 0, subpool->size);
	subpool->pt_mode = CVM_GSTAGE_MODE;
	subpool->offset = ROOT_PT_PAGES;
}

/* Return the root page-table address for the selected Enclave. */
void *get_enclave_root_pt(mem_pool_t *mp, uint32_t enclave_id)
{
	if (enclave_id >= MAX_ENCLAVES)
		return NULL;
	return mp->pt_pool.enclave[enclave_id].base;
}

/* Reset the page-table sub-pool for the selected Enclave. */
void reset_enclave_pt_pool(mem_pool_t *mp, uint32_t enclave_id)
{
	if (!mp || enclave_id >= MAX_ENCLAVES)
		return;

	pt_subpool_t *subpool = &mp->pt_pool.enclave[enclave_id];
	if (!subpool->base)
		return;

	sbi_memset(subpool->base, 0, subpool->size);
	subpool->pt_mode = CVM_GSTAGE_MODE;
	subpool->offset = ROOT_PT_PAGES;
}

// Split the data pool into 2MB blocks and build the free list.
static void init_data_pool(data_pool_t *dp, uint64_t start_addr,
			   size_t pool_size, data_block_t blocks_arr[],
			   int max_blocks)
{
	int num_blocks = pool_size / BLOCK_SIZE;
	if (num_blocks > max_blocks)
		num_blocks = max_blocks;
	dp->total_count	   = num_blocks;
	dp->free_count	   = num_blocks;
	dp->head	   = NULL;
	data_block_t *prev = NULL;

	for (int i = 0; i < num_blocks; i++) {
		blocks_arr[i].start_addr = start_addr + (uint64_t)i * BLOCK_SIZE;
		blocks_arr[i].tid	 = DATA_BLOCK_FREE_TID;
		blocks_arr[i].size	 = BLOCK_SIZE;
		blocks_arr[i].prev	 = prev;
		blocks_arr[i].next	 = NULL;
		if (prev)
			prev->next = &blocks_arr[i];
		else
			dp->head = &blocks_arr[i];
		prev = &blocks_arr[i];
	}
}

uint64_t alloc_data_block(data_pool_t *dp, uint32_t tid)
{
	if (!dp || !dp->head)
		return (uint64_t)-1;

	data_block_t *block = dp->head;
	dp->head = block->next;
	if (dp->head)
		dp->head->prev = NULL;
	block->next = NULL;
	block->prev = NULL;
	block->tid  = tid;
	dp->free_count--;

	tee_mem_status(dp);

	return block->start_addr;
}

void free_data_blocks_per_tid(data_pool_t *dp, uint32_t tid)
{
	if (!dp)
		return;

	data_block_t *blk = dp->head;
	data_block_t *last_free = NULL;

	/* Find the tail of the current free list */
	if (blk) {
		while (blk->next)
			blk = blk->next;
		last_free = blk;
	}

	/* Walk all blocks, reclaim those belonging to tid */
	for (int i = 0; i < dp->total_count; i++) {
		data_block_t *b = &data_blocks_arr[i];
		if (b->tid != tid)
			continue;

		/* Unlink from used list (no used-list head, blocks are
		   standalone when allocated) */
		b->tid = DATA_BLOCK_FREE_TID;
		b->prev = last_free;
		b->next = NULL;
		if (last_free)
			last_free->next = b;
		else
			dp->head = b;
		last_free = b;
		dp->free_count++;
	}

	tee_mem_status(dp);
}

pte_t *get_pte_entry(mem_pool_t *mp, pte_t *root_pt, uint64_t va, bool allocate,
		     int cvm_id, int target_level, uint8_t page_table_mode)
{
	int levels = 4; // Sv48x4 has 4 levels
	pte_t *pt   = root_pt;

	(void)mp;
	(void)cvm_id;
	(void)page_table_mode;

	for (int level = levels - 1; level >= 0; level--) {
		uint64_t index = (va >> (PAGE_SHIFT + level * gstage_index_bits))
				 & ZION_PTE_INDEX_MASK;
		pte_t *entry = &pt[index];

		if (level == target_level)
			return entry;

		if (*entry & PTE_V) {
			/* Valid non-leaf: descend */
			pt = (pte_t *)(((uint64_t)(*entry & ZION_PTE_ADDR_MASK)
					>> ZION_PTE_PPN_SHIFT) << PAGE_SHIFT);
		} else if (allocate) {
			/* Allocate a new intermediate page */
			void *new_page = NULL;
			if (cvm_id >= 0 && cvm_id < CVM_NUM)
				new_page = alloc_pt_page(mp, (uint32_t)cvm_id);
			else if (cvm_id >= CVM_NUM &&
				 cvm_id < CVM_NUM + MAX_ENCLAVES)
				new_page = alloc_pt_page_enclave(mp,
					(uint32_t)(cvm_id - CVM_NUM));
			if (!new_page)
				return NULL;
			sbi_memset(new_page, 0, PAGE_SIZE);
			*entry = (((uint64_t)new_page >> PAGE_SHIFT)
				  << ZION_PTE_PPN_SHIFT) | PTE_V;
			pt = (pte_t *)new_page;
		} else {
			return NULL;
		}
	}

	return NULL;
}

int map_gpa_to_hpa(mem_pool_t *mp, int cvm_id, uint64_t gpa, uint64_t hpa,
		   size_t size, bool huge_page, bool rdonly)
{
	(void)size;
	pte_t *root_pt = NULL;

	/* For CVM IDs 0..CVM_NUM-1, use CVM sub-pool.
	   For enclave IDs, offset into enclave sub-pool. */
	if (cvm_id >= 0 && cvm_id < CVM_NUM) {
		root_pt = (pte_t *)get_cvm_root_pt(mp, (uint32_t)cvm_id);
	} else if (cvm_id >= CVM_NUM && cvm_id < CVM_NUM + MAX_ENCLAVES) {
		root_pt = (pte_t *)get_enclave_root_pt(mp,
			(uint32_t)(cvm_id - CVM_NUM));
	}

	if (!root_pt)
		return -1;

	int target_level = huge_page ? 1 : 0; // 2MB huge at level 1, 4K at level 0

	pte_t *entry = get_pte_entry(mp, root_pt, gpa, true,
				     cvm_id, target_level, CVM_GSTAGE_MODE);
	if (!entry)
		return -1;

	uint64_t flags = PTE_V | PTE_R | PTE_A | PTE_D;
	if (!rdonly)
		flags |= PTE_W;
	flags |= PTE_X | PTE_U;

	*entry = ((hpa >> PAGE_SHIFT) << ZION_PTE_PPN_SHIFT) | flags;

	return 0;
}

static bool pte_is_valid(pte_t *pte)
{
	return pte && (*pte & PTE_V);
}

static bool translate_hpa_at_level(uintptr_t root_pt, unsigned long mode,
				   unsigned long mtval, int level,
				   unsigned long offset_mask,
				   const char *page_name, uint64_t *hpa,
				   pte_t **resolved_pte)
{
	unsigned long offset = mtval & offset_mask;
	pte_t *pte = get_pte_entry(NULL, (pte_t *)root_pt, mtval, false, 0,
				   level, mode);

	if (!pte_is_valid(pte)) {
		if (pte) {
			tee_log(
				"[SM] TEE security check: No translation in %s page, pte: %lx\n",
				page_name, *pte);
		} else {
			tee_log(
				"[SM] TEE security check: No translation in %s page\n",
				page_name);
		}
		return false;
	}

	*resolved_pte = pte;
	*hpa = ((*pte >> ZION_PTE_PPN_SHIFT) << PAGE_SHIFT) + offset;
	return true;
}

static bool resolve_hpa_for_security_check(uintptr_t root_pt, unsigned long mode,
					   unsigned long mtval, uint64_t *hpa,
					   pte_t **resolved_pte)
{
	if (translate_hpa_at_level(root_pt, mode, mtval, 0,
				   ZION_4K_PAGE_OFFSET_MASK, "4KiB", hpa,
				   resolved_pte))
		return true;

	if (translate_hpa_at_level(root_pt, mode, mtval, 1,
				   ZION_2M_PAGE_OFFSET_MASK, "2MiB", hpa,
				   resolved_pte))
		return true;

	return translate_hpa_at_level(root_pt, mode, mtval, 2,
				      ZION_1G_PAGE_OFFSET_MASK, "1GiB", hpa,
				      resolved_pte);
}

static bool address_in_range(uint64_t addr, uint64_t start, uint64_t end)
{
	return addr >= start && addr < end;
}

static void report_smm_region_access(uint64_t hpa, unsigned long mtval)
{
	uint64_t vcpu_start = (uint64_t)(&(tee_threads[0]));
	uint64_t vcpu_end = (uint64_t)(&(tee_threads[MAX_TEE_THREADS]) +
				       sizeof(struct tee_thread));

	tee_log(
		"[SM] TEE security check: The hypervisor is trying to access the SM region\n");

	hpa += mtval & ZION_4K_PAGE_OFFSET_MASK;
	if (address_in_range(hpa, vcpu_start, vcpu_end)) {
		tee_log(
			"[SM] TEE security check: The hypervisor is trying to access the vCPU region\n");
	}
}

static void report_protected_region_access(uint64_t hpa, unsigned long mcause)
{
	uintptr_t protection_start = (uintptr_t)g_mem_pool.base_addr;
	uintptr_t protection_end =
		(uintptr_t)g_mem_pool.base_addr +
		g_mem_pool.total_pages * PAGE_SIZE;
	uintptr_t page_table_end =
		protection_start + PT_MEM_PER_CVM_MB * MB * CVM_NUM;

	if (!protection_start || !g_mem_pool.total_pages ||
	    !address_in_range(hpa, protection_start, protection_end)) {
		return;
	}

	tee_log(
		"[SM] TEE security check: the hypervisor is trying to r/w the protected region\n");
	tee_log("[SM] TEE security check: The physical address: %lx\n", hpa);

	if (address_in_range(hpa, protection_start, page_table_end)) {
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

static void init_mem_pool(mem_pool_t *mp, uint8_t *base, uint32_t n_page,
			  data_block_t blocks_arr[], int max_blocks)
{
	mp->base_addr		 = base;
	mp->total_pages		 = n_page;
	uint32_t total_mem_bytes = n_page * PAGE_SIZE;
	uint32_t align		 = HUGE_PAGE_SIZE;
	// Reserve page table memory for CVMs and Enclaves.
	uint32_t pt_bytes_per_cvm    = PT_MEM_PER_CVM_MB * MB;
	uint32_t pt_bytes_per_enclave = PT_MEM_PER_ENCLAVE_MB * MB;
	uint32_t pt_total_bytes	     = CVM_NUM * pt_bytes_per_cvm +
				       MAX_ENCLAVES * pt_bytes_per_enclave;
	pt_total_bytes = (pt_total_bytes + align - 1) & ~(align - 1);

	if (total_mem_bytes < pt_total_bytes)
		return;

	init_pt_pool(&mp->pt_pool, base, pt_total_bytes);

	// Use the remaining aligned memory as the data pool in 2MB blocks.
	uint64_t data_pool_start = (uint64_t)(base + pt_total_bytes);
	data_pool_start		 = (data_pool_start + align - 1) & ~(align - 1);
	size_t data_pool_size =
		total_mem_bytes - (data_pool_start - (uint64_t)base);
	init_data_pool(&mp->data_pool, data_pool_start, data_pool_size,
		       blocks_arr, max_blocks);
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
		report_smm_region_access(hpa, mtval);
		return;
	}

	report_protected_region_access(hpa, mcause);
}

int tee_mem_init(uint8_t *mem_base, uint32_t n_page)
{

	sbi_memset((void *)mem_base, 0, n_page * PAGE_SIZE);

	init_mem_pool(&g_mem_pool, mem_base, n_page, data_blocks_arr,
		      MAX_DATA_BLOCKS);

	tee_mem_status(&g_mem_pool.data_pool);

	return 0;
}
