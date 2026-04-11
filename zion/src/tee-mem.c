
#include "tee-mem.h"
#include "zion.h"
#include "tee.h"
#include "sm.h"
#include "sbi/riscv_encoding.h"

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
	int free_blocks	     = get_free_data_block_count(dp);
	int allocated_blocks = get_allocated_data_block_count(dp);

	zion_printf("[SM] Data Pool -- Free blocks: %d, Allocated blocks: %d\n",
		    free_blocks, allocated_blocks);
#else
	(void)dp;
#endif
}

// Initialize the page-table pool. The provided base must point to a
// CVM_NUM * (PT_MEM_PER_CVM_MB * MB) region.
static void init_pt_pool(pt_pool_t *pt_pool, uint8_t *base, size_t total_size)
{
	pt_pool->base	    = base;
	pt_pool->total_size = total_size;
	size_t subpool_size = PT_MEM_PER_CVM_MB * MB;
	for (int i = 0; i < CVM_NUM; i++) {
		pt_pool->cvm[i].base	= base + i * subpool_size;
		pt_pool->cvm[i].pt_mode = CVM_GSTAGE_MODE;
		pt_pool->cvm[i].size	= subpool_size;
		pt_pool->cvm[i].offset = ROOT_PT_PAGES;
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
		data_block_t *blk = &blocks_arr[i];
		blk->start_addr	  = start_addr + i * BLOCK_SIZE;
		blk->tid	  = DATA_BLOCK_FREE_TID;
		blk->size	  = BLOCK_SIZE;
		blk->prev	  = prev;
		blk->next	  = NULL;
		if (prev)
			prev->next = blk;
		else
			dp->head = blk;
		prev = blk;
	}
}

// Allocate one 2MB block from the data pool.
uint64_t alloc_data_block(data_pool_t *dp, uint32_t tid)
{
	if (dp->head == NULL)
		return 0;
	data_block_t *blk = dp->head;
	dp->head	  = blk->next;
	if (dp->head)
		dp->head->prev = NULL;
	blk->next = blk->prev = NULL;
	blk->tid	      = tid;
	dp->free_count--;

	if (blk->start_addr == 0) {
		sbi_printf(
			"[SBI] !!!ERROR!!! alloc_data_block(): start_addr is 0\n");
		return 0;
	}

	// Clean the allocated block before returning
	sbi_memset((void *)blk->start_addr, 0, blk->size);

	return blk->start_addr;
}

// Return a 2MB block to the data pool and keep the free list ordered by
// address.
static void free_data_block(data_pool_t *dp, data_block_t blocks_arr[],
			    int max_blocks, uint64_t addr)
{
	data_block_t *free_blk = NULL;
	// Scan the known blocks and locate the returned address.
	for (int i = 0; i < max_blocks; i++) {
		if (blocks_arr[i].start_addr == addr) {
			free_blk = &blocks_arr[i];
			break;
		}
	}
	if (!free_blk)
		return;

	// Insert the block while preserving address order.
	if (dp->head == NULL) {
		dp->head       = free_blk;
		free_blk->prev = free_blk->next = NULL;
		dp->free_count++;
		return;
	}
	data_block_t *cur  = dp->head;
	data_block_t *prev = NULL;
	while (cur && cur->start_addr < addr) {
		prev = cur;
		cur  = cur->next;
	}
	free_blk->next = cur;
	free_blk->prev = prev;
	if (cur)
		cur->prev = free_blk;
	if (prev)
		prev->next = free_blk;
	else
		dp->head = free_blk;
	free_blk->tid = DATA_BLOCK_FREE_TID;
	dp->free_count++;
}

void free_data_blocks_per_tid(data_pool_t *dp, uint32_t tid)
{
	data_block_t *cur;

	for (int i = 0; i < dp->total_count; i++) {
		cur = &data_blocks_arr[i];
		if (cur->tid == tid) {
			data_block_t *to_free = cur;
			free_data_block(dp, data_blocks_arr, dp->total_count,
					to_free->start_addr);
		}
	}
	tee_mem_status(dp);
}

// target_level: 0 for 4KB pages, 1 for 2MB huge pages.
pte_t *get_pte_entry(mem_pool_t *mp, pte_t *root_pt, uint64_t va, bool allocate,
		     int cvm_id, int target_level, uint8_t page_table_mode)
{
	pte_t *pt     = root_pt;
	int MAX_LEVEL = 0;
	// Read satp, check the mode (SV39/SV48/SV57)
	if (page_table_mode == HGATP_MODE_SV39X4) {
		MAX_LEVEL = 2; // SV39
	} else if (page_table_mode == HGATP_MODE_SV48X4) {
		MAX_LEVEL = 3; // SV48
	} else if (page_table_mode == HGATP_MODE_SV57X4) {
		MAX_LEVEL = 4; // SV57
	} else {
		sbi_printf(
			"[SBI] !!!ERROR!!! get_pte_entry(): invalid page_table_mode=%d\n",
			page_table_mode);
		return NULL;
	}

	zion_printf("[SM] get_pte_entry: Max level: %d\n", MAX_LEVEL);

	for (int level = MAX_LEVEL; level > target_level; level--) {

		uint64_t index = (va >> (PAGE_SHIFT + level * gstage_index_bits)) &
				 ZION_PTE_INDEX_MASK;

		pte_t *entry = &pt[index];
		if (!(*entry & PTE_V)) {
			if (!allocate)
				return NULL;
			pte_t *new_pt = alloc_pt_page(mp, cvm_id);
			if (!new_pt)
				return NULL;
			sbi_memset(new_pt, 0, PAGE_SIZE);
			*entry = (((uint64_t)new_pt >> PAGE_SHIFT)
				  << ZION_PTE_PPN_SHIFT) | PTE_V;
		}

		// A PTE with R/W/X bits set is already a leaf entry.
		if ((*entry) & (PTE_X | PTE_R | PTE_W)) {
			sbi_printf(
				"[SBI] !!!ERROR!!! get_pte_entry(): encountered leaf entry at level %d\n",
				level);
			return NULL;
		}

		// Bits 10..53 hold the PPN.
		pt = (pte_t *)(((uint64_t)((*entry) & ZION_PTE_ADDR_MASK) >>
				ZION_PTE_PPN_SHIFT)
			       << PAGE_SHIFT);
	}
	uint64_t index = (va >> (PAGE_SHIFT + target_level * gstage_index_bits)) &
			 ZION_PTE_INDEX_MASK;
	return &pt[index];
}

int map_gpa_to_hpa(mem_pool_t *mp, int cvm_id, uint64_t gpa, uint64_t hpa,
		   size_t size, bool huge_page, bool rdonly)
{

	pte_t *root_pt	= (pte_t *)get_cvm_root_pt(mp, cvm_id);
	uint8_t pt_mode = get_cvm_pt_mode(mp, cvm_id);
	if (!root_pt)
		return -1;

	if (hpa == 0) {
		hpa = alloc_data_block(&mp->data_pool, cvm_id);
		if (hpa == 0)
			return -1;
	}

	zion_printf(
		"[SBI] map_gpa_to_hpa(): gpa=%lx, hpa=%lx, size=%lx, huge_page=%d, pt_mode=%d\n",
		gpa, hpa, size, huge_page, pt_mode);

	size_t granularity = huge_page ? HUGE_PAGE_SIZE : PAGE_SIZE;
	int target_level   = huge_page ? 1 : 0;

	// Align GPA and HPA down to the selected mapping granularity.
	uint64_t aligned_gpa = gpa & ~(granularity - 1);
	uint64_t aligned_hpa = hpa ? (hpa & ~(granularity - 1)) : 0;

	size_t num_pages = size / granularity;
	for (size_t i = 0; i < num_pages; i++) {
		uint64_t cur_gpa = aligned_gpa + i * granularity;
		uint64_t cur_hpa = aligned_hpa + i * granularity;
		pte_t *pte = get_pte_entry(mp, root_pt, cur_gpa, true, cvm_id,
					   target_level, pt_mode);
		if (!pte)
			return -1;

		if (rdonly)
			*pte = ((cur_hpa >> PAGE_SHIFT)
				<< ZION_PTE_PPN_SHIFT) | PTE_V | PTE_R |
			       PTE_X | PTE_U | PTE_A | PTE_D;
		else
			*pte = ((cur_hpa >> PAGE_SHIFT)
				<< ZION_PTE_PPN_SHIFT) | PTE_V | PTE_R |
			       PTE_W | PTE_X | PTE_U | PTE_A | PTE_D;
	}
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
			sbi_printf(
				"[SM] TEE security check: No translation in %s page, pte: %lx\n",
				page_name, *pte);
		} else {
			sbi_printf(
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

	sbi_printf(
		"[SM] TEE security check: The hypervisor is trying to access the SM region\n");

	hpa += mtval & ZION_4K_PAGE_OFFSET_MASK;
	if (address_in_range(hpa, vcpu_start, vcpu_end)) {
		sbi_printf(
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

	sbi_printf(
		"[SM] TEE security check: the hypervisor is trying to r/w the protected region\n");
	sbi_printf("[SM] TEE security check: The physical address: %lx\n", hpa);

	if (address_in_range(hpa, protection_start, page_table_end)) {
		if (mcause == CAUSE_LOAD_ACCESS) {
			sbi_printf(
				"[SM] TEE security check: The hypervisor is trying to read the page table region\n");
		} else if (mcause == CAUSE_STORE_ACCESS) {
			sbi_printf(
				"[SM] TEE security check: The hypervisor is trying to write the page table region\n");
		}
		return;
	}

	if (mcause == CAUSE_LOAD_ACCESS) {
		sbi_printf(
			"[SM] TEE security check: The hypervisor is trying to read the CVM private memory\n");
	} else if (mcause == CAUSE_STORE_ACCESS) {
		sbi_printf(
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
	// Reserve PT_MEM_PER_CVM_MB MB per CVM for page tables.
	uint32_t pt_bytes_per_cvm = PT_MEM_PER_CVM_MB * MB;
	uint32_t pt_total_bytes	  = CVM_NUM * pt_bytes_per_cvm;
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

	sbi_printf(
		"[SM] TEE security check: Info: mtval=%lx, mcause=%lx, root_pt: %lx, mode: %lx\n",
		mtval, mcause, root_pt, mode);

	pte_t *pte = NULL;
	uint64_t hpa = 0;

	if (!resolve_hpa_for_security_check(root_pt, mode, mtval, &hpa, &pte))
		return;
	sbi_printf("[SM] The hpa: 0x%lx, with permission: %lx\n", hpa,
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
