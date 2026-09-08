#ifndef __TEE_MEM_H__
#define __TEE_MEM_H__

#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_types.h>
#include <sbi/riscv_locks.h>
#include "zion.h"

#define gstage_index_bits 9
#define CVM_GSTAGE_MODE HGATP_MODE_SV48X4

#define GSTAGE_MODE ((unsigned long)CVM_GSTAGE_MODE << HGATP_MODE_SHIFT)

#define RISCV_PGSIZE PAGE_SIZE

#define HUGE_PAGE_SIZE (2 * 1024 * 1024) // 2MB huge page
#define BLOCK_SIZE HUGE_PAGE_SIZE
/* Keep allocator metadata inside the 2 MiB monitor image. With 2 MiB data
 * blocks this still supports up to 8 GiB of online trusted data. */
#define MAX_DATA_BLOCKS (4 * 1024)
#define MAX_TRUSTED_EXTENTS 4
#define TRUSTED_CORE_EXTENT_ID 0
#define DATA_BLOCK_INVALID_EXTENT ((uint32_t)-1)
#define MB (1024 * 1024)

#define DATA_BLOCK_FREE_OWNER       ((uint32_t)-1)
#define DATA_BLOCK_RECLAIMING_OWNER ((uint32_t)-2)
#define DATA_BLOCK_ALLOCATING_OWNER ((uint32_t)-3)
#define DATA_BLOCK_CVM_OWNER(id)     ((uint32_t)(id))
#define DATA_BLOCK_ENCLAVE_OWNER(id) (0x80000000U | (uint32_t)(id))
#define ZION_PTE_PPN_SHIFT 10
#define ZION_PTE_ADDR_MASK 0x3FFFFFFFFFFC00ULL
#define ZION_PTE_FLAG_MASK ((1UL << ZION_PTE_PPN_SHIFT) - 1)
#define ZION_PTE_INDEX_MASK ((1UL << gstage_index_bits) - 1)
#define CVM_ROOT_PT_INDEX_BITS (gstage_index_bits + 2)
#define CVM_ROOT_PT_INDEX_SHIFT (PAGE_SHIFT + 2 * gstage_index_bits)
#define CVM_ROOT_PT_INDEX_MASK ((1UL << CVM_ROOT_PT_INDEX_BITS) - 1)
#define ZION_4K_PAGE_OFFSET_MASK (PAGE_SIZE - 1)
#define ZION_2M_PAGE_OFFSET_MASK (HUGE_PAGE_SIZE - 1)
#define ZION_1G_PAGE_OFFSET_MASK ((1UL << CVM_ROOT_PT_INDEX_SHIFT) - 1)
#define ZION_SATP_PPN_MASK 0xFFFFFFFFFFFULL
#define ZION_SATP_MODE_SHIFT 60
#define ZION_SATP_MODE_MASK 0xFULL

#if BLOCK_SIZE == HUGE_PAGE_SIZE
#define IS_HUGE_PAGE true
#else
#define IS_HUGE_PAGE false
#endif

/* Sixteen CVM owner slots are exposed by the monitor.  The recovery regression
 * boots two full guests concurrently and verifies all 16 management slots via
 * scratch CVM creation.  Page-table pages are allocated on demand from the
 * shared PT pool below. */
#define CVM_NUM 16
#define ROOT_PT_PAGES 4 /* Sv48x4 root table: 2048 entries == 16 KiB. */
#define PT_OWNER_COUNT (CVM_NUM + MAX_ENCLAVES)
#define PT_POOL_DYNAMIC_MB 8
#define PT_POOL_MAX_PAGES ((PT_POOL_DYNAMIC_MB * MB) / PAGE_SIZE)
#define PT_OWNER_INVALID ((uint32_t)-1)

// Partial PTE flag definitions
#define PTE_V (1UL << 0) // Valid
#define PTE_R (1UL << 1) // Readable
#define PTE_W (1UL << 2) // Writable
#define PTE_X (1UL << 3) // Executable
#define PTE_U (1UL << 4)
#define PTE_A (1UL << 6)
#define PTE_D (1UL << 7)
#define PTE_LEAF_PERM_MASK (PTE_R | PTE_W | PTE_X | PTE_U)

typedef uint64_t pte_t;

typedef enum {
	TRUSTED_EXTENT_FREE = 0,
	TRUSTED_EXTENT_PREPARING,
	TRUSTED_EXTENT_ONLINE,
	TRUSTED_EXTENT_DRAINING,
	TRUSTED_EXTENT_REMOVING,
} trusted_extent_state_t;

typedef struct {
	uint64_t base;
	uint64_t size;
	uint64_t data_base;
	uint64_t data_size;
	uint32_t id;
	uint32_t generation;
	uint32_t state;
	uint32_t total_blocks;
	uint32_t free_blocks;
	int32_t pmp_region_id;
} tee_mem_extent_info_t;

typedef struct {
	tee_mem_extent_info_t info;
	uint32_t first_block;
	bool is_core;
} trusted_extent_t;


typedef struct {
	uint8_t *base;   /* 16 KiB-aligned root table base. */
	uint8_t pt_mode;
	bool in_use;
} pt_root_slot_t;

/* Shared page-table pool.  Each possible owner has a tiny root slot; all
 * intermediate page-table pages are allocated from one owner-tagged pool and
 * returned on owner reset. */
typedef struct {
	uint8_t *base; // Page-table pool base address
	size_t total_size; // Total size in bytes
	size_t total_pages;
	size_t mid_start_page;
	pt_root_slot_t roots[PT_OWNER_COUNT];
	uint32_t page_owner[PT_POOL_MAX_PAGES];
} pt_pool_t;

typedef struct data_block {
	uint64_t start_addr; // Block start physical address
	uint32_t owner;
	uint32_t pending_owner;
	uint32_t size;		 // Fixed at 2MB
	uint32_t extent_id;
	struct data_block *prev; // Previous node
	struct data_block *next; // Next node
	struct data_block *owner_prev;
	struct data_block *owner_next;
} data_block_t;

typedef struct {
	data_block_t *head; // Free data-block list head
	data_block_t *owner_heads[CVM_NUM + MAX_ENCLAVES];
	data_block_t *blocks;
	int free_count;	    // Current number of free blocks
	int total_count;    // Total number of blocks computed at init time
	int max_blocks;
	trusted_extent_t *extents;
} data_pool_t;

typedef struct {
	uint8_t *base_addr;   // Backing memory pool base address
	size_t total_pages; // Total pages in PAGE_SIZE units

	pt_pool_t pt_pool;     // Page-table memory pool
	data_pool_t data_pool; // Data memory pool
	trusted_extent_t extents[MAX_TRUSTED_EXTENTS];
	uint32_t next_extent_generation;
} mem_pool_t;

extern mem_pool_t g_mem_pool;

uint64_t alloc_data_block(data_pool_t *dp, uint32_t owner);
void free_data_blocks_per_owner(data_pool_t *dp, uint32_t owner);
bool data_block_owned_range(data_pool_t *dp, uint64_t hpa, uint32_t owner,
			    size_t *contiguous);
void *get_cvm_root_pt(mem_pool_t *mp, uint32_t cvm_id);
void *alloc_cvm_root_pt(mem_pool_t *mp, uint32_t cvm_id);
uint8_t get_cvm_pt_mode(mem_pool_t *mp, uint32_t cvm_id);
void set_cvm_pt_mode(mem_pool_t *mp, uint32_t cvm_id, uint8_t mode);
void reset_cvm_pt_pool(mem_pool_t *mp, uint32_t cvm_id);
bool cvm_pt_page_owned_by(mem_pool_t *mp, uint32_t cvm_id, uint64_t address);
pte_t *get_pte_entry(mem_pool_t *mp, pte_t *root_pt, uint64_t va, bool allocate,
			     int cvm_id, int target_level, uint8_t page_table_mode);
int map_gpa_to_hpa(mem_pool_t *mp, int cvm_id, uint64_t gpa, uint64_t hpa,
		   size_t size, int target_level, uint64_t permissions);
int remap_gpa_to_hpa(mem_pool_t *mp, int cvm_id, uint64_t gpa, uint64_t hpa,
		     size_t size, int target_level, uint64_t permissions);
int tee_mem_init(uint8_t *mem_base, size_t n_page);
int tee_mem_set_core_pmp_region(int pmp_region_id);
int tee_mem_validate_new_extent(uint64_t base, size_t size);
int tee_mem_add_extent(uint64_t base, size_t size, int pmp_region_id,
		       uint32_t *extent_id);
int tee_mem_prepare_remove_extent(uint32_t extent_id,
				  tee_mem_extent_info_t *info);
void tee_mem_cancel_remove_extent(uint32_t extent_id);
void tee_mem_finish_remove_extent(uint32_t extent_id);
int tee_mem_query_extent(uint32_t extent_id, tee_mem_extent_info_t *info);

void tee_mem_context_enter_begin(void);
void tee_mem_context_enter_end(void);
void tee_mem_context_exit_begin(void);
void tee_mem_context_exit_end(void);
int tee_mem_maintenance_begin(void);
void tee_mem_maintenance_end(void);
int tee_mem_set_local_pmp_permissions(uint8_t permissions);
int tee_mem_replay_local_pmp_permissions(uint8_t permissions);
void tee_security_check(unsigned long mtval, unsigned long mcause,
			unsigned long raw_root_pt);

/* Enclave page table pool functions */
void *get_enclave_root_pt(mem_pool_t *mp, uint32_t enclave_id);
void *alloc_enclave_root_pt(mem_pool_t *mp, uint32_t enclave_id);
void reset_enclave_pt_pool(mem_pool_t *mp, uint32_t enclave_id);

#endif
