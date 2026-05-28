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
#define MAX_DATA_BLOCKS 1024 * 32
#define ROOT_PT_PAGES 4 // Reserve 4 pages for each CVM root page table
#define MB (1024 * 1024)

#define DATA_BLOCK_FREE_TID ((uint32_t)-1)
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

#define CVM_NUM 4
#define PT_MEM_PER_CVM_MB 4

// Partial PTE flag definitions
#define PTE_V (1UL << 0) // Valid
#define PTE_R (1UL << 1) // Readable
#define PTE_W (1UL << 2) // Writable
#define PTE_X (1UL << 3) // Executable
#define PTE_U (1UL << 4)
#define PTE_A (1UL << 6)
#define PTE_D (1UL << 7)

typedef uint64_t pte_t;


typedef struct {
	uint8_t *base;	 // Sub-pool base address
	uint8_t pt_mode; // Page-table mode (for example, SBI_SV39_MODE)
	size_t size;	 // Sub-pool size in bytes
	size_t offset; // Current page allocation offset in PAGE_SIZE units, with ROOT_PT_PAGES reserved for the root page table
} pt_subpool_t;

// The page-table pool contains sub-pools for CVMs and Enclaves.
typedef struct {
	uint8_t *base; // Page-table pool base address
	size_t total_size; // Total size in bytes
	pt_subpool_t cvm[CVM_NUM]; // Per-CVM sub-pool metadata
	pt_subpool_t enclave[MAX_ENCLAVES]; // Per-Enclave sub-pool metadata
} pt_pool_t;

typedef struct data_block {
	uint64_t start_addr; // Block start physical address
	uint32_t tid;
	uint32_t size;		 // Fixed at 2MB
	struct data_block *prev; // Previous node
	struct data_block *next; // Next node
} data_block_t;

typedef struct {
	data_block_t *head; // Free data-block list head
	int free_count;	    // Current number of free blocks
	int total_count;    // Total number of blocks computed at init time
} data_pool_t;

typedef struct {
	uint8_t *base_addr;   // Backing memory pool base address
	uint32_t total_pages; // Total pages in PAGE_SIZE units

	pt_pool_t pt_pool;     // Page-table memory pool
	data_pool_t data_pool; // Data memory pool
} mem_pool_t;

extern mem_pool_t g_mem_pool;

uint64_t alloc_data_block(data_pool_t *dp, uint32_t tid);
void free_data_blocks_per_tid(data_pool_t *dp, uint32_t tid);
void *get_cvm_root_pt(mem_pool_t *mp, uint32_t cvm_id);
uint8_t get_cvm_pt_mode(mem_pool_t *mp, uint32_t cvm_id);
void set_cvm_pt_mode(mem_pool_t *mp, uint32_t cvm_id, uint8_t mode);
void reset_cvm_pt_pool(mem_pool_t *mp, uint32_t cvm_id);
pte_t *get_pte_entry(mem_pool_t *mp, pte_t *root_pt, uint64_t va, bool allocate,
		     int cvm_id, int target_level, uint8_t page_table_mode);
int map_gpa_to_hpa(mem_pool_t *mp, int cvm_id, uint64_t gpa, uint64_t hpa,
		   size_t size, bool huge_page, bool rdonly);
int tee_mem_init(uint8_t *mem_base, uint32_t n_page);
void tee_security_check(unsigned long mtval, unsigned long mcause,
			unsigned long raw_root_pt);

/* Enclave page table pool functions */
void *get_enclave_root_pt(mem_pool_t *mp, uint32_t enclave_id);
void reset_enclave_pt_pool(mem_pool_t *mp, uint32_t enclave_id);

#endif
