#ifndef _PMP_H_
#define _PMP_H_

#include <sbi/riscv_atomic.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_console.h>

enum pmp_priority {
	PMP_PRI_ANY,
};

#define PMP_ALL_PERM (PMP_W | PMP_X | PMP_R)
#define PMP_NO_PERM 0

typedef int region_id;

void pmp_init(void);
int pmp_region_init_atomic(uintptr_t start, uint64_t size,
			   enum pmp_priority pri, region_id *rid,
			   int allow_overlap);
int pmp_region_init(uintptr_t start, uint64_t size, enum pmp_priority pri,
		    region_id *rid, int allow_overlap);
int pmp_region_free_atomic(region_id region);
int pmp_set_zion(region_id region, uint8_t perm);
int pmp_set_global(region_id region, uint8_t perm);
int pmp_unset(region_id region);
int pmp_unset_global(region_id region);
int pmp_detect_region_overlap_atomic(uintptr_t base, uintptr_t size);
void handle_pmp_ipi(void);

uintptr_t pmp_region_get_addr(region_id region);
uint64_t pmp_region_get_size(region_id region);

#endif
