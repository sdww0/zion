#ifndef __PMP_IPI_H__
#define __PMP_IPI_H__

#include <sbi/sbi_scratch.h>
#include <sbi/sbi_hartmask.h>
#include <sbi/sbi_tlb.h>

#define SBI_PMP_IPI_TYPE_SET    0
#define SBI_PMP_IPI_TYPE_UNSET  1

void sbi_pmp_ipi_local_update(struct sbi_tlb_info *info);

int send_and_sync_pmp_ipi(int region_idx, int type, uint8_t perm);
#endif
