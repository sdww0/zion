#include <sbi/sbi_fifo.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hsm.h>
#include <sbi/sbi_domain.h>
#include "ipi.h"
#include "pmp.h"

void sbi_pmp_ipi_local_update(struct sbi_tlb_info *__info)
{
  struct sbi_pmp_ipi_info* info = (struct sbi_pmp_ipi_info *) __info;
  if (info->type == SBI_PMP_IPI_TYPE_SET) {
    pmp_set_keystone(info->rid, (uint8_t) info->perm);
  } else {
    pmp_unset(info->rid);
  }
}

void send_and_sync_pmp_ipi(int region_idx, int type, uint8_t perm)
{
  ulong mask = 0;
  ulong source_hart = current_hartid();
  struct sbi_tlb_info tlb_info;
  struct sbi_pmp_ipi_info *pmp_info = (struct sbi_pmp_ipi_info *)&tlb_info;
  pmp_info->type = type;
  pmp_info->rid = region_idx;
  pmp_info->perm = perm;
  sbi_hsm_hart_interruptible_mask(sbi_domain_thishart_ptr(), 0, &mask);

  /* v1.5 compat: TLB IPI API incompatible with v1.1.
   * Do local PMP update only (multi-hart IPI not implemented). */
  sbi_pmp_ipi_local_update(&tlb_info);
}

