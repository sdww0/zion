/* Zion enclave core. */
#include <sbi/sbi_fifo.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_hsm.h>
#include <sbi/sbi_domain.h>
#include "ipi.h"
#include "pmp.h"
#include "zion.h"

void sbi_pmp_ipi_local_update(struct sbi_tlb_info *info)
{
	int action = (int)info->start;
	int region_idx = (int)info->asid;
	uint8_t perm = (uint8_t)info->vmid;

	if (action == SBI_PMP_IPI_TYPE_SET)
		pmp_set_zion(region_idx, perm);
	else if (action == SBI_PMP_IPI_TYPE_UNSET)
		pmp_unset(region_idx);

	zion_printf("[SM] PMP sync: hart=%u region=%d action=%d perm=0x%x\n",
		    current_hartid(), region_idx, action, perm);
}

int send_and_sync_pmp_ipi(int region_idx, int type, uint8_t perm)
{
	ulong mask = 0;
	ulong source_hart = current_hartid();
	struct sbi_tlb_info tlb_info;
	int ret;

	if (type != SBI_PMP_IPI_TYPE_SET && type != SBI_PMP_IPI_TYPE_UNSET)
		return SBI_EINVAL;

	ret = sbi_hsm_hart_interruptible_mask(sbi_domain_thishart_ptr(), 0,
					       &mask);
	if (ret)
		return ret;

	/* The OpenSBI TLB IPI path already provides a per-hart FIFO and a
	 * synchronous completion counter.  Encode the compact PMP command in
	 * fields which survive an ordinary sbi_tlb_info copy. */
	SBI_TLB_INFO_INIT(&tlb_info, (unsigned long)type, 0,
			  (uint16_t)region_idx, (uint16_t)perm,
			  SBI_PMP_IPI_LOCAL_UPDATE, source_hart);

	ret = sbi_tlb_request(mask, 0, &tlb_info);

	return ret;
}
