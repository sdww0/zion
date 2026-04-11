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
	unsigned long type = __info->start;
	unsigned long rid = __info->asid;
	unsigned long perm = __info->vmid;
	int ret;

	if (type == SBI_PMP_IPI_TYPE_SET) {
		ret = pmp_set_zion(rid, (uint8_t)perm);
	} else {
		ret = pmp_unset(rid);
	}

	if (ret) {
		sbi_printf("[SM] PMP IPI update failed: region_idx=%lu, type=%lu, perm=%lu, hart=%u, ret=%d\n",
			   rid, type, perm, current_hartid(), ret);
	}
}

void send_and_sync_pmp_ipi(int region_idx, int type, uint8_t perm)
{
	ulong mask	  = 0;
	ulong source_hart = current_hartid();
	struct sbi_tlb_info tlb_info;
	int ret;

	ret = sbi_hsm_hart_interruptible_mask(sbi_domain_thishart_ptr(), 0, &mask);
	if (ret) {
		sbi_printf("[SM] PMP IPI mask query failed: region_idx=%d, type=%d, perm=%u, hart=%lu, ret=%d\n",
			   region_idx, type, perm, source_hart, ret);
		return;
	}

	if (!mask)
		sbi_printf("[SM] PMP IPI warning: empty interruptible mask on hart=%lu\n",
			   source_hart);

	SBI_TLB_INFO_INIT(&tlb_info, type, 0, region_idx, perm,
			  SBI_PMP_IPI_LOCAL_UPDATE, source_hart);
	ret = sbi_tlb_request(mask, 0, &tlb_info);
	if (ret) {
		sbi_printf("[SM] PMP IPI request failed: region_idx=%d, type=%d, perm=%u, hart=%lu, mask=0x%lx, ret=%d\n",
			   region_idx, type, perm, source_hart, mask, ret);
	}
}
