
#include "sm.h"
#include "pmp.h"

int smm_init()
{
	sbi_printf("[SM] smm_init(): base=%lx, size=%lx\n",
		   (unsigned long)SMM_BASE, (unsigned long)SMM_SIZE);
	int region = -1;
	int ret	   = pmp_region_init_atomic(SMM_BASE, SMM_SIZE, PMP_PRI_TOP,
					    &region, 0);
	if (ret) {
		sbi_printf(
			"[SM] smm_init(): pmp_region_init_atomic() failed, ret: %d\n",
			ret);
		return -1;
	}

	return region;
}

void sm_metadata_init()
{
}
