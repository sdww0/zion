
#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/riscv_barrier.h>
#include <sbi/riscv_asm.h>
#include "pmp.h"
#include "ree.h"
#include "sm.h"
#include "tee.h"

extern struct sbi_ecall_extension ecall_cvm;

static int zion_init_done = 0;
static int sm_region_id = 0, os_region_id = 0;

void zion_enable_counters(void)
{
	csr_write(CSR_MCOUNTINHIBIT, 0);
	csr_write(CSR_MCOUNTEREN, ZION_COUNTER_ENABLE_MASK);
	csr_write(CSR_SCOUNTEREN, ZION_COUNTER_ENABLE_MASK);
}

void zion_init(bool cold_boot)
{
	if (cold_boot) {
		/* only the cold-booting hart will execute these */
		sbi_printf("[SBI] Initializing ... hart [%lx]\n",
			   csr_read(mhartid));

		sbi_ecall_register_extension(&ecall_cvm);

		sm_region_id = smm_init();
		os_region_id = osm_init();

		if (os_region_id < 0) {
			sbi_printf("[SM] !!! osm_init() failed");
			sbi_hart_hang();
		}

		if (sm_region_id < 0 || os_region_id < 0) {
			sbi_printf("[SM] !!! smm_init() or osm_init() failed");
			sbi_hart_hang();
		}
		sbi_printf("[SM] smm_init() succeeded: region_id=%d\n",
			   sm_region_id);
		sbi_printf("[SM] osm_init() succeeded: region_id=%d\n",
			   os_region_id);

		sm_metadata_init();
		ree_metadata_init();
		tee_metadata_init();

		zion_init_done = 1;

		mb();
	}

	/* wait until cold-boot hart finishes */
	while (!zion_init_done) {
		mb();
	}

	/* below are executed by all harts */
	pmp_init();
	pmp_set_zion(os_region_id, PMP_ALL_PERM);
	pmp_set_zion(sm_region_id, PMP_NO_PERM);

	zion_enable_counters();

	sbi_printf("[SBI] Zion security monitor has been initialized!\n");
}
