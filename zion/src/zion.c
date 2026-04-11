
#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/riscv_barrier.h>
#include <sbi/riscv_asm.h>
#include "ree.h"
#include "sm.h"
#include "tee.h"

extern struct sbi_ecall_extension ecall_cvm;

static int zion_init_done = 0;

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

		/*
		 * Legacy SMM/OSM regions used Zion's own static PMP allocator.
		 * The current flow leaves boot-time PMP ownership to OpenSBI and
		 * installs the TVM private-memory window only after the host
		 * reserves it through SBI_SM_RESERVE_MEM.
		 */
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

	/* Per-hart counters are enabled after cold-boot metadata is ready. */
	zion_enable_counters();

	if (cold_boot)
		sbi_printf("[SBI] Zion security monitor initialized\n");
}
