
#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/riscv_barrier.h>
#include <sbi/riscv_asm.h>
#include "ree.h"
#include "sm.h"
#include "tee.h"

extern struct sbi_ecall_extension ecall_cvm;

static int zion_init_done = 0;

#define ZION_ANSI_RESET  "\033[0m"
#define ZION_ANSI_RED    "\033[1;31m"
#define ZION_ANSI_YELLOW "\033[1;33m"
#define ZION_ANSI_CYAN   "\033[1;36m"
#define ZION_ANSI_GREEN  "\033[1;32m"
#define ZION_ANSI_BLUE   "\033[1;34m"
#define ZION_ANSI_WHITE  "\033[1;37m"

static void zion_print_logo(void)
{
	sbi_printf("\n");
	sbi_printf(ZION_ANSI_RED
		   "#########"
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_YELLOW
		   "*********"
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_CYAN
		   " @@@@@@@ "
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_GREEN
		   "&&     &&"
		   ZION_ANSI_RESET "\n");
	sbi_printf(ZION_ANSI_RED
		   "      ###"
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_YELLOW
		   "   ***   "
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_CYAN
		   "@@     @@"
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_GREEN
		   "&&&    &&"
		   ZION_ANSI_RESET "\n");
	sbi_printf(ZION_ANSI_RED
		   "    ###  "
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_YELLOW
		   "   ***   "
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_CYAN
		   "@@     @@"
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_GREEN
		   "&& &&  &&"
		   ZION_ANSI_RESET "\n");
	sbi_printf(ZION_ANSI_RED
		   "  ###    "
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_YELLOW
		   "   ***   "
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_CYAN
		   "@@     @@"
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_GREEN
		   "&&  && &&"
		   ZION_ANSI_RESET "\n");
	sbi_printf(ZION_ANSI_RED
		   "#########"
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_YELLOW
		   "*********"
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_CYAN
		   " @@@@@@@ "
		   ZION_ANSI_RESET "   "
		   ZION_ANSI_GREEN
		   "&&    &&&"
		   ZION_ANSI_RESET "\n");
	sbi_printf("\n");
}

static void zion_print_banner(unsigned long hartid)
{
	sbi_printf(ZION_ANSI_BLUE
		   " ============================================================\n"
		   ZION_ANSI_RESET);
	sbi_printf(ZION_ANSI_WHITE
		   "   RISC-V TRUSTED EXECUTION ENVIRONMENT\n"
		   ZION_ANSI_RESET);
	sbi_printf(ZION_ANSI_BLUE
		   " ============================================================\n"
		   ZION_ANSI_RESET);
	sbi_printf(" " ZION_ANSI_RED
		   "> Monitor   "
		   ZION_ANSI_RESET
		   ": Zion security monitor on OpenSBI\n");
	sbi_printf(" " ZION_ANSI_YELLOW
		   "> Isolation "
		   ZION_ANSI_RESET
		   ": PMP-guarded protected memory across harts\n");
	sbi_printf(" " ZION_ANSI_CYAN
		   "> Memory    "
		   ZION_ANSI_RESET
		   ": CVM G-stage Sv48x4 with 2MB private blocks\n");
	// sbi_printf(" " ZION_ANSI_GREEN
	// 	   "> Measure   "
	// 	   ZION_ANSI_RESET
	// 	   ": SHA3-512 hashing and Ed25519 signing\n");
	// sbi_printf(" " ZION_ANSI_RED
	// 	   "> Capacity  "
	// 	   ZION_ANSI_RESET
	// 	   ": 16 CVMs | 4 vCPUs/CVM | 48 TEE threads\n");
	sbi_printf(" " ZION_ANSI_GREEN
		   "> SBI       "
		   ZION_ANSI_RESET
		   ": experimental extension 0x%08x\n",
		   SBI_EXT_EXPERIMENTAL_zion);
	sbi_printf(" " ZION_ANSI_CYAN
		   "> Boot Hart "
		   ZION_ANSI_RESET
		   ": %lu | counters: cycle/time/instret\n",
		   hartid);
	sbi_printf(ZION_ANSI_BLUE
		   " ============================================================\n"
		   ZION_ANSI_RESET);
	sbi_printf("\n");
}

void zion_enable_counters(void)
{
	csr_write(CSR_MCOUNTINHIBIT, 0);
	csr_write(CSR_MCOUNTEREN, ZION_COUNTER_ENABLE_MASK);
	csr_write(CSR_SCOUNTEREN, ZION_COUNTER_ENABLE_MASK);
}

void zion_init(bool cold_boot)
{
	if (cold_boot) {
		unsigned long hartid = csr_read(mhartid);

		/* only the cold-booting hart will execute these */
		sbi_printf("[SBI] Initializing ... hart [%lx]\n",
			   hartid);
		zion_print_logo();
		zion_print_banner(hartid);

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
