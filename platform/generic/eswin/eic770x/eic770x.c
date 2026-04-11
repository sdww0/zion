#include <platform_override.h>
#include <sbi_utils/fdt/fdt_helper.h>
#include <sbi_utils/serial/uart8250.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_io.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_system.h>
#include <sbi/sbi_timer.h>

#ifdef CONFIG_PLATFORM_ESWIN_EIC7700
#define BR2_CHIPLET_1
#define BR2_CHIPLET_1_DIE0_AVAILABLE
#endif

/* Full tlb flush always */
#define EIC770X_TLB_RANGE_FLUSH_LIMIT	0

#ifdef BR2_CHIPLET_1
#ifdef BR2_CHIPLET_1_DIE0_AVAILABLE
#define	DIE_REG_OFFSET				0
#else
#define	DIE_REG_OFFSET				0x20000000
#endif
#else //BR2_CHIPLET_2
#define	DIE_REG_OFFSET				0
#endif

#define EIC770X_UART_RESET_ADDR			(0x51828434UL + DIE_REG_OFFSET)
#define EIC770X_UART2_ADDR				(0x50920000UL + DIE_REG_OFFSET)
#define EIC770X_UART_CLK       (200000000UL)
#define EIC770X_UART_BAUDRATE			115200

/* system reset register */
#define EIC770X_SYS_RESET_ADDR	0x51828300UL
#define EIC770X_SYS_RESET_VALUE	0x1ac0ffe6

#define FRAME_DATA_MAX 250

typedef struct {
	uint32_t header;	// Frame heade
	uint32_t xTaskToNotify; // id
	uint8_t msg_type; 	// Message type
	uint8_t cmd_type; 	// Command type
	uint8_t cmd_result;  // command result
	uint8_t data_len; 	// Data length
	uint8_t data[FRAME_DATA_MAX]; // Data
	uint8_t checksum; 	// Checksum
	uint32_t tail;			// Frame tail
} __attribute__((packed)) Message;

typedef enum {
	MSG_REQUEST = 0x01,
	MSG_REPLY,
	MSG_NOTIFLY,
} MsgType;

// Define command types
typedef enum {
	CMD_POWER_OFF = 0x01,
	CMD_RESET = 0x02,
	CMD_READ_BOARD_INFO = 0x03,
	CMD_CONTROL_LED = 0x04,
	CMD_PVT_INFO,
	CMD_BOARD_STATUS,
	CMD_POWER_INFO,
	CMD_RESTART,    //cold reboot with power off/on
	// You can continue adding other command types
} CommandType;

struct uart8250_device mcu_uart_dev;
static spinlock_t mcu_uart_lock = SPIN_LOCK_INITIALIZER;

static int transmit_message(Message *msg)
{
	static int inited = 0;
	unsigned char checksum = 0;
	char *p = (char*)msg;
	unsigned len = sizeof(*msg);

	if (!inited) {
		writeb(0x1B, (volatile void *)EIC770X_UART_RESET_ADDR);
		writeb(0x1F, (volatile void *)EIC770X_UART_RESET_ADDR);
		uart8250_init(&mcu_uart_dev,
				EIC770X_UART2_ADDR,
				EIC770X_UART_CLK,
				EIC770X_UART_BAUDRATE,
				2, 2, 0);
		inited = 1;
	}

	msg->header = 0xA55AAA55;
	msg->tail = 0xBDBABDBA;
	checksum ^= msg->msg_type;
	checksum ^= msg->cmd_type;
	checksum ^= msg->data_len;
	for (int i = 0; i < FRAME_DATA_MAX; ++i) {
		if (i < msg->data_len)
			checksum ^= msg->data[i];
		else
			msg->data[i] = 0;
	}
	msg->checksum = checksum;

	spin_lock(&mcu_uart_lock);
	while (len--) {
		uart8250_putc(&mcu_uart_dev, *p);
		p++;
	}
	spin_unlock(&mcu_uart_lock);

	return 0;
}

static int eic770x_core_shutdown(void)
{
	Message shutdown_reply = {
		.msg_type = MSG_NOTIFLY,
		.cmd_type = CMD_POWER_OFF,
		.data_len = 0x0,
	};
	transmit_message(&shutdown_reply);
	return 0;
};

static int eic770x_cold_reset(void)
{
	Message shutdown_reply = {
		.msg_type = MSG_NOTIFLY,
		.cmd_type = CMD_RESTART,
		.data_len = 0x0,
	};
	transmit_message(&shutdown_reply);
	sbi_timer_mdelay(3000);
	/*When it is not a DVB board, reboot can still be done, but there is no real power off/power on action at that time.*/
	writel(EIC770X_SYS_RESET_VALUE, (volatile void *)EIC770X_SYS_RESET_ADDR);
	return 0;
};

static int eic770x_core_reset(void)
{
	writel(EIC770X_SYS_RESET_VALUE, (volatile void *)EIC770X_SYS_RESET_ADDR);
	return 0;
}

static int eic770x_system_reset_check(u32 type, u32 reason)
{
	switch (type) {
	case SBI_SRST_RESET_TYPE_SHUTDOWN:
	case SBI_SRST_RESET_TYPE_COLD_REBOOT:
	case SBI_SRST_RESET_TYPE_WARM_REBOOT:
		return 1;
	}

	return 0;
}

static void eic770x_system_reset(u32 type, u32 reason)
{
	switch (type) {
	case SBI_SRST_RESET_TYPE_SHUTDOWN:
		eic770x_core_shutdown();
		break;
	case SBI_SRST_RESET_TYPE_COLD_REBOOT:
		eic770x_cold_reset();
		break;
	case SBI_SRST_RESET_TYPE_WARM_REBOOT:
		eic770x_core_reset();
		break;
	}

	sbi_hart_hang();
}

static struct sbi_system_reset_device eic770x_reset = {
	.name = "eswin_eic770x_reset",
	.system_reset_check = eic770x_system_reset_check,
	.system_reset = eic770x_system_reset
};

static u64 eic770x_get_tlbr_flush_limit(const struct fdt_match *match)
{
	return EIC770X_TLB_RANGE_FLUSH_LIMIT;
}

static void eic770x_fw_init(void *fdt, const struct fdt_match *match)
{
/*
 * CONFIG_BR2_CHIPLE_2 can currently be defined in platform/generic/eswin/eic770x/Kconfig
 * and can be obtained through fdt in the future
 */
#if BR2_CHIPLE_2
	unsigned long fw_text_start_addr;

	// set die1 u84 boot addr
	fw_text_start_addr = FW_TEXT_START;
	writel(fw_text_start_addr>>32, (void *)(0x71828000UL + 0x31c));
	writel(fw_text_start_addr&0xfffffffful, (void *)(0x71828000UL + 0x320));
	writel(fw_text_start_addr>>32, (void *)(0x71828000UL + 0x324));
	writel(fw_text_start_addr&0xfffffffful, (void *)(0x71828000UL + 0x328));
	writel(fw_text_start_addr>>32, (void *)(0x71828000UL + 0x32c));
	writel(fw_text_start_addr&0xfffffffful, (void *)(0x71828000UL + 0x330));
	writel(fw_text_start_addr>>32, (void *)(0x71828000UL + 0x334));
	writel(fw_text_start_addr&0xfffffffful, (void *)(0x71828000UL + 0x338));
	writel(0xfffffffful, (void *)(0x71828000UL + 0x44c));  //release die1 u84
#endif
}

static int eic770x_nascent_init(void)
{
	unsigned long hwpf;
	hwpf = 0x104095C1BE241UL;
	__asm__ volatile("csrw 0x7c3 , %0" : : "r"(hwpf));
	hwpf = 0x38c84eUL;
	__asm__ volatile("csrw 0x7c4 , %0" : : "r"(hwpf));
	return 0;
}


static void init_fcsr(void)
{
	unsigned long hwpf;

	/* enable speculative icache refill */
	hwpf = 0x4000UL;	// [14]	Disable Indirect-Jump Target Predictor
	__asm__ volatile("csrw 0x7c1 , %0" : : "r"(hwpf));

	hwpf = 0x80UL;	// [7]	Force Noisy Evict to send release message from any valid coherence permission state
	__asm__ volatile("csrw 0x7c2 , %0" : : "r"(hwpf));

	hwpf = 0x104095C1BE241UL;
	__asm__ volatile("csrw 0x7c3 , %0" : : "r"(hwpf));

	hwpf = 0x929FUL;
	//cleanup fields
	hwpf &= (~(0x1f << 5)); //[9:5]  cleanup  hitCacheThrdL2
	hwpf &= (~(0x7  << 14)); //[16:14] cleanup numL2PFIssQEnt

	//set new value
	hwpf |= (0x1f << 5); //[9:5]    hitCacheThrdL2
	hwpf |= (0x7  << 14); //[16:14] numL2PFIssQEnt
	__asm__ volatile("csrw 0x7c4 , %0" : : "r"(hwpf));
}

#ifndef BR2_CHIPLET_2
static void init_bus_blocker(void)
{
#if (defined BR2_CHIPLET_1) && (defined BR2_CHIPLET_1_DIE0_AVAILABLE)
	#define BLOCKER_TL64D2D_OUT	(void *)0x200000
	#define BLOCKER_TL256D2D_OUT	(void *)0x202000
	#define BLOCKER_TL256D2D_IN	(void *)0x204000
	writel(1,BLOCKER_TL64D2D_OUT);
	writel(1,BLOCKER_TL256D2D_OUT);
	writel(1,BLOCKER_TL256D2D_IN);
#elif (defined BR2_CHIPLET_1) && (defined BR2_CHIPLET_1_DIE1_AVAILABLE)
	#define BLOCKER_TL64D2D_OUT	(void *)(0x200000+0x20000000)
	#define BLOCKER_TL256D2D_OUT	(void *)(0x202000+0x20000000)
	#define BLOCKER_TL256D2D_IN	(void *)(0x204000+0x20000000)
	writel(1,BLOCKER_TL64D2D_OUT);
	writel(1,BLOCKER_TL256D2D_OUT);
	writel(1,BLOCKER_TL256D2D_IN);
#endif
}
#endif

static void sbi_hart_blocker_fscr_configure(struct sbi_scratch *scratch)
{
	struct sbi_domain *dom = sbi_domain_thishart_ptr();

	if (dom->boot_hartid == current_hartid()) {
		#ifndef BR2_CHIPLET_2
		/* if only one die, need config blocker to
		generate fake response when access remote target */
		init_bus_blocker();
		#endif
	}

	init_fcsr();
}

static int eic770x_early_init(bool cold_boot, const struct fdt_match *match)
{
	struct sbi_domain_memregion reg;
	if (cold_boot) {
		sbi_system_reset_add_device(&eic770x_reset);

	#if defined(BR2_CHIPLET_1_DIE0_AVAILABLE) && defined(BR2_CHIPLET_1)
		sbi_domain_memregion_init(0x2000000UL, 0xbfffUL, (SBI_DOMAIN_MEMREGION_MMIO |
					   SBI_DOMAIN_MEMREGION_M_READABLE |
					   SBI_DOMAIN_MEMREGION_M_WRITABLE), &reg);
		sbi_domain_root_add_memregion(&reg);
		sbi_domain_memregion_init_tor(0x1000000000UL, 0x7000000000UL,
			SBI_DOMAIN_MEMREGION_ENF_PERMISSIONS, &reg);
		sbi_domain_root_add_memregion(&reg);
		/*
		 * Leave room for Zion's dynamic TOR PMP pair. The uncached
		 * window consumes two locked entries on EIC7700 and prevents
		 * runtime secure-region updates from landing on writable PMPs.
		 */
		
		// sbi_domain_memregion_init_tor(0xc000000000UL, 0x1000000000UL,
		// 	SBI_DOMAIN_MEMREGION_SU_READABLE |
		// 	SBI_DOMAIN_MEMREGION_SU_WRITABLE |
		// 	SBI_DOMAIN_MEMREGION_ENF_PERMISSIONS, &reg);
		// sbi_domain_root_add_memregion(&reg);
	#elif defined(BR2_CHIPLET_1_DIE1_AVAILABLE) && defined(BR2_CHIPLET_1)
		sbi_domain_memregion_init(0x22000000UL, 0xbfffUL, (SBI_DOMAIN_MEMREGION_MMIO |
					   SBI_DOMAIN_MEMREGION_M_READABLE |
					   SBI_DOMAIN_MEMREGION_M_WRITABLE), &reg);
		sbi_domain_root_add_memregion(&reg);
		sbi_domain_memregion_init_tor(0x80000000UL, 0x1f80000000UL,
			SBI_DOMAIN_MEMREGION_ENF_PERMISSIONS, &reg);
		sbi_domain_root_add_memregion(&reg);
		sbi_domain_memregion_init_tor(0x3000000000UL, 0x5000000000UL,
			SBI_DOMAIN_MEMREGION_ENF_PERMISSIONS, &reg);
		sbi_domain_root_add_memregion(&reg);
#elif defined(BR2_CHIPLET_2)
		sbi_domain_memregion_init_tor(0x1000000000UL, 0x1000000000UL,
			SBI_DOMAIN_MEMREGION_ENF_PERMISSIONS, &reg);
		sbi_domain_root_add_memregion(&reg);
		sbi_domain_memregion_init_tor(0x3000000000UL, 0x1000000000UL,
			SBI_DOMAIN_MEMREGION_ENF_PERMISSIONS, &reg);
		sbi_domain_root_add_memregion(&reg);
		sbi_domain_memregion_init_tor(0x6000000000UL, 0x2000000000UL,
			SBI_DOMAIN_MEMREGION_ENF_PERMISSIONS, &reg);
		sbi_domain_root_add_memregion(&reg);
#endif
	}
	return 0;
}

static int eic770x_final_init(int clod_boot, const struct fdt_match *match)
{
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();
	sbi_hart_blocker_fscr_configure(scratch);
	return 0;
}


static int eic770x_resume_finish(struct sbi_scratch *scratch)
{
	sbi_hart_blocker_fscr_configure(scratch);
	return 0;
}

static const struct fdt_match eic770x_match[] = {
	{ .compatible = "SiFive,FU800-dev" },
	{ .compatible = "fu800-dev" },
	{ .compatible = "sifive-dev" },
        { .compatible = "eswin,eic7700" },
	{ },
};

const struct platform_override eic770x = {
	.match_table		= eic770x_match,
	.tlbr_flush_limit	= eic770x_get_tlbr_flush_limit,
	.fw_init		= eic770x_fw_init,
	.nascent_init		= eic770x_nascent_init,
	.early_init		= eic770x_early_init,
	.final_init		= eic770x_final_init,
	.resume_finish		= eic770x_resume_finish,
};
