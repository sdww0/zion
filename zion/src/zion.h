#ifndef __ZION_H__
#define __ZION_H__

#include <sbi/sbi_types.h>

#define MAX_TEE_THREADS 96
#define MAX_REE_HARTS 8
#define MAX_CVMS 16
#define MAX_CVM_VCPUS 4
#define MAX_TEES 16

#define TEE_TRAP_STAT_SLOTS 30
#define ZION_COUNTER_ENABLE_MASK 0x7UL

#define MAX_SHARED_MEMS 4

/* Enclave limits */
#define MAX_ENCLAVES 16
#define MAX_ENCLAVE_VCPUS 1  /* Zion enclave is single-hart */

typedef enum {
	REE = -1,
	CVM = 0,
	ENCLAVE,
} zion_mode;

typedef enum {
	TEE_INIT = -1,
	ENCLAVE_STOP_TIMER_INTERRUPT,
	ENCLAVE_STOP_EDGECALL_HOST,
	ENCLAVE_STOP_SYSCALL_HOST,
	ENCLAVE_STOP_EXIT_ENCLAVE,
	ENCLAVE_STOP_PAGE_FAULT,

	CVM_EXIT_SBI_CALL,
	CVM_EXIT_INTERRUPT,
	CVM_EXIT_SHARED_MEM_PAGE_FAULT,
	CVM_EXIT_MMIO_LOAD,
	CVM_EXIT_MMIO_STORE,
	CVM_EXIT_VIRT_INST,
} tee_quit_cause;

struct zion_state {
	unsigned int rtid;
	unsigned int ttid;
	struct tee_thread *tthread;
	zion_mode mode;
};

void zion_init(bool cold_boot);
void zion_pmp_reconfigure(void);
void zion_pmp_finalize(void);
void zion_enable_counters(void);
unsigned int zion_current_hart_index(void);

/*
 * Production builds leave ZION_DEBUG undefined.  The Zion objects makefile
 * enables it for either `make DEBUG=1` or `make ZION_DEBUG=1` builds.
 *
 * Keep diagnostic output separate from the two always-on channels below:
 *   sm_error()   terse, non-sensitive monitor failures
 *   tee_console() bytes explicitly written through the guest console ABI
 */
#define sm_error(...) \
	do { \
		sbi_printf(__VA_ARGS__); \
	} while (0)
#define tee_console(...) \
	do { \
		sbi_printf(__VA_ARGS__); \
	} while (0)

#ifdef ZION_DEBUG
#define zion_printf(...) \
	do {                 \
		sbi_printf(__VA_ARGS__); \
	} while (0)
#define sm_debug(...) \
	do {              \
		sbi_printf(__VA_ARGS__); \
	} while (0)
#define tee_log(...) \
	do {              \
		sbi_printf(__VA_ARGS__); \
	} while (0)
#else
#define zion_printf(...) do { } while (0)
#define sm_debug(...) do { } while (0)
#define tee_log(...) do { } while (0)
#endif

#endif
