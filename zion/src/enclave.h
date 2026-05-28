#ifndef __ENCLAVE_H__
#define __ENCLAVE_H__

#include <sbi/sbi_types.h>
#include <sbi/sbi_trap.h>
#include "zion.h"
#include "tee.h"
#include "crypto.h"

struct enclave_mem_info {
	unsigned long epm_base;       /* EPM GPA (Enclave Private Memory) */
	unsigned long epm_size;       /* EPM size in bytes */
	unsigned long utm_base;       /* UTM GPA (Untrusted Shared Memory) */
	unsigned long utm_size;       /* UTM size in bytes */
	unsigned long runtime_entry;  /* Eyrie runtime entry address */
	unsigned long runtime_size;   /* Eyrie runtime size */
	unsigned long user_entry;     /* User app entry address */
	unsigned long user_entry_size;/* User app size */
	unsigned long untrusted_ptr;  /* Host argument pointer */
	unsigned long untrusted_size; /* Host argument size */
};

struct enclave_shared_channel {
	unsigned long eid;
	unsigned long *retval;
};

struct enclave {
	unsigned int owner_rtid;      /* Owning REE hart */

	/* G-stage page table (reuses Zion pt_pool) */
	unsigned long hgatp;
	unsigned long pgd;

	/* Memory layout */
	struct enclave_mem_info mem_info;

	/* TEE thread (reuses Zion tee_thread) */
	struct tee_thread *tthread;
	tee_quit_cause exit_cause;

	/* Measurement */
	byte hash[MDSIZE];

	/* Shared channel (edge call in UTM) */
	struct enclave_shared_channel channel;

	bool inited;
};

extern struct enclave enclaves[MAX_ENCLAVES];

/* Enclave lifecycle */
unsigned long create_enclave(unsigned long epm_base, unsigned long epm_size,
			     unsigned long utm_base, unsigned long utm_size,
			     unsigned int *eid_out);
unsigned long destroy_enclave(unsigned int eid);
unsigned long run_enclave(struct sbi_trap_regs *regs, unsigned int eid);
unsigned long exit_enclave(struct sbi_trap_regs *regs, unsigned int eid,
			   unsigned int exit_cause);

/* Enclave memory management */
int enclave_map_epm(unsigned int eid);
int enclave_map_utm(unsigned int eid);

/* SBI entry points */
unsigned long sbi_sm_create_enclave(struct sbi_trap_regs *regs,
				    unsigned long epm_base,
				    unsigned long epm_size,
				    unsigned long utm_base,
				    unsigned long utm_size);
unsigned long sbi_sm_destroy_enclave(struct sbi_trap_regs *regs,
				     unsigned int eid);
unsigned long sbi_sm_run_enclave(struct sbi_trap_regs *regs,
				 unsigned int eid);
unsigned long sbi_sm_exit_enclave(struct sbi_trap_regs *regs,
				  unsigned int eid,
				  unsigned int exit_cause);

#endif /* __ENCLAVE_H__ */
