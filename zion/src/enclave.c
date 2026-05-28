#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hfence.h>
#include <sbi/sbi_string.h>
#include "enclave.h"
#include "context.h"
#include "tee-mem.h"
#include "mprv.h"
#include "ree.h"

struct enclave enclaves[MAX_ENCLAVES];
static unsigned long enclaves_alloc_bitmap = 0;

static void reset_enclave_metadata(unsigned int eid)
{
	if (eid >= MAX_ENCLAVES)
		return;

	sbi_memset(&enclaves[eid], 0, sizeof(enclaves[eid]));
	enclaves[eid].owner_rtid = (unsigned int)-1;
}

static bool enclave_eid_allocated(unsigned int eid)
{
	return eid < MAX_ENCLAVES && (enclaves_alloc_bitmap & (1UL << eid));
}

static int alloc_enclave_eid(unsigned int *eid)
{
	for (unsigned int i = 0; i < MAX_ENCLAVES; i++) {
		if (enclaves_alloc_bitmap & (1UL << i))
			continue;

		enclaves_alloc_bitmap |= (1UL << i);
		*eid = i;
		return 0;
	}

	return -1;
}

static void free_enclave_eid(unsigned int eid)
{
	if (eid >= MAX_ENCLAVES)
		return;

	enclaves_alloc_bitmap &= ~(1UL << eid);
}

static void init_enclave_csrs(struct tee_csr *csrs, uintptr_t mstatus,
			      unsigned long hgatp)
{
	csrs->mstatus = mstatus;
	csrs->hstatus = HSTATUS_VTW | HSTATUS_SPVP | HSTATUS_SPV;
	csrs->scounteren = ZION_COUNTER_ENABLE_MASK;
	csrs->hcounteren = -1UL;
	csrs->hvip = 0;
	csrs->hgatp = hgatp & ~HGATP_VMID_MASK;
}

/*
 * create_enclave - Allocate and initialize an enclave structure.
 *
 * @epm_base: Enclave Private Memory guest-physical base
 * @epm_size: EPM size in bytes
 * @utm_base: Untrusted shared Memory guest-physical base
 * @utm_size: UTM size in bytes
 * @host_utm_pa: Host physical address backing the UTM region
 * @runtime_entry: Eyrie runtime entry point (GPA)
 * @user_entry: User application entry point (GPA)
 * @eid_out:  receives the allocated enclave ID on success
 *
 * Returns 0 on success, -1 on failure.
 */
unsigned long create_enclave(unsigned long epm_base, unsigned long epm_size,
			     unsigned long utm_base, unsigned long utm_size,
			     unsigned long host_utm_pa,
			     unsigned long runtime_entry,
			     unsigned long user_entry,
			     unsigned int *eid_out)
{
	unsigned int eid;
	struct enclave *enc;

	if (alloc_enclave_eid(&eid) != 0) {
		sbi_printf("[SM] create_enclave(): no free enclave slot\n");
		return -1;
	}

	reset_enclave_metadata(eid);
	enc = &enclaves[eid];

	/* Allocate G-stage page table from Zion pt_pool */
	reset_enclave_pt_pool(&g_mem_pool, eid);
	unsigned long pgd = (unsigned long)get_enclave_root_pt(&g_mem_pool, eid);
	if (!pgd) {
		sbi_printf("[SM] create_enclave(): failed to alloc page table\n");
		free_enclave_eid(eid);
		return -1;
	}

	/* Build hgatp */
	unsigned long hgatp = GSTAGE_MODE;
	hgatp |= ((unsigned long)eid << HGATP_VMID_SHIFT) & HGATP_VMID_MASK;
	hgatp |= (pgd >> PAGE_SHIFT) & HGATP_PPN;

	enc->hgatp = hgatp;
	enc->pgd = pgd;

	/* Save memory layout */
	enc->mem_info.epm_base = epm_base;
	enc->mem_info.epm_size = epm_size;
	enc->mem_info.utm_base = utm_base;
	enc->mem_info.utm_size = utm_size;
	enc->mem_info.host_utm_pa = host_utm_pa;
	enc->mem_info.runtime_entry = runtime_entry;
	enc->mem_info.user_entry = user_entry;

	enc->owner_rtid = (unsigned int)-1;

	/* Map EPM: allocate physical blocks and build G-stage mappings */
	if (enclave_map_epm(eid) != 0) {
		sbi_printf("[SM] create_enclave(): EPM mapping failed\n");
		reset_enclave_pt_pool(&g_mem_pool, eid);
		free_enclave_eid(eid);
		return -1;
	}

	/* Map UTM: host PA → enclave GPA in G-stage */
	if (host_utm_pa && utm_size) {
		if (enclave_map_utm(eid) != 0) {
			sbi_printf("[SM] create_enclave(): UTM mapping failed\n");
			free_data_blocks_per_tid(&g_mem_pool.data_pool, eid);
			reset_enclave_pt_pool(&g_mem_pool, eid);
			free_enclave_eid(eid);
			return -1;
		}
	}

	*eid_out = eid;

	zion_printf("[SM] create_enclave(): eid=%u, hgatp=%lx, pgd=%lx\n",
		    eid, hgatp, pgd);
	zion_printf("[SM] create_enclave(): epm=0x%lx+0x%lx, utm=0x%lx+0x%lx\n",
		    epm_base, epm_size, utm_base, utm_size);

	return 0;
}

/*
 * destroy_enclave - Release all resources of an enclave.
 */
unsigned long destroy_enclave(unsigned int eid)
{
	struct enclave *enc;

	if (!enclave_eid_allocated(eid))
		return -1;

	enc = &enclaves[eid];

	/* Free page table pool */
	reset_enclave_pt_pool(&g_mem_pool, eid);

	/* Free TEE thread */
	if (enc->tthread) {
		tee_thread_free(enc->tthread);
		enc->tthread = NULL;
	}

	/* Free data blocks */
	free_data_blocks_per_tid(&g_mem_pool.data_pool, eid);

	reset_enclave_metadata(eid);
	free_enclave_eid(eid);

	zion_printf("[SM] destroy_enclave(): eid=%u destroyed\n", eid);

	return 0;
}

/*
 * enclave_map_epm - Map Enclave Private Memory into G-stage page table.
 *
 * Uses lazy mapping: pages are mapped on first access (page fault).
 * This function pre-maps the EPM region using 2MB huge pages.
 */
int enclave_map_epm(unsigned int eid)
{
	struct enclave *enc;
	size_t mapped = 0;

	if (!enclave_eid_allocated(eid))
		return -1;

	enc = &enclaves[eid];

	if (!enc->mem_info.epm_base || !enc->mem_info.epm_size)
		return -1;

	while (mapped < enc->mem_info.epm_size) {
		uint64_t gpa = enc->mem_info.epm_base + mapped;
		uint64_t block = alloc_data_block(&g_mem_pool.data_pool, eid);
		if (block == (uint64_t)-1) {
			sbi_printf("[SM] enclave_map_epm(): out of data blocks\n");
			return -1;
		}

		if (map_gpa_to_hpa(&g_mem_pool, eid + CVM_NUM, gpa, block,
				   BLOCK_SIZE, IS_HUGE_PAGE, false)) {
			sbi_printf("[SM] enclave_map_epm(): map failed at 0x%lx\n",
				   gpa);
			return -1;
		}

		mapped += BLOCK_SIZE;
	}

	__sbi_hfence_gvma_all();

	zion_printf("[SM] enclave_map_epm(): eid=%u, mapped 0x%lx bytes\n",
		    eid, mapped);

	return 0;
}

/*
 * enclave_map_utm - Map Untrusted shared Memory into G-stage page table.
 *
 * UTM is backed by host physical memory (host_utm_pa). We map it into
 * the enclave's G-stage at utm_base GPA so both host and enclave can
 * access it. Uses 2MB huge pages.
 */
int enclave_map_utm(unsigned int eid)
{
	struct enclave *enc;
	size_t mapped = 0;

	if (!enclave_eid_allocated(eid))
		return -1;

	enc = &enclaves[eid];

	if (!enc->mem_info.utm_base || !enc->mem_info.utm_size)
		return -1;

	if (!enc->mem_info.host_utm_pa) {
		sbi_printf("[SM] enclave_map_utm(): no host UTM PA\n");
		return -1;
	}

	while (mapped < enc->mem_info.utm_size) {
		uint64_t gpa = enc->mem_info.utm_base + mapped;
		uint64_t hpa = enc->mem_info.host_utm_pa + mapped;

		if (map_gpa_to_hpa(&g_mem_pool, eid + CVM_NUM, gpa, hpa,
				   BLOCK_SIZE, IS_HUGE_PAGE, false)) {
			sbi_printf("[SM] enclave_map_utm(): map failed at "
				   "gpa=0x%lx hpa=0x%lx\n", gpa, hpa);
			return -1;
		}

		mapped += BLOCK_SIZE;
	}

	__sbi_hfence_gvma_all();

	zion_printf("[SM] enclave_map_utm(): eid=%u, mapped 0x%lx bytes, "
		    "host_pa=0x%lx\n",
		    eid, mapped, enc->mem_info.host_utm_pa);

	return 0;
}

/*
 * run_enclave - Enter an enclave for the first time (or resume from exit).
 *
 * Sets up the tee_thread CSR/GPR state and performs context switch
 * from REE to ENCLAVE.
 */
unsigned long run_enclave(struct sbi_trap_regs *regs, unsigned int eid)
{
	struct enclave *enc;
	struct tee_thread *tthread;
	uintptr_t mstatus;

	if (!enclave_eid_allocated(eid)) {
		sbi_printf("[SM] run_enclave(): invalid eid=%u\n", eid);
		return -1;
	}

	enc = &enclaves[eid];

	/* Allocate tee_thread on first run */
	if (!enc->tthread) {
		tthread = tee_thread_alloc();
		if (!tthread) {
			sbi_printf("[SM] run_enclave(): no free tee_thread\n");
			return -1;
		}

		enc->tthread = tthread;
		tthread->master = (void *)enc;

		save_tthread_state(&tthread->state, eid, 0, tthread, ENCLAVE);

		/* Build initial mstatus for VS-mode */
		mstatus = csr_read(CSR_MSTATUS);
		mstatus &= ~MSTATUS_MPP;
		mstatus |= (PRV_S << MSTATUS_MPP_SHIFT);
		mstatus |= MSTATUS_MPV;  /* Enter virtual mode */
		mstatus &= ~MSTATUS_FS;
		mstatus |= (1UL << 14);  /* FS=Dirty for FP */
		mstatus &= ~MSTATUS_SIE;
		mstatus &= ~MSTATUS_SPIE;

		/* Initialize CSR state for Eyrie runtime in VS-mode */
		init_enclave_csrs(&tthread->csrs, mstatus, enc->hgatp);

		/* Set Eyrie runtime entry point as mepc */
		tthread->csrs.mepc = enc->mem_info.runtime_entry;

		/*
		 * Set initial arguments for Eyrie eyrie_boot():
		 *   a0 = dummy (0)
		 *   a1 = dram_base (EPM base GPA)
		 *   a2 = dram_size (EPM size)
		 *   a3 = runtime_paddr (runtime entry = EPM base)
		 *   a4 = user_paddr (user app entry point)
		 *   a5 = free_paddr (free memory after user app)
		 *   a6 = utm_vaddr (UTM GPA)
		 *   a7 = utm_size
		 */
		tthread->gprs.a0 = 0;
		tthread->gprs.a1 = enc->mem_info.epm_base;
		tthread->gprs.a2 = enc->mem_info.epm_size;
		tthread->gprs.a3 = enc->mem_info.runtime_entry;
		tthread->gprs.a4 = enc->mem_info.user_entry;
		tthread->gprs.a5 = enc->mem_info.epm_base +
				   enc->mem_info.epm_size;
		tthread->gprs.a6 = enc->mem_info.utm_base;
		tthread->gprs.a7 = enc->mem_info.utm_size;

		enc->inited = true;

		zion_printf("[SM] run_enclave(): eid=%u, first run, "
			    "runtime_entry=0x%lx, user_entry=0x%lx\n",
			    eid, enc->mem_info.runtime_entry,
			    enc->mem_info.user_entry);
	} else {
		tthread = enc->tthread;

		zion_printf("[SM] run_enclave(): eid=%u, resume, mepc=0x%lx\n",
			    eid, tthread->csrs.mepc);
	}

	/* Context switch: REE -> Enclave */
	context_switch_to(regs, ree.harts[csr_read(mhartid)].tthread,
			  tthread, REE_TO_ENCLAVE, enc->exit_cause,
			  NULL, (struct kvm_vcpu_channel *)&enc->channel);

	return 0;
}

/*
 * exit_enclave - Exit from enclave back to REE.
 *
 * Called when enclave explicitly exits (edge call, error, etc.)
 */
unsigned long exit_enclave(struct sbi_trap_regs *regs, unsigned int eid,
			   unsigned int exit_cause)
{
	struct enclave *enc;
	struct tee_thread *s_tthread;

	if (!enclave_eid_allocated(eid))
		return -1;

	enc = &enclaves[eid];
	s_tthread = enc->tthread;

	if (!s_tthread) {
		sbi_printf("[SM] exit_enclave(): eid=%u has no tthread\n", eid);
		return -1;
	}

	enc->exit_cause = (tee_quit_cause)exit_cause;

	context_switch_from(regs, s_tthread,
			    ree.harts[csr_read(mhartid)].tthread,
			    REE_FROM_ENCLAVE, enc->exit_cause,
			    NULL, NULL, NULL, 1);

	return 0;
}

/*------------------ SBI entry points ------------------*/

unsigned long sbi_sm_create_enclave(struct sbi_trap_regs *regs,
				    unsigned long epm_base,
				    unsigned long epm_size,
				    unsigned long utm_base,
				    unsigned long utm_size,
				    unsigned long host_utm_pa)
{
	unsigned long ret;
	unsigned int eid = 0;

	(void)regs;

	ret = create_enclave(epm_base, epm_size, utm_base, utm_size,
			     host_utm_pa, 0, 0, &eid);
	if (ret) {
		sbi_printf("[SBI] sbi_sm_create_enclave() failed: ret=0x%lx\n",
			   ret);
		return ret;
	}

	/* Return enclave ID in a0 */
	return (unsigned long)eid;
}

unsigned long sbi_sm_destroy_enclave(struct sbi_trap_regs *regs,
				     unsigned int eid)
{
	(void)regs;
	return destroy_enclave(eid);
}

unsigned long sbi_sm_run_enclave(struct sbi_trap_regs *regs, unsigned int eid)
{
	return run_enclave(regs, eid);
}
unsigned long sbi_sm_exit_enclave(struct sbi_trap_regs *regs,
				  unsigned long eid,
				  unsigned long exit_cause)
{
	unsigned long ret;

	ret = exit_enclave(regs, eid, exit_cause);
	if (!ret)
		regs->mepc += 4; /* Skip ecall instruction */
	return ret;
}

unsigned long sbi_sm_set_enclave_entry(struct sbi_trap_regs *regs,
				       unsigned long eid,
				       unsigned long runtime_entry,
				       unsigned long user_entry)
{
	struct enclave *enc;

	(void)regs;

	if ((unsigned int)eid >= MAX_ENCLAVES ||
	    !enclave_eid_allocated((unsigned int)eid))
		return -1;

	enc = &enclaves[(unsigned int)eid];
	enc->mem_info.runtime_entry = runtime_entry;
	enc->mem_info.user_entry = user_entry;

	zion_printf("[SBI] set_enclave_entry: eid=%lu, runtime=0x%lx, "
		    "user=0x%lx\n",
		    eid, runtime_entry, user_entry);

	return 0;
}
