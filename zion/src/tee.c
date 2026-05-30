#include <sbi/sbi_types.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_string.h>
#include "zion.h"
#include "tee.h"
#include "ree.h"
#include "cvm.h"
#include "pmp.h"
#include "crypto.h"
#include "mprv.h"

#include "tee-mem.h"

struct tee_thread tee_threads[MAX_TEE_THREADS];
unsigned int tee_thread_next = 0;
static unsigned long tee_thread_alloc_bitmap;

int tee_region_id = 0;

struct tee_thread *tee_thread_alloc(void)
{
	for (size_t i = MAX_REE_HARTS; i < MAX_TEE_THREADS; i++) {
		if (tee_thread_alloc_bitmap & (1UL << i))
			continue;

		tee_thread_alloc_bitmap |= 1UL << i;
		sbi_memset(&tee_threads[i], 0, sizeof(tee_threads[i]));
		return &tee_threads[i];
	}

	return NULL;
}

void tee_thread_free(struct tee_thread *tthread)
{
	if (!tthread)
		return;

	if (tthread < tee_threads ||
	    tthread >= &tee_threads[MAX_TEE_THREADS])
		return;

	size_t index = tthread - tee_threads;

	if (index < MAX_REE_HARTS)
		return;

	sbi_memset(tthread, 0, sizeof(*tthread));
	tee_thread_alloc_bitmap &= ~(1UL << index);
}

static size_t get_load_mem_chunk_size(const struct sbi_load_mem *req,
				      size_t cursor)
{
	size_t remaining = req->size - cursor;

	return remaining > BLOCK_SIZE ? BLOCK_SIZE : remaining;
}

static int resolve_load_mem_block(unsigned int d_rtid, pte_t *root_pt,
				  uint8_t pt_mode, uint64_t gpa,
				  uint64_t *block_hpa)
{
	pte_t *pte = get_pte_entry(NULL, root_pt, gpa, false, 0, 1, pt_mode);

	zion_printf("[SM] load_mem(): Checking mapping for gpa=%lx, pte=%lx\n",
		    gpa, pte ? *pte : 0);

	if (!pte || !(*pte & PTE_V)) {
		*block_hpa = alloc_data_block(&g_mem_pool.data_pool, d_rtid);
		zion_printf(
			"[SM] load_mem(): Allocated block hpa=%lx for gpa=%lx\n",
			*block_hpa, gpa);
		if (map_gpa_to_hpa(&g_mem_pool, d_rtid, gpa, *block_hpa,
				   BLOCK_SIZE, IS_HUGE_PAGE, false) != 0) {
			sbi_printf(
				"[SBI] !!!ERROR!!! in load_mem(): Failed to map 2MB block\n");
			return -1;
		}
		return 0;
	}

	*block_hpa = ((*pte >> ZION_PTE_PPN_SHIFT) << PAGE_SHIFT);
	zion_printf(
		"[SM] load_mem(): Block already mapped, block_hpa=%lx for gpa=%lx\n",
		*block_hpa, gpa);

	return 0;
}

static size_t trim_load_mem_chunk_to_block(uint64_t gpa, uint64_t *block_hpa,
					   size_t load_size)
{
	uint64_t offset = gpa & (BLOCK_SIZE - 1);

	*block_hpa += offset;
	if (offset + load_size > BLOCK_SIZE)
		load_size = BLOCK_SIZE - offset;

	zion_printf(
		"[SM] load_mem(): Final block_hpa=%lx, offset=%lx, load_size=%lx\n",
		*block_hpa, offset, load_size);

	return load_size;
}

static int copy_load_mem_chunk(uint64_t block_hpa, unsigned long stash,
			       size_t cursor, size_t load_size)
{
	unsigned long mstatus_old = csr_read(CSR_MSTATUS);
	unsigned long mstatus	   = mstatus_old;

	mstatus &= ~MSTATUS_MPP;
	mstatus |= (PRV_U << MSTATUS_MPP_SHIFT);
	csr_write(CSR_MSTATUS, mstatus);

	zion_printf("[SM] load_mem(): stash=%lx, cursor=%lx, load_size=%lx\n",
		    stash, cursor, load_size);
	int illegal = copy_to_sm((void *)block_hpa, stash + cursor, load_size);
	csr_write(CSR_MSTATUS, mstatus_old);

	return illegal ? -1 : 0;
}

void set_inited(unsigned int tid)
{
	unsigned int target_rtid;
	zion_mode target_mode;
	struct zion_state *current_state = hart_get_caller();
	if (current_state->mode == REE) {
		target_rtid = ree.tees[tid].id;
		target_mode = ree.tees[tid].mode;

	} else if (current_state->mode == CVM) {
		target_rtid = cvms[current_state->rtid].tees[tid].id;
		target_mode = cvms[current_state->rtid].tees[tid].mode;
	} else {
		return;
	}

	if (target_mode == CVM) {
		cvms[target_rtid].inited = true;
	}
}

unsigned long reserve_mem(unsigned long base, unsigned long count)
{
	unsigned long size = count << PAGE_SHIFT;
	sbi_printf("[SBI] reserve_mem(): base=0x%lx, count=0x%lx, size=0x%lx\n",
		   base, count, size);
	int ret = tee_mem_init((uint8_t *)base, (uint32_t)count);
	sbi_printf("[SBI] reserve_mem(): tee_mem_init() ret=%d\n", ret);
	if (ret) {
		sbi_printf("[SBI] reserve_mem(): tee_mem_init() failed, base=0x%lx, count=0x%lx, ret=%d\n",
			   base, count, ret);
		return ret;
	}

	tee_region_id = teem_init(base, size);
	if (tee_region_id < 0) {
		sbi_printf("[SBI] reserve_mem(): teem_init() failed, base=0x%lx, count=0x%lx, ret=%d\n",
			   base, count, tee_region_id);
		return tee_region_id;
	}
	/*
	 * The protected TVM region must be blocked on every started hart.
	 * A local-only PMP update works on single-hart QEMU, but leaves
	 * other REE harts unprotected on SMP boards.
	 */
	ret = pmp_set_global(tee_region_id, PMP_NO_PERM);
	if (ret) {
		sbi_printf("[SBI] reserve_mem(): pmp_set_global(region=%d, perm=0x%x) failed, ret=%d\n",
			   tee_region_id, PMP_NO_PERM, ret);
		return ret;
	}

	sbi_printf("[SBI] reserve_mem(): protected region=%d, addr=0x%lx, size=0x%lx\n",
		   tee_region_id, (unsigned long)pmp_region_get_addr(tee_region_id),
		   (unsigned long)pmp_region_get_size(tee_region_id));
	return 0;
}

unsigned long register_pt(unsigned int tid, struct sbi_register_pt *pt)
{
	unsigned int rtid = hart_get_callee_rtid(tid);

	set_cvm_pt_mode(&g_mem_pool, rtid, pt->level);

	return map_gpa_to_hpa(&g_mem_pool, rtid, pt->gpa,
			      pt->hfn << PAGE_SHIFT,
			      pt->is_huge ? HUGE_PAGE_SIZE : PAGE_SIZE,
			      pt->is_huge, pt->rdonly);
}

unsigned long sync_pt(unsigned int tid, unsigned long gpa,
		      unsigned long pt_paddr)
{
	unsigned int rtid = hart_get_callee_rtid(tid);

	uint64_t index = (gpa >> CVM_ROOT_PT_INDEX_SHIFT) &
			 CVM_ROOT_PT_INDEX_MASK;

	pte_t *root_pt = (pte_t *)cvms[rtid].pgd;

	pte_t *entry = &root_pt[index];

	*entry = (((uint64_t)pt_paddr >> PAGE_SHIFT) << ZION_PTE_PPN_SHIFT) |
		 PTE_V;

	return 0;
}

unsigned long load_mem(unsigned int d_rtid, struct sbi_load_mem *p)
{
	hash_ctx hash_ctx;

	zion_printf(
		"[SM] load_mem(): d_rtid=%x, stash=%lx, pos=%lx, size=%lx\n",
		d_rtid, p->stash, p->pos, p->size);

	hash_init(&hash_ctx);

	// Hash the runtime parameters
	hash_extend(&hash_ctx, p, sizeof(struct sbi_load_mem));

	size_t cursor	= 0;
	pte_t *root_pt	= (pte_t *)get_cvm_root_pt(&g_mem_pool, d_rtid);
	uint8_t pt_mode = get_cvm_pt_mode(&g_mem_pool, d_rtid);
	while (cursor < p->size) {
		uint64_t gpa = p->pos + cursor;
		size_t load_size = get_load_mem_chunk_size(p, cursor);
		uint64_t block_hpa = 0;

		if (resolve_load_mem_block(d_rtid, root_pt, pt_mode, gpa,
					   &block_hpa) != 0 ||
		    block_hpa == 0)
			return -1;

		load_size =
			trim_load_mem_chunk_to_block(gpa, &block_hpa, load_size);
		if (copy_load_mem_chunk(block_hpa, p->stash, cursor, load_size) !=
		    0) {
			sbi_printf(
				"[SBI] !!!ERROR!!! in load_mem(): copy block, stash=%lx, pos=%lx\n",
				p->stash, p->pos);
			return -1;
		}

		cursor += load_size;
	}

	// Finalize the hash
	hash_finalize(cvms[d_rtid].hash, &hash_ctx);

	return 0;
}

int teem_init(uintptr_t start, unsigned long size)
{
	int region = -1;
	int ret = pmp_region_init_atomic(start, size, PMP_PRI_ANY, &region, 0);
	if (ret) {
		sbi_printf("[SBI] teem_init(): pmp_region_init_atomic() failed, ret=%d\n",
			   ret);
		return -1;
	}

	return region;
}

void tee_metadata_init()
{

	for (size_t i = 0; i < MAX_CVMS; i++) {
		cvms[i].tee_id_next = 0;
		cvms[i].inited	    = false;
		for (size_t j = 0; j < MAX_CVM_VCPUS; j++) {
			cvms[i].vcpus[j].exit_cause = TEE_INIT;
		}
	}
}
