#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_hart.h>

#include "ipi.h"
#include "pmp.h"

struct zion_pmp_region {
	/*
	 * Zion currently protects one host-reserved TVM memory window. The PMP
	 * CSR numbers are selected at reservation time from OpenSBI's existing
	 * per-hart PMP layout instead of being hard-coded by the monitor.
	 */
	bool valid;
	uintptr_t addr;
	uint64_t size;
	unsigned int lower_entry;
	unsigned int fallback_entry;
	bool use_fallback;
};

static spinlock_t pmp_lock = SPIN_LOCK_INITIALIZER;
static struct zion_pmp_region tee_region;

#define ZION_PMP_NO_FALLBACK ((unsigned int)-1)

static bool zion_pmp_entry_is_free(unsigned int entry);
static bool zion_pmp_entry_is_allow_all(unsigned int entry);

static inline bool region_valid(region_id region)
{
	return region == 0 && tee_region.valid;
}

static inline void pmp_local_fence(void)
{
	asm volatile("sfence.vma" ::: "memory");
}

static bool zion_pmp_entry_covers_phys_addr_space(unsigned long addr,
						      unsigned long log2len)
{
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();
	unsigned int pmp_addr_bits =
		scratch ? sbi_hart_pmp_addrbits(scratch) : 0;

	/*
	 * OpenSBI root-domain catch-all PMP entries are not guaranteed to decode
	 * as log2len == __riscv_xlen. On EIC7700 we observed a 0-based NAPOT
	 * entry with log2len=42 while the hart only exposes 39 PMP address bits.
	 * What matters for reuse is that the entry starts at 0 and covers the
	 * entire physical address space visible to the hart.
	 */
	if (addr != 0 || !pmp_addr_bits)
		return false;

	return log2len >= pmp_addr_bits;
}

static bool zion_ranges_overlap(uintptr_t lhs_addr, uint64_t lhs_size,
				uintptr_t rhs_addr, uint64_t rhs_size)
{
	uintptr_t lhs_end;
	uintptr_t rhs_end;

	if (__builtin_uaddl_overflow(lhs_addr, lhs_size, &lhs_end))
		return true;
	if (__builtin_uaddl_overflow(rhs_addr, rhs_size, &rhs_end))
		return true;

	return lhs_addr < rhs_end && rhs_addr < lhs_end;
}

static bool zion_pmp_entry_is_free(unsigned int entry)
{
	unsigned long prot = 0;
	unsigned long addr = 0;
	unsigned long log2len = 0;

	if (pmp_get(entry, &prot, &addr, &log2len))
		return false;

	return !(prot & (PMP_A | PMP_L));
}

static bool zion_pmp_entry_is_allow_all(unsigned int entry)
{
	unsigned long prot = 0;
	unsigned long addr = 0;
	unsigned long log2len = 0;

	if (pmp_get(entry, &prot, &addr, &log2len))
		return false;

	return !(prot & PMP_L) &&
	       (prot & PMP_ALL_PERM) == PMP_ALL_PERM &&
	       (prot & PMP_A) == PMP_A_NAPOT &&
	       zion_pmp_entry_covers_phys_addr_space(addr, log2len);
}

static void zion_dump_pmp_layout(const char *reason)
{
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();
	unsigned int pmp_count = scratch ? sbi_hart_pmp_count(scratch) : 0;
	unsigned int entry;

	sbi_printf("[SM] PMP layout dump: reason=%s, hart=%u, pmp_count=%u\n",
		   reason ? reason : "unknown", current_hartid(), pmp_count);

	for (entry = 0; entry < pmp_count; entry++) {
		unsigned long prot = 0;
		unsigned long addr = 0;
		unsigned long log2len = 0;

		if (pmp_get(entry, &prot, &addr, &log2len)) {
			sbi_printf("[SM]   pmp[%u]: read failed\n", entry);
			continue;
		}

		sbi_printf("[SM]   pmp[%u]: prot=0x%lx, addr=0x%lx, log2len=%lu, free=%d, allow_all=%d\n",
			   entry, prot, addr, log2len,
			   zion_pmp_entry_is_free(entry),
			   zion_pmp_entry_is_allow_all(entry));
	}
}

static int zion_find_runtime_layout(unsigned int *lower_entry,
				    unsigned int *fallback_entry,
				    bool *use_fallback)
{
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();
	unsigned int pmp_count = sbi_hart_pmp_count(scratch);
	int entry;
	int lower = -1;
	int fallback = -1;

	if (!lower_entry || !fallback_entry || !use_fallback || pmp_count < 2) {
		sbi_printf("[SM] runtime layout search failed: invalid args or insufficient PMP entries\n");
		return -1;
	}

	/*
	 * Reuse OpenSBI's existing catch-all SU RWX entry as the lower
	 * half of our TOR pair. The next free entry becomes the upper
	 * TOR bound, and we add a new low-priority catch-all entry above
	 * it so accesses outside the protected window still work.
	 */
	for (entry = 0; entry < (int)pmp_count; entry++) {
		if (zion_pmp_entry_is_allow_all(entry)) {
			lower = entry;
			break;
		}
	}

	if (lower < 0)
		goto fallback_free_pair;

	if (lower + 1 >= (int)pmp_count)
		goto fallback_free_pair;

	if (!zion_pmp_entry_is_free(lower + 1))
		goto fallback_free_pair;

	for (entry = (int)pmp_count - 1; entry >= 0; entry--) {
		if (entry == lower + 1)
			continue;
		if (zion_pmp_entry_is_free(entry)) {
			fallback = entry;
			break;
		}
	}

	if (fallback < 0)
		goto fallback_free_pair;

	*lower_entry = (unsigned int)lower;
	*fallback_entry = (unsigned int)fallback;
	*use_fallback = true;
	return 0;

fallback_free_pair:
	/*
	 * Some boards only expose 8 PMP entries and their root-domain layout
	 * does not include a writable all-space NAPOT entry. In that case,
	 * fall back to the first genuinely free TOR pair and rely on the
	 * remaining higher-numbered root-domain PMPs to preserve normal access
	 * outside the protected window.
	 */
	for (entry = 0; entry + 1 < (int)pmp_count; entry++) {
		if (!zion_pmp_entry_is_free(entry) ||
		    !zion_pmp_entry_is_free(entry + 1))
			continue;

		*lower_entry = (unsigned int)entry;
		*fallback_entry = ZION_PMP_NO_FALLBACK;
		*use_fallback = false;
		return 0;
	}

	sbi_printf("[SM] runtime layout search failed: no usable layout on hart=%u\n",
		   current_hartid());
	return -1;
}

static int zion_region_init(uintptr_t start, uint64_t size,
			    enum pmp_priority priority, region_id *rid,
			    int allow_overlap)
{
	unsigned int lower_entry = 0;
	unsigned int fallback_entry = 0;
	bool use_fallback = false;

	if (!rid || !size) {
		sbi_printf("[SM] zion_region_init() failed: invalid rid/size\n");
		return -1;
	}
	if (priority != PMP_PRI_ANY) {
		sbi_printf("[SM] zion_region_init() failed: unsupported priority=%d\n",
			   priority);
		return -1;
	}
	if ((start & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1))) {
		sbi_printf("[SM] zion_region_init() failed: unaligned start=0x%lx, size=0x%lx\n",
			   (unsigned long)start, (unsigned long)size);
		return -1;
	}
	if (tee_region.valid && !allow_overlap &&
	    zion_ranges_overlap(start, size, tee_region.addr, tee_region.size)) {
		sbi_printf("[SM] zion_region_init() failed: overlap with existing region addr=0x%lx, size=0x%lx\n",
			   (unsigned long)tee_region.addr,
			   (unsigned long)tee_region.size);
		return -1;
	}
	if (tee_region.valid) {
		sbi_printf("[SM] zion_region_init() failed: region already valid\n");
		return -1;
	}
	if (zion_find_runtime_layout(&lower_entry, &fallback_entry,
				     &use_fallback)) {
		zion_dump_pmp_layout("no runtime layout");
		return -1;
	}

	tee_region.valid = true;
	tee_region.addr = start;
	tee_region.size = size;
	tee_region.lower_entry = lower_entry;
	tee_region.fallback_entry = fallback_entry;
	tee_region.use_fallback = use_fallback;
	*rid = 0;

	return 0;
}

void pmp_init(void)
{
	/*
	 * Hardware PMP discovery and root-domain programming are handled by
	 * OpenSBI. This remains as a compatibility hook for older Zion call
	 * sites and intentionally does not touch any PMP CSR.
	 */
}

int pmp_region_init_atomic(uintptr_t start, uint64_t size,
			   enum pmp_priority priority, region_id *rid,
			   int allow_overlap)
{
	int ret;

	spin_lock(&pmp_lock);
	ret = zion_region_init(start, size, priority, rid, allow_overlap);
	spin_unlock(&pmp_lock);

	return ret;
}

int pmp_region_init(uintptr_t start, uint64_t size, enum pmp_priority priority,
		    region_id *rid, int allow_overlap)
{
	return pmp_region_init_atomic(start, size, priority, rid, allow_overlap);
}

int pmp_region_free_atomic(region_id region)
{
	spin_lock(&pmp_lock);

	if (!region_valid(region)) {
		sbi_printf("[SM] pmp_region_free_atomic() failed: invalid region=%d\n",
			   region);
		spin_unlock(&pmp_lock);
		return -1;
	}

	tee_region.valid = false;
	tee_region.addr = 0;
	tee_region.size = 0;
	tee_region.lower_entry = 0;
	tee_region.fallback_entry = 0;
	tee_region.use_fallback = false;

	spin_unlock(&pmp_lock);
	return 0;
}

int pmp_set_zion(region_id region, uint8_t perm)
{
	int ret;

	if (!region_valid(region)) {
		sbi_printf("[SM] pmp_set_zion() failed: invalid region=%d\n", region);
		return -1;
	}

	if (tee_region.use_fallback) {
		/*
		 * Reinstall an all-access NAPOT entry above the TOR pair. This
		 * keeps normal REE accesses working after we repurpose OpenSBI's
		 * original catch-all PMP entry as the lower TOR bound.
		 */
		ret = pmp_set(tee_region.fallback_entry, PMP_ALL_PERM, 0,
			      __riscv_xlen);
		if (ret) {
			sbi_printf("[SM] pmp_set_zion() failed: fallback entry=%u ret=%d\n",
				   tee_region.fallback_entry, ret);
			return ret;
		}
	}

	ret = pmp_set_tor(tee_region.lower_entry, perm & PMP_ALL_PERM,
			  tee_region.addr, tee_region.size);
	if (!ret) {
		pmp_local_fence();
		return 0;
	}

	sbi_printf("[SM] pmp_set_zion() failed: lower=%u, upper=%u, perm=0x%lx, addr=0x%lx, size=0x%lx, ret=%d\n",
		   tee_region.lower_entry, tee_region.lower_entry + 1,
		   (unsigned long)(perm & PMP_ALL_PERM),
		   (unsigned long)tee_region.addr,
		   (unsigned long)tee_region.size, ret);
	return ret;
}

int pmp_unset(region_id region)
{
	int ret;

	if (!region_valid(region)) {
		sbi_printf("[SM] pmp_unset() failed: invalid region=%d\n", region);
		return -1;
	}

	if (tee_region.use_fallback) {
		/* Keep the fallback entry valid while tearing down the TOR pair. */
		ret = pmp_set(tee_region.fallback_entry, PMP_ALL_PERM, 0,
			      __riscv_xlen);
		if (ret) {
			sbi_printf("[SM] pmp_unset() failed: fallback entry=%u ret=%d\n",
				   tee_region.fallback_entry, ret);
			return ret;
		}
	}

	ret = pmp_disable(tee_region.lower_entry + 1);
	if (ret)
		return ret;

	ret = pmp_disable(tee_region.lower_entry);
	if (!ret) {
		pmp_local_fence();
		return 0;
	}

	sbi_printf("[SM] pmp_unset() failed: lower=%u, upper=%u, ret=%d\n",
		   tee_region.lower_entry, tee_region.lower_entry + 1, ret);
	return ret;
}

int pmp_set_global(region_id region, uint8_t perm)
{
	if (!region_valid(region)) {
		sbi_printf("[SM] pmp_set_global() failed: invalid region=%d\n",
			   region);
		return -1;
	}

	/*
	 * PMP CSRs are per-hart. The boot hart updates itself through the same
	 * TLB/IPI path so the protected window becomes consistent on all harts.
	 */
	send_and_sync_pmp_ipi(region, SBI_PMP_IPI_TYPE_SET, perm);
	return 0;
}

int pmp_unset_global(region_id region)
{
	if (!region_valid(region)) {
		sbi_printf("[SM] pmp_unset_global() failed: invalid region=%d\n",
			   region);
		return -1;
	}

	send_and_sync_pmp_ipi(region, SBI_PMP_IPI_TYPE_UNSET, PMP_NO_PERM);
	return 0;
}

int pmp_detect_region_overlap_atomic(uintptr_t base, uintptr_t size)
{
	int overlap;

	spin_lock(&pmp_lock);
	overlap = tee_region.valid &&
		  zion_ranges_overlap(base, size, tee_region.addr, tee_region.size);
	spin_unlock(&pmp_lock);

	return overlap;
}

void handle_pmp_ipi(void)
{
	sbi_printf("[SM] handle_pmp_ipi(): hart=%u, unexpected direct call\n",
		   current_hartid());
}

uintptr_t pmp_region_get_addr(region_id region)
{
	return region_valid(region) ? tee_region.addr : 0;
}

uint64_t pmp_region_get_size(region_id region)
{
	return region_valid(region) ? tee_region.size : 0;
}
