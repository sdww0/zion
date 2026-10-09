/*
 * Zion platform hooks.
 */
#include "enclave.h"
#include "crypto.h"
#include "hmac_sha3/hmac_sha3.h"
#include "pmp.h"
#include "platform-hook.h"
#include "zion.h"
#include <sbi/sbi_string.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_csr_detect.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_scratch.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/riscv_locks.h>

struct zion_optional_csr_caps {
	bool menvcfg;
	bool henvcfg;
};

static struct zion_optional_csr_caps optional_csr_caps;

static void platform_probe_optional_csrs(void)
{
#ifdef ZION_DISABLE_ENVCFG
	optional_csr_caps.menvcfg = false;
	optional_csr_caps.henvcfg = false;
#else
	struct sbi_trap_info trap = {0};

	(void)csr_read_allowed(CSR_MENVCFG, (ulong)&trap);
	optional_csr_caps.menvcfg = !trap.cause;

	optional_csr_caps.henvcfg = false;
	if (misa_extension('H')) {
		(void)csr_read_allowed(CSR_HENVCFG, (ulong)&trap);
		optional_csr_caps.henvcfg = !trap.cause;
	}
#endif
}

bool platform_has_menvcfg(void)
{
	return optional_csr_caps.menvcfg;
}

bool platform_has_henvcfg(void)
{
	return optional_csr_caps.henvcfg;
}

unsigned long platform_menvcfg_read(void)
{
#ifdef ZION_DISABLE_ENVCFG
	return 0;
#else
	return optional_csr_caps.menvcfg ? csr_read(CSR_MENVCFG) : 0;
#endif
}

unsigned long platform_henvcfg_read(void)
{
#ifdef ZION_DISABLE_ENVCFG
	return 0;
#else
	return optional_csr_caps.henvcfg ? csr_read(CSR_HENVCFG) : 0;
#endif
}

void platform_menvcfg_write(unsigned long value)
{
#ifndef ZION_DISABLE_ENVCFG
	if (optional_csr_caps.menvcfg)
		csr_write(CSR_MENVCFG, value);
#endif
}

void platform_henvcfg_write(unsigned long value)
{
#ifndef ZION_DISABLE_ENVCFG
	if (optional_csr_caps.henvcfg)
		csr_write(CSR_HENVCFG, value);
#endif
}

void platform_menvcfg_clear(unsigned long mask)
{
#ifndef ZION_DISABLE_ENVCFG
	if (optional_csr_caps.menvcfg)
		csr_clear(CSR_MENVCFG, mask);
#endif
}

bool platform_security_alias(uintptr_t base, size_t size, uintptr_t *alias)
{
#ifdef ZION_MEGREZ_ACTIVATE
	const uintptr_t mem_base = 0x80000000UL;
	const uintptr_t mem_size = 0x800000000UL;
	const uintptr_t sys_base = 0xc000000000UL;

	if (!alias || !size || base < mem_base ||
	    size > mem_size || base - mem_base > mem_size - size)
		return false;
	*alias = sys_base + (base - mem_base);
	return true;
#else
	(void)base;
	(void)size;
	(void)alias;
	return false;
#endif
}

unsigned long platform_security_preflight(void)
{
	platform_probe_optional_csrs();
#ifdef ZION_MEGREZ_PREFLIGHT
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();
	unsigned int pmp_count = sbi_hart_pmp_count(scratch);
	unsigned int pmp_gran = sbi_hart_pmp_log2gran(scratch);
	unsigned int pmp_addr_bits = sbi_hart_pmp_addrbits(scratch);
	unsigned long pmp_gran_bytes =
		pmp_gran < __riscv_xlen ? 1UL << pmp_gran : 0;
	unsigned long old_hgatp;
	unsigned long probe_hgatp;
	unsigned long read_hgatp;
	unsigned long pmpcfg0;
	struct sbi_trap_info trap = {0};
	bool ok = true;

	sbi_printf("[ZION-PREFLIGHT] Milk-V Megrez hardware contract\n");
	sbi_printf("[ZION-PREFLIGHT] H=%s PMP=%u granule=%lu bytes PA=%u bits\n",
		   misa_extension('H') ? "yes" : "no", pmp_count,
		   pmp_gran_bytes, pmp_addr_bits);
	sbi_printf("[ZION-PREFLIGHT] menvcfg=%s henvcfg=%s%s\n",
		   optional_csr_caps.menvcfg ? "yes" : "no",
		   optional_csr_caps.henvcfg ? "yes" : "no",
#ifdef ZION_DISABLE_ENVCFG
		   " (compiled out)"
#else
		   ""
#endif
	);

	if (!misa_extension('H')) {
		sbi_printf("[ZION-PREFLIGHT] FAIL: hypervisor extension is absent\n");
		ok = false;
	}
	if (pmp_count < PMP_N_REG) {
		sbi_printf("[ZION-PREFLIGHT] FAIL: Zion needs at least %u PMP entries\n",
			   PMP_N_REG);
		ok = false;
	}
	if (pmp_gran > PAGE_SHIFT) {
		sbi_printf("[ZION-PREFLIGHT] FAIL: PMP granularity exceeds 4 KiB\n");
		ok = false;
	}
	if (pmp_addr_bits < 39) {
		sbi_printf("[ZION-PREFLIGHT] FAIL: PMP cannot cover the Megrez DDR map\n");
		ok = false;
	}

	/* EIC7700X implements exactly eight PMP entries. A locked boot-ROM entry
	 * cannot be incorporated by the current Zion allocator and must therefore
	 * disable the monitor instead of being overwritten silently. */
	pmpcfg0 = csr_read(CSR_PMPCFG0);
	for (unsigned int i = 0; i < MIN(pmp_count, PMP_N_REG); i++) {
		if (pmpcfg0 & (PMP_L << (i * 8))) {
			sbi_printf("[ZION-PREFLIGHT] FAIL: pmp%u is locked by an earlier stage\n",
				   i);
			ok = false;
		}
	}

	/* This is a non-destructive WARL probe. It proves that the current Sv48x4
	 * hgatp encoding is accepted, but deliberately does not claim full H-1.0
	 * compatibility; the EIC7700X manual describes a frozen H-0.6 core. */
	if (misa_extension('H')) {
		old_hgatp = csr_read_allowed(CSR_HGATP, (ulong)&trap);
		if (trap.cause) {
			sbi_printf("[ZION-PREFLIGHT] FAIL: hgatp read trapped (cause=%lu)\n",
				   trap.cause);
			ok = false;
		} else {
			probe_hgatp = HGATP_MODE_SV48X4 << HGATP_MODE_SHIFT;
			csr_write_allowed(CSR_HGATP, (ulong)&trap, probe_hgatp);
			if (trap.cause) {
				sbi_printf("[ZION-PREFLIGHT] FAIL: hgatp write trapped (cause=%lu)\n",
					   trap.cause);
				ok = false;
			} else {
				bool read_failed;
				bool restore_failed;

				read_hgatp = csr_read_allowed(CSR_HGATP,
							 (ulong)&trap);
				read_failed = !!trap.cause;
				csr_write_allowed(CSR_HGATP, (ulong)&trap,
						  old_hgatp);
				restore_failed = !!trap.cause;
				sbi_printf("[ZION-PREFLIGHT] hgatp Sv48x4 WARL=%s (read=0x%lx)\n",
					   !read_failed && !restore_failed &&
					   (read_hgatp & (_UL(0xf) << HGATP_MODE_SHIFT)) ==
						   probe_hgatp ? "pass" : "fail",
					   read_hgatp);
				if (read_failed || restore_failed ||
				    (read_hgatp & (_UL(0xf) << HGATP_MODE_SHIFT)) !=
					    probe_hgatp)
					ok = false;
			}
		}
	}

	if (!ok) {
		sbi_printf("[ZION-PREFLIGHT] Zion disabled; OpenSBI will continue booting\n");
		return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
	}
	sbi_printf("[ZION-PREFLIGHT] PASS (CSR-level only; VS-mode test still required)\n");
#ifndef ZION_MEGREZ_ACTIVATE
	sbi_printf("[ZION-PREFLIGHT] Zion remains disabled in the Phase-0 probe build\n");
	return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
#endif
#endif
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long platform_init_global_once(void)
{
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long platform_init_global(void)
{
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void platform_init_enclave(struct enclave *enclave) {}
void platform_destroy_enclave(struct enclave *enclave) {}

unsigned long platform_create_enclave(struct enclave *enclave)
{
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void platform_switch_to_enclave(struct enclave *enclave) {}
void platform_switch_from_enclave(struct enclave *enclave) {}

/*
 * sm_copy_key: fills the global key arrays defined in sm.c.
 */
#ifndef ZION_INSECURE_TEST_KEYS
#error "Zion platform key provider is not provisioned; use ZION_INSECURE_TEST_KEYS=1 only for test images"
#endif

#ifdef ZION_TEST_KEY_HEADER
#include ZION_TEST_KEY_HEADER
#else
#include "test_dev_key.h"
#endif

static const byte test_sm_seed[32] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

/* QEMU-only sealing fixture. This is deliberately independent from the SM
 * signing seed so attestation-key rotation cannot re-key sealed data. A
 * production platform must load this root from persistent protected storage. */
static const byte test_sealing_root[SEALING_ROOT_SIZE] = {
	0x22, 0xb8, 0xe5, 0xc3, 0x0d, 0x54, 0x18, 0xf7,
	0xf0, 0x52, 0x77, 0xc9, 0x6e, 0x31, 0x8f, 0xf9,
	0xbd, 0xc2, 0x5d, 0x28, 0xee, 0xcc, 0x88, 0x59,
	0xa0, 0x7f, 0xc1, 0xb2, 0x64, 0x66, 0xad, 0x45,
	0x9a, 0x54, 0x30, 0xa8, 0x5c, 0x42, 0x77, 0xef,
	0x12, 0x1e, 0x0f, 0xae, 0x6d, 0xb1, 0x1d, 0xd7,
	0x1f, 0xb7, 0x0d, 0x09, 0x39, 0x38, 0x8a, 0xc6,
	0x0b, 0x5e, 0x16, 0xe5, 0xb4, 0xb2, 0xde, 0x6e,
};

/* Independent HKDF-SHA3-512 v1 vector for the measurement/identity bytes
 * constructed by sealing_root_isolation_self_test(). */
static const byte test_sealing_key[SEALING_KEY_SIZE] = {
	0xc3, 0x2e, 0x34, 0x96, 0xf1, 0x33, 0x8b, 0x6c,
	0xcf, 0x28, 0x52, 0x55, 0xe0, 0x1a, 0x0c, 0xd4,
	0x7a, 0x06, 0x34, 0xb5, 0x9c, 0x24, 0x8b, 0x99,
	0xb0, 0x16, 0xe8, 0xc5, 0xec, 0x42, 0xde, 0xf8,
	0x88, 0x6e, 0xcf, 0x60, 0x1c, 0xa0, 0x27, 0xc4,
	0x0d, 0x2a, 0xef, 0x40, 0xc8, 0x07, 0x90, 0xb6,
	0x75, 0xb3, 0x53, 0x35, 0xf6, 0xe3, 0x62, 0x6b,
	0x15, 0x40, 0x34, 0xf0, 0xeb, 0x09, 0x8b, 0xa2,
	0xc3, 0x15, 0x6d, 0x8e, 0x85, 0xaa, 0x0e, 0xbd,
	0xcb, 0xd3, 0x0b, 0xa4, 0x9f, 0x42, 0x29, 0xa7,
	0x90, 0x52, 0x51, 0xcf, 0x09, 0xc3, 0x0b, 0xd3,
	0xb4, 0xcd, 0x5d, 0x44, 0x5e, 0x50, 0x17, 0x2a,
	0x84, 0x79, 0x31, 0x1f, 0xdb, 0x72, 0xee, 0x10,
	0xad, 0x73, 0x4a, 0x21, 0x5f, 0xda, 0x52, 0x09,
	0x40, 0xaf, 0x61, 0x50, 0x10, 0x9b, 0xbe, 0x56,
	0x21, 0xdb, 0xef, 0x63, 0xc3, 0x7e, 0xae, 0x6d,
};

static const byte test_random_seed[PLATFORM_RANDOM_SEED_SIZE] = {
	0x64, 0x74, 0xce, 0xec, 0xbe, 0x35, 0x36, 0xd5,
	0x0d, 0xcc, 0x2f, 0x74, 0x71, 0xbf, 0x0d, 0xe4,
	0x82, 0x27, 0x94, 0x8a, 0x47, 0xe1, 0xc5, 0xe4,
	0x9d, 0xfa, 0xf7, 0x9e, 0xdc, 0x12, 0x2b, 0xbe,
	0x21, 0x76, 0x91, 0x51, 0x46, 0xd6, 0x34, 0x59,
	0x86, 0x0b, 0x8e, 0x47, 0x7c, 0x4a, 0x48, 0x1b,
	0xf1, 0xe0, 0xa2, 0xc3, 0x19, 0x98, 0xe8, 0x64,
	0x44, 0xfa, 0xfd, 0xe5, 0xbe, 0x12, 0xcb, 0x29,
};

static const byte test_random_vector[SHA3_512_HASH_LEN] = {
	0xb5, 0x17, 0xb4, 0x47, 0x5f, 0x6f, 0x40, 0x99,
	0x7a, 0x41, 0x60, 0x61, 0xe2, 0x60, 0xa4, 0x55,
	0xd5, 0xdb, 0xe8, 0x85, 0x01, 0xb5, 0xef, 0x58,
	0xee, 0x95, 0x38, 0xc2, 0x0c, 0xb9, 0x13, 0x8f,
	0xb9, 0x8f, 0x16, 0x9e, 0x2b, 0x5d, 0x0a, 0x1b,
	0x37, 0x41, 0x8d, 0x96, 0x37, 0xb6, 0x88, 0x65,
	0xf0, 0x80, 0x69, 0xe7, 0xc1, 0x81, 0xf6, 0x40,
	0xfc, 0xf4, 0xea, 0x11, 0x1d, 0x35, 0x3b, 0x16,
};

static const byte random_label[] = "ZION-SM-RANDOM-v1";
static byte platform_random_key[PLATFORM_RANDOM_SEED_SIZE];
static uint64_t platform_random_counter;
static int platform_random_ready;
static spinlock_t platform_random_lock = SPIN_LOCK_INITIALIZER;

unsigned long platform_get_sealing_root(unsigned char *root, size_t size)
{
	if (!root || size != sizeof(test_sealing_root))
		return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
	sbi_memcpy(root, test_sealing_root, sizeof(test_sealing_root));
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long platform_get_random_seed(unsigned char *seed, size_t size)
{
	if (!seed || size != sizeof(test_random_seed))
		return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
	sbi_memcpy(seed, test_random_seed, sizeof(test_random_seed));
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static void store_be64(byte output[8], uint64_t value)
{
	for (unsigned int i = 0; i < 8; i++)
		output[i] = value >> (56 - 8 * i);
}

static int random_seed_is_valid(const byte seed[PLATFORM_RANDOM_SEED_SIZE])
{
	byte seed_or = 0;

	for (size_t i = 0; i < PLATFORM_RANDOM_SEED_SIZE; i++)
		seed_or |= seed[i];
	return seed_or &&
	       sbi_memcmp(seed, sm_private_key, PLATFORM_RANDOM_SEED_SIZE) &&
	       sbi_memcmp(seed, sm_sealing_root, PLATFORM_RANDOM_SEED_SIZE);
}

static int initialize_platform_random(void)
{
	byte seed[PLATFORM_RANDOM_SEED_SIZE];
	byte rejected_seed[PLATFORM_RANDOM_SEED_SIZE];
	byte input[sizeof(random_label) - 1 + sizeof(uint64_t)];
	byte output[SHA3_512_HASH_LEN];
	int ret = -1;

	sbi_memcpy(input, random_label, sizeof(random_label) - 1);
	store_be64(input + sizeof(random_label) - 1, 1);
	hmac_sha3(test_random_seed, sizeof(test_random_seed), input,
		  sizeof(input), output);
	if (sbi_memcmp(output, test_random_vector, sizeof(output)))
		goto out;

	sbi_memset(rejected_seed, 0, sizeof(rejected_seed));
	if (random_seed_is_valid(rejected_seed))
		goto out;
	sbi_memcpy(rejected_seed, sm_private_key, sizeof(rejected_seed));
	if (random_seed_is_valid(rejected_seed))
		goto out;
	sbi_memcpy(rejected_seed, sm_sealing_root, sizeof(rejected_seed));
	if (random_seed_is_valid(rejected_seed))
		goto out;

	if (platform_get_random_seed(seed, sizeof(seed)))
		goto out;
	if (!random_seed_is_valid(seed))
		goto out;

	sbi_memcpy(platform_random_key, seed, sizeof(seed));
	platform_random_counter = 0;
	platform_random_ready = 1;
	ret = 0;
out:
	sbi_memset(seed, 0, sizeof(seed));
	sbi_memset(rejected_seed, 0, sizeof(rejected_seed));
	sbi_memset(input, 0, sizeof(input));
	sbi_memset(output, 0, sizeof(output));
	return ret;
}

uint64_t platform_random(void)
{
	byte input[sizeof(random_label) - 1 + sizeof(uint64_t)];
	byte output[SHA3_512_HASH_LEN];
	uint64_t counter;
	uint64_t value = 0;

	spin_lock(&platform_random_lock);
	if (!platform_random_ready ||
	    platform_random_counter == (uint64_t)-1) {
		spin_unlock(&platform_random_lock);
		sm_error("[SM] fatal: random generator unavailable\n");
		sbi_hart_hang();
	}
	counter = ++platform_random_counter;
	spin_unlock(&platform_random_lock);

	sbi_memcpy(input, random_label, sizeof(random_label) - 1);
	store_be64(input + sizeof(random_label) - 1, counter);
	hmac_sha3(platform_random_key, sizeof(platform_random_key), input,
		  sizeof(input), output);
	for (unsigned int i = 0; i < sizeof(value); i++)
		value = (value << 8) | output[i];

	sbi_memset(input, 0, sizeof(input));
	sbi_memset(output, 0, sizeof(output));
	return value;
}

static const byte ed25519_group_order[32] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

extern byte sm_hash[MDSIZE];
extern byte sm_signature[SIGNATURE_SIZE];
extern byte sm_public_key[PUBLIC_KEY_SIZE];
extern byte sm_private_key[PRIVATE_KEY_SIZE];
extern byte sm_sealing_root[SEALING_ROOT_SIZE];
extern byte dev_public_key[PUBLIC_KEY_SIZE];

extern char _fw_start[];
extern char _fw_rw_start[];

static void malleate_signature_scalar(byte signature[SIGNATURE_SIZE])
{
	unsigned int carry = 0;

	for (unsigned int i = 0; i < sizeof(ed25519_group_order); i++) {
		unsigned int sum = signature[32 + i] +
				   ed25519_group_order[i] + carry;

		signature[32 + i] = sum;
		carry = sum >> 8;
	}
}

static int sealing_root_is_valid(const byte root[SEALING_ROOT_SIZE],
				 const byte signing_key[PRIVATE_KEY_SIZE])
{
	byte root_or = 0;

	for (size_t i = 0; i < SEALING_ROOT_SIZE; i++)
		root_or |= root[i];
	return root_or && sbi_memcmp(root, signing_key, SEALING_ROOT_SIZE);
}

static int sealing_root_isolation_self_test(void)
{
	byte measurement[MDSIZE];
	byte identity[16];
	byte baseline[SEALING_KEY_SIZE];
	byte signing_key_changed[SEALING_KEY_SIZE];
	byte sealing_root_changed[SEALING_KEY_SIZE];
	byte rejected_root[SEALING_ROOT_SIZE];
	byte saved_private_byte = sm_private_key[0];
	byte saved_root_byte = sm_sealing_root[0];
	int ret = -1;

	sbi_memset(rejected_root, 0, sizeof(rejected_root));
	if (sealing_root_is_valid(rejected_root, sm_private_key))
		goto out;
	sbi_memcpy(rejected_root, sm_private_key, sizeof(rejected_root));
	if (sealing_root_is_valid(rejected_root, sm_private_key) ||
	    !sealing_root_is_valid(sm_sealing_root, sm_private_key))
		goto out;

	for (size_t i = 0; i < sizeof(measurement); i++)
		measurement[i] = (byte)(0x80U + i);
	for (size_t i = 0; i < sizeof(identity); i++)
		identity[i] = (byte)(0x40U + i);

	if (sm_derive_sealing_key(baseline, identity, sizeof(identity),
				  measurement))
		goto out;
	if (sbi_memcmp(baseline, test_sealing_key, sizeof(baseline)))
		goto out;
	sm_private_key[0] ^= 0x80;
	if (sm_derive_sealing_key(signing_key_changed, identity,
				  sizeof(identity), measurement))
		goto out;
	sm_private_key[0] = saved_private_byte;
	if (sbi_memcmp(baseline, signing_key_changed, sizeof(baseline)))
		goto out;

	sm_sealing_root[0] ^= 0x80;
	if (sm_derive_sealing_key(sealing_root_changed, identity,
				  sizeof(identity), measurement))
		goto out;
	sm_sealing_root[0] = saved_root_byte;
	if (!sbi_memcmp(baseline, sealing_root_changed, sizeof(baseline)))
		goto out;

	ret = 0;
out:
	sm_private_key[0] = saved_private_byte;
	sm_sealing_root[0] = saved_root_byte;
	sbi_memset(measurement, 0, sizeof(measurement));
	sbi_memset(identity, 0, sizeof(identity));
	sbi_memset(baseline, 0, sizeof(baseline));
	sbi_memset(signing_key_changed, 0, sizeof(signing_key_changed));
	sbi_memset(sealing_root_changed, 0, sizeof(sealing_root_changed));
	sbi_memset(rejected_root, 0, sizeof(rejected_root));
	return ret;
}

void sm_copy_key(void)
{
	byte certificate_body[MDSIZE + PUBLIC_KEY_SIZE];
	byte rejected_signature[SIGNATURE_SIZE];
	byte small_order_public_key[PUBLIC_KEY_SIZE];
	hash_ctx hash;
	size_t measured_size = (uintptr_t)_fw_rw_start -
			       (uintptr_t)_fw_start;

	sbi_printf("[ZION] WARNING: insecure test keys enabled; "
		   "do not deploy this firmware\n");

	/* Explicit test identity. Production platforms must replace this seed, the
	 * sealing fixture, and the embedded device secret with provisioned,
	 * hardware-protected material. Deriving the pair here prevents mismatched
	 * placeholder key bytes from producing unauthenticatable reports. */
	ed25519_create_keypair(sm_public_key, sm_private_key, test_sm_seed);
	if (platform_get_sealing_root(sm_sealing_root,
				      sizeof(sm_sealing_root)))
		goto invalid_keys;
	sbi_memcpy(dev_public_key, _sanctum_dev_public_key, PUBLIC_KEY_SIZE);
	if (initialize_platform_random())
		goto invalid_keys;
	if (sealing_root_isolation_self_test())
		goto invalid_keys;

	/* Measure immutable firmware text and read-only data. Writable state is
	 * intentionally excluded so the digest remains stable after boot. */
	hash_init(&hash);
	hash_extend(&hash, _fw_start, measured_size);
	hash_finalize(sm_hash, &hash);

	sbi_memcpy(certificate_body, sm_hash, MDSIZE);
	sbi_memcpy(certificate_body + MDSIZE, sm_public_key,
		   PUBLIC_KEY_SIZE);
	ed25519_sign(sm_signature, certificate_body, sizeof(certificate_body),
		     _sanctum_dev_public_key, _sanctum_dev_secret_key);

	/* Fail closed if the compiled test root and generated certificate do not
	 * form a valid chain. Exercise message/signature tampering, wrong-key
	 * binding, and the classic S+L signature-malleability case at boot. */
	if (!ed25519_verify(sm_signature, certificate_body,
			    sizeof(certificate_body), dev_public_key))
		goto invalid_keys;
	certificate_body[0] ^= 1;
	if (ed25519_verify(sm_signature, certificate_body,
			   sizeof(certificate_body), dev_public_key))
		goto invalid_keys;
	certificate_body[0] ^= 1;
	if (ed25519_verify(sm_signature, certificate_body,
			   sizeof(certificate_body), sm_public_key))
		goto invalid_keys;

	sbi_memcpy(rejected_signature, sm_signature,
		   sizeof(rejected_signature));
	rejected_signature[0] ^= 1;
	if (ed25519_verify(rejected_signature, certificate_body,
			   sizeof(certificate_body), dev_public_key))
		goto invalid_keys;
	sbi_memcpy(rejected_signature, sm_signature,
		   sizeof(rejected_signature));
	malleate_signature_scalar(rejected_signature);
	if (ed25519_verify(rejected_signature, certificate_body,
			   sizeof(certificate_body), dev_public_key))
		goto invalid_keys;

	/* A=identity, R=identity, S=0 satisfies the unchecked Ed25519
	 * equation for every message. Strict verification must reject the
	 * small-order public key and R point before evaluating that equation. */
	sbi_memset(small_order_public_key, 0,
		   sizeof(small_order_public_key));
	small_order_public_key[0] = 1;
	sbi_memset(rejected_signature, 0, sizeof(rejected_signature));
	rejected_signature[0] = 1;
	if (ed25519_verify(rejected_signature, certificate_body,
			   sizeof(certificate_body), small_order_public_key))
		goto invalid_keys;

	sbi_memset(certificate_body, 0, sizeof(certificate_body));
	sbi_memset(rejected_signature, 0, sizeof(rejected_signature));
	sbi_memset(small_order_public_key, 0,
		   sizeof(small_order_public_key));
	sbi_memset(&hash, 0, sizeof(hash));
	tee_log("[SM] Test attestation chain, isolated sealing root, and random generator initialized\n");
	return;

invalid_keys:
	sbi_memset(certificate_body, 0, sizeof(certificate_body));
	sbi_memset(rejected_signature, 0, sizeof(rejected_signature));
	sbi_memset(small_order_public_key, 0,
		   sizeof(small_order_public_key));
	sbi_memset(&hash, 0, sizeof(hash));
	sbi_memset(sm_private_key, 0, sizeof(sm_private_key));
	sbi_memset(sm_sealing_root, 0, sizeof(sm_sealing_root));
	sbi_memset(platform_random_key, 0, sizeof(platform_random_key));
	platform_random_counter = 0;
	platform_random_ready = 0;
	sm_error("[SM] fatal: platform key or cryptographic self-test failed\n");
	sbi_hart_hang();
}
