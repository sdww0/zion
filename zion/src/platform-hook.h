#ifndef _PLATFORM_HOOK_H_
#define _PLATFORM_HOOK_H_

#include "enclave.h"

/* These functions are defined by platform/soc specific objects,
   defined in platform/$PLATFORM/$PLATFORM.c */

/* This fires once FOR EACH sm supported enclave during init of
   enclave metadata. It may not fail currently. */
void platform_init_enclave(struct enclave* enclave);

/* Validate the minimum hardware contract before Zion installs SBI handlers or
 * owns PMP entries. Returning an error disables Zion while allowing OpenSBI to
 * continue booting the next stage, which is useful for board bring-up. */
unsigned long platform_security_preflight(void);

/* Optional environment-configuration CSR accessors.  Platforms must make
 * these no-ops when the corresponding CSR was compiled out or did not pass a
 * trap-safe runtime probe. */
bool platform_has_menvcfg(void);
bool platform_has_henvcfg(void);
unsigned long platform_menvcfg_read(void);
unsigned long platform_henvcfg_read(void);
void platform_menvcfg_write(unsigned long value);
void platform_henvcfg_write(unsigned long value);
void platform_menvcfg_clear(unsigned long mask);

/* Return the second CPU-visible physical address for the same DRAM range.
 * Platforms without aliased DRAM return false.  Security callers must apply
 * the same PMP policy to both addresses when this returns true. */
bool platform_security_alias(uintptr_t base, size_t size, uintptr_t *alias);

/* This fires once GLOBALLY before any other platform init */
unsigned long platform_init_global_once(void);
/* Fires once per-hart after global_once */
unsigned long platform_init_global(void);

/* Load a persistent, platform-protected sealing root. The monitor fails
 * closed if the platform cannot provide exactly the requested size. */
unsigned long platform_get_sealing_root(unsigned char *root, size_t size);

/* Load a dedicated boot-time random seed. Production implementations must
 * obtain fresh, hardware-backed entropy rather than a compiled fixture. */
#define PLATFORM_RANDOM_SEED_SIZE 64
unsigned long platform_get_random_seed(unsigned char *seed, size_t size);

/* This fires once each time an enclave is created by the sm */
unsigned long platform_create_enclave(struct enclave* enclave);

/* This fires once each time an enclave is destroyed by the sm */
void platform_destroy_enclave(struct enclave* enclave);

/* This fires when context switching INTO an enclave from the OS */
void platform_switch_to_enclave(struct enclave* enclave);

/* This fires when context switching OUT of an enclave into the OS */
void platform_switch_from_enclave(struct enclave* enclave);

/* Future version: This fires when context switching from enclave A to
   enclave B */
// void platform_switch_between_enclaves(platform_enclave_data* enclaveA,
//                                       platform_enclave_data* enclaveB);

/* This is a required feature. It returns 64 bits from the initialized
 * platform generator and fails closed on unavailable or exhausted state. */
uint64_t platform_random(void);

#endif /* _PLATFORM_HOOK_H_ */
