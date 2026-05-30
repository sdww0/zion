/*
 * OpenSBI ecall extension registration for Keystone SM.
 *
 * sm.c already registers the extension in sm_init().
 * This file is kept for the zion_init() glue but does nothing extra.
 */
void keystone_register_ecall(void)
{
	/* sm_init() already registers ecall_keystone_enclave */
}
