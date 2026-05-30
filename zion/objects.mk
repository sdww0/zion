# Zion TEE framework — now using Keystone SM core
#
# Keystone SM requires TARGET_PLATFORM_HEADER to find platform.h
platform-genflags-y += -DTARGET_PLATFORM_HEADER=\"platform/zion/platform.h\"
platform-genflags-y += -I$(src_dir)/zion/src
# Must come before system includes so our headers are found first

# Core SM files (from keystone-ref/sm/src/)
zion-objs-y += src/enclave.o
zion-objs-y += src/thread.o
zion-objs-y += src/cpu.o
zion-objs-y += src/pmp.o
zion-objs-y += src/ipi.o
zion-objs-y += src/mprv.o
zion-objs-y += src/sm.o
zion-objs-y += src/sm-sbi.o
zion-objs-y += src/attest.o
zion-objs-y += src/sbi_trap_hack.o
zion-objs-y += src/trap.o

# Crypto (from keystone-ref)
zion-objs-y += src/crypto.o
zion-objs-y += src/sha3/sha3.o
zion-objs-y += src/ed25519/fe.o
zion-objs-y += src/ed25519/ge.o
zion-objs-y += src/ed25519/keypair.o
zion-objs-y += src/ed25519/sc.o
zion-objs-y += src/ed25519/sign.o
zion-objs-y += src/hkdf_sha3_512/hkdf_sha3_512.o
zion-objs-y += src/hmac_sha3/hmac_sha3.o

# Platform hooks (Zion-specific)
zion-objs-y += src/platform/zion/platform.o

# OpenSBI integration (Zion glue layer)
zion-objs-y += src/zion.o
zion-objs-y += src/sm-sbi-opensbi.o
zion-objs-y += src/tee-sbi-opensbi.o
zion-objs-y += src/plugins/plugins.o
zion-objs-y += src/plugins/multimem.o
zion-objs-y += src/trap_exit.o
