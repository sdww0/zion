# Zion TEE framework — native implementation
#
platform-genflags-y += -DTARGET_PLATFORM_HEADER=\"platform/zion/platform.h\"
platform-genflags-y += -I$(src_dir)/zion/src
# Keystone headers still used for data structure compatibility
platform-genflags-y += -I$(src_dir)/zion/src/keystone

# PMP management (from keystone — hardware abstraction, not enclave logic)
# The other files in keystone are not used, but we keep these code for now.
zion-objs-y += src/keystone/pmp.o
zion-objs-y += src/keystone/ipi.o
zion-objs-y += src/mprv.o

# Crypto
zion-objs-y += src/crypto.o
zion-objs-y += src/sha3/sha3.o
zion-objs-y += src/ed25519/fe.o
zion-objs-y += src/ed25519/ge.o
zion-objs-y += src/ed25519/keypair.o
zion-objs-y += src/ed25519/sc.o
zion-objs-y += src/ed25519/sign.o
zion-objs-y += src/hkdf_sha3_512/hkdf_sha3_512.o
zion-objs-y += src/hmac_sha3/hmac_sha3.o

# Platform hooks
zion-objs-y += src/platform/zion/platform.o

# OpenSBI integration (Zion glue layer)
zion-objs-y += src/zion.o
zion-objs-y += src/tee-sbi-opensbi.o
zion-objs-y += src/plugins/plugins.o
zion-objs-y += src/plugins/multimem.o

# Zion TEE infrastructure (CVM + Enclave)
zion-objs-y += src/tee.o
zion-objs-y += src/tee-sbi.o
zion-objs-y += src/cvm.o
zion-objs-y += src/ree.o
zion-objs-y += src/context.o
zion-objs-y += src/tee-mem.o
zion-objs-y += src/tee-trap-handler.o
zion-objs-y += src/tee-trap.o
zion-objs-y += src/enclave.o
