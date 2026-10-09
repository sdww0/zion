# Zion TEE framework — native implementation
#
platform-genflags-y += -DTARGET_PLATFORM_HEADER=\"platform/zion/platform.h\"
platform-genflags-y += -I$(src_dir)/zion/src
# Zion headers still used for data structure compatibility
platform-genflags-y += -I$(src_dir)/zion/src/zion-enclave

# DEBUG=1 is the normal OpenSBI debug build switch.  ZION_DEBUG=1 permits
# verbose monitor logging without also changing the optimizer to -O0.
ifneq ($(filter 1 y yes true,$(DEBUG) $(ZION_DEBUG)),)
platform-genflags-y += -DZION_DEBUG
endif

# The repository contains deterministic identity material solely for emulator
# and bring-up regression images.  A full monitor build must opt in explicitly;
# production platforms are expected to replace platform.c's provider first.
ifneq ($(filter 1 y yes true,$(ZION_INSECURE_TEST_KEYS)),)
platform-genflags-y += -DZION_INSECURE_TEST_KEYS
endif

# Test packages may inject an ephemeral device identity without modifying the
# checked-in regression key. The header path must be visible in the build
# environment (for example, below the mounted workspace in a container).
ifneq ($(strip $(ZION_TEST_KEY_HEADER)),)
platform-genflags-y += -DZION_TEST_KEY_HEADER=\"$(ZION_TEST_KEY_HEADER)\"
endif

# Megrez bring-up builds enable an early, non-destructive H/PMP capability
# check. Failure keeps the normal OpenSBI boot chain alive but leaves the Zion
# SBI extension unregistered.
ifneq ($(filter 1 y yes true,$(ZION_MEGREZ_PREFLIGHT)),)
platform-genflags-y += -DZION_MEGREZ_PREFLIGHT
endif

ifneq ($(filter 1 y yes true,$(ZION_MEGREZ_ACTIVATE)),)
platform-genflags-y += -DZION_MEGREZ_ACTIVATE
endif

# EIC7700X has only eight PMP entries and its OpenSBI platform code already
# consumes entries for board-specific root-domain ranges.  Keep that hardware
# layout and insert the CVM pool dynamically instead of replacing every entry
# with the enclave allocator's fixed layout.
ifneq ($(filter 1 y yes true,$(ZION_DYNAMIC_PMP)),)
platform-genflags-y += -DZION_DYNAMIC_PMP
endif

# Environment-configuration CSRs were added after Priv v1.11/H v0.6.  Keep
# them enabled for existing platforms, but compile every access out of Megrez
# probe builds unless the caller explicitly opts in with ZION_USE_ENVCFG=1.
zion-disable-envcfg :=
ifneq ($(filter 1 y yes true,$(ZION_MEGREZ_PREFLIGHT)),)
ifeq ($(strip $(ZION_USE_ENVCFG)),)
zion-disable-envcfg := y
endif
endif
ifneq ($(filter 0 n no false,$(ZION_USE_ENVCFG)),)
zion-disable-envcfg := y
endif
ifneq ($(zion-disable-envcfg),)
platform-genflags-y += -DZION_DISABLE_ENVCFG
endif

# Phase-0 hardware probing must not pull the full monitor, crypto workspace,
# CVM slots, or enclave metadata into OpenSBI.  This keeps the first board
# image close to the vendor firmware's memory layout and guarantees that the
# probe cannot register or activate Zion's SBI ABI.
ifneq ($(filter 1 y yes true,$(ZION_MEGREZ_MINIMAL_PREFLIGHT)),)
platform-genflags-y += -DZION_MEGREZ_MINIMAL_PREFLIGHT
zion-objs-y += src/megrez-preflight.o
else

# PMP management (from zion — hardware abstraction, not enclave logic)
ifneq ($(filter 1 y yes true,$(ZION_DYNAMIC_PMP)),)
zion-objs-y += src/pmp.o
else
zion-objs-y += src/zion-enclave/pmp.o
endif
zion-objs-y += src/zion-enclave/ipi.o
zion-objs-y += src/mprv.o

# Crypto
zion-objs-y += src/crypto.o
zion-objs-y += src/sha3/sha3.o
zion-objs-y += src/ed25519/fe.o
zion-objs-y += src/ed25519/ge.o
zion-objs-y += src/ed25519/keypair.o
zion-objs-y += src/ed25519/sc.o
zion-objs-y += src/ed25519/sign.o
zion-objs-y += src/ed25519/verify.o
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
zion-objs-y += src/fp.o
zion-objs-y += src/tee-mem.o
zion-objs-y += src/tee-trap-handler.o
zion-objs-y += src/tee-trap.o
zion-objs-y += src/enclave.o

endif
