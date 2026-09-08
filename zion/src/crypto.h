//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <sbi/sbi_types.h>
#include "sha3/sha3.h"
#include "ed25519/ed25519.h"
#include "hkdf_sha3_512/hkdf_sha3_512.h"

typedef sha3_ctx_t hash_ctx;
#define MDSIZE  64

#define SIGNATURE_SIZE  64
#define PRIVATE_KEY_SIZE  64 // includes public key
#define PUBLIC_KEY_SIZE 32
#define SEALING_ROOT_SIZE 64

#define SEALING_KDF_VERSION 1
/* "ZION-SM-SEALING-KEY" plus four big-endian 32-bit fields. */
#define SEALING_KDF_V1_INFO_OVERHEAD 35

typedef unsigned char byte;

extern byte sm_hash[MDSIZE];
extern byte sm_signature[SIGNATURE_SIZE];
extern byte sm_public_key[PUBLIC_KEY_SIZE];
extern byte sm_private_key[PRIVATE_KEY_SIZE];
extern byte sm_sealing_root[SEALING_ROOT_SIZE];

void hash_init(hash_ctx* hash_ctx);
void hash_extend(hash_ctx* hash_ctx, const void* ptr, size_t len);
void hash_extend_page(hash_ctx* hash_ctx, const void* ptr);
void hash_finalize(void* md, hash_ctx* hash_ctx);

void sign(void* sign, const void* data, size_t len, const byte* public_key, const byte* private_key);
int kdf(const unsigned char* salt, size_t salt_len,
        const unsigned char* ikm, size_t ikm_len,
        const unsigned char* info, size_t info_len,
        unsigned char* okm, size_t okm_len);
int kdf_derive_sealing_key_v1(const unsigned char *root, size_t root_size,
        const unsigned char *measurement, size_t measurement_size,
        const unsigned char *identity, size_t identity_size,
        unsigned char *key, size_t key_size,
        unsigned char *workspace, size_t workspace_size);
#endif /* crypto.h */
