//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "crypto.h"
#include "page.h"
#include <sbi/sbi_string.h>

static const unsigned char sealing_kdf_label[] = "ZION-SM-SEALING-KEY";
static const unsigned char sealing_kdf_salt[] =
  "ZION-SM-SEALING-ROOT-SHA3-512-v1";

static void store_be32(unsigned char output[4], uint32_t value)
{
  output[0] = value >> 24;
  output[1] = value >> 16;
  output[2] = value >> 8;
  output[3] = value;
}

void hash_init(hash_ctx* ctx)
{
  sha3_init(ctx, MDSIZE);
}

void hash_extend(hash_ctx* ctx, const void* ptr, size_t len)
{
  sha3_update(ctx, ptr, len);
}

void hash_extend_page(hash_ctx* ctx, const void* ptr)
{
  sha3_update(ctx, ptr, RISCV_PGSIZE);
}

void hash_finalize(void* md, hash_ctx* ctx)
{
  sha3_final(md, ctx);
}

void sign(void* sign, const void* data, size_t len, const unsigned char* public_key, const unsigned char* private_key)
{
  ed25519_sign(sign, data, len, public_key, private_key);
}

int kdf(const unsigned char* salt, size_t salt_len,
        const unsigned char* ikm, size_t ikm_len,
        const unsigned char* info, size_t info_len,
        unsigned char* okm, size_t okm_len)
{
  return hkdf_sha3_512(salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len);
}

int kdf_derive_sealing_key_v1(const unsigned char *root, size_t root_size,
        const unsigned char *measurement, size_t measurement_size,
        const unsigned char *identity, size_t identity_size,
        unsigned char *key, size_t key_size,
        unsigned char *workspace, size_t workspace_size)
{
  size_t required_size;
  size_t offset = 0;
  int ret = -1;

  if (sizeof(sealing_kdf_label) - 1 + 4 * sizeof(uint32_t) !=
      SEALING_KDF_V1_INFO_OVERHEAD ||
      !root || !root_size || !measurement || !measurement_size ||
      (identity_size && !identity) || !key || !key_size || !workspace ||
      root_size > 0x7fffffffUL || measurement_size > 0xffffffffUL ||
      identity_size > 0xffffffffUL ||
      key_size > 255 * MDSIZE)
    goto out;

  required_size = SEALING_KDF_V1_INFO_OVERHEAD + measurement_size +
                  identity_size;
  if (required_size > workspace_size || required_size > 0x7fffffffUL)
    goto out;

  sbi_memcpy(workspace + offset, sealing_kdf_label,
             sizeof(sealing_kdf_label) - 1);
  offset += sizeof(sealing_kdf_label) - 1;
  store_be32(workspace + offset, SEALING_KDF_VERSION);
  offset += sizeof(uint32_t);
  store_be32(workspace + offset, measurement_size);
  offset += sizeof(uint32_t);
  store_be32(workspace + offset, identity_size);
  offset += sizeof(uint32_t);
  store_be32(workspace + offset, key_size);
  offset += sizeof(uint32_t);
  sbi_memcpy(workspace + offset, measurement, measurement_size);
  offset += measurement_size;
  if (identity_size)
    sbi_memcpy(workspace + offset, identity, identity_size);

  ret = kdf(sealing_kdf_salt, sizeof(sealing_kdf_salt) - 1,
            root, root_size, workspace, required_size, key, key_size);

out:
  if (workspace && workspace_size)
    sbi_memset(workspace, 0, workspace_size);
  if (ret && key && key_size <= 255 * MDSIZE)
    sbi_memset(key, 0, key_size);
  return ret;
}
