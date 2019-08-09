#ifndef _HSK_HASH_H
#define _HSK_HASH_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "blake2b.h"
#include "sha3.h"

typedef hsk_blake2b_ctx hsk_hash_blake2b_ctx;
typedef hsk_sha3_ctx hsk_hash_sha3_ctx;

void
hsk_hash_blake2b(const uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_blake2b_key(
  const uint8_t *data,
  size_t data_len,
  const uint8_t *key,
  size_t key_len,
  uint8_t *hash
);

void
hsk_hash_blake160(const uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_blake256(const uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_blake512(const uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_blake256_init(hsk_blake2b_ctx *ctx);

void
hsk_hash_blake256_update(hsk_blake2b_ctx *ctx, uint8_t *data, size_t data_len);

void
hsk_hash_blake256_final(hsk_blake2b_ctx *ctx, uint8_t *hash);

void
hsk_hash_sha3(const uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_sha3_key(
  const uint8_t *data,
  size_t data_len,
  const uint8_t *key,
  size_t key_len,
  uint8_t *hash
);

void
hsk_hash_sha3_init(hsk_sha3_ctx *ctx);

void
hsk_hash_sha3_update(hsk_sha3_ctx *ctx, uint8_t *data, size_t data_len);

void
hsk_hash_sha3_final(hsk_sha3_ctx *ctx, uint8_t *hash);

void
hsk_hash_name(const char *name, uint8_t *hash);

void
hsk_hash_sha256(const uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_hash256(const uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_sha256_hmac(
  const uint8_t *data,
  size_t data_len,
  const uint8_t *key,
  size_t key_len,
  uint8_t *mac
);

void
hsk_hash_hkdf(
  const uint8_t *secret,
  size_t secret_len,
  const uint8_t *salt,
  size_t salt_len,
  const uint8_t *info,
  size_t info_len,
  uint8_t *h1,
  uint8_t *h2
);
#endif
