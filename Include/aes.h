#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm.

#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
#endif

#define AES128 1
// #define AES192 1
// #define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16
    #define AES_keyExpSize 176
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct AES_ctx {
  uint8_t RoundKey[AES_keyExpSize];
#if (CBC == 1) || (CTR == 1)
  uint8_t Iv[AES_BLOCKLEN];
#endif
};

// Initialization
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
#if (CBC == 1) || (CTR == 1)
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif

// ECB mode
#if (ECB == 1)
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
#endif

// CBC mode
#if (CBC == 1)
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
#endif

// CTR mode
#if (CTR == 1)
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#ifdef __cplusplus
}
#endif

#endif // _AES_H_
