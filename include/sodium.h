
#ifndef sodium_H
#define sodium_H

#ifndef sodium_export_H
#define sodium_export_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#if !defined(__clang__) && !defined(__GNUC__)
#ifdef __attribute__
#undef __attribute__
#endif
#define __attribute__(a)
#endif

#ifdef SODIUM_STATIC
#define SODIUM_EXPORT
#define SODIUM_EXPORT_WEAK
#else
#if defined(_MSC_VER)
#ifdef SODIUM_DLL_EXPORT
#define SODIUM_EXPORT __declspec(dllexport)
#else
#define SODIUM_EXPORT __declspec(dllimport)
#endif
#else
#if defined(__SUNPRO_C)
#ifndef __GNU_C__
#define SODIUM_EXPORT __attribute__(visibility(__global))
#else
#define SODIUM_EXPORT __attribute__ __global
#endif
#elif defined(_MSG_VER)
#define SODIUM_EXPORT extern __declspec(dllexport)
#else
#define SODIUM_EXPORT __attribute__((visibility("default")))
#endif
#endif
#if defined(__ELF__) && !defined(SODIUM_DISABLE_WEAK_FUNCTIONS)
#define SODIUM_EXPORT_WEAK SODIUM_EXPORT __attribute__((weak))
#else
#define SODIUM_EXPORT_WEAK SODIUM_EXPORT
#endif
#endif

#ifndef CRYPTO_ALIGN
#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#define CRYPTO_ALIGN(x) __declspec(align(x))
#else
#define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#endif
#endif

#define SODIUM_MIN(A, B) ((A) < (B) ? (A) : (B))
#define SODIUM_SIZE_MAX SODIUM_MIN(UINT64_MAX, SIZE_MAX)

#endif

extern "C"
{

#define crypto_generichash_blake2b_PERSONALBYTES 16U
    SODIUM_EXPORT
    size_t crypto_generichash_blake2b_personalbytes(void);

    typedef struct CRYPTO_ALIGN(64) crypto_generichash_blake2b_state
    {
        unsigned char opaque[384];
    } crypto_generichash_blake2b_state;

    SODIUM_EXPORT
    int crypto_generichash_blake2b_init_salt_personal(crypto_generichash_blake2b_state *state,
                                                      const unsigned char *key,
                                                      const size_t keylen, const size_t outlen,
                                                      const unsigned char *salt,
                                                      const unsigned char *personal)
        __attribute__((nonnull(1)));

    SODIUM_EXPORT
    int crypto_generichash_blake2b_update(crypto_generichash_blake2b_state *state,
                                          const unsigned char *in,
                                          unsigned long long inlen)
        __attribute__((nonnull(1)));

    SODIUM_EXPORT
    int crypto_generichash_blake2b_final(crypto_generichash_blake2b_state *state,
                                         unsigned char *out,
                                         const size_t outlen) __attribute__((nonnull));
}

#endif
