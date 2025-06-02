// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2021-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZCASH_SCRIPT_ZCASH_SCRIPT_H
#define ZCASH_SCRIPT_ZCASH_SCRIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "script_error.h"

#if defined(BUILD_BITCOIN_INTERNAL) && defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
  #if defined(_WIN32)
    #if defined(DLL_EXPORT)
      #if defined(HAVE_FUNC_ATTRIBUTE_DLLEXPORT)
        #define EXPORT_SYMBOL __declspec(dllexport)
      #else
        #define EXPORT_SYMBOL
      #endif
    #endif
  #elif defined(HAVE_FUNC_ATTRIBUTE_VISIBILITY)
    #define EXPORT_SYMBOL __attribute__ ((visibility ("default")))
  #endif
#elif defined(MSC_VER) && !defined(STATIC_LIBZCASHCONSENSUS)
  #define EXPORT_SYMBOL __declspec(dllimport)
#endif

#ifndef EXPORT_SYMBOL
  #define EXPORT_SYMBOL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ZCASH_SCRIPT_API_VER 4

/** Script verification flags */
enum
{
    zcash_script_SCRIPT_FLAGS_VERIFY_NONE                = 0,
    zcash_script_SCRIPT_FLAGS_VERIFY_P2SH                = (1U << 0), // evaluate P2SH (BIP16) subscripts
    zcash_script_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9), // enable CHECKLOCKTIMEVERIFY (BIP65)
};

/// Returns the current version of the zcash_script library.
EXPORT_SYMBOL unsigned int zcash_script_version();

/// Returns the number of transparent signature operations in the input or
/// output script pointed to by script.
EXPORT_SYMBOL unsigned int zcash_script_legacy_sigop_count_script(
    const unsigned char* script,
    unsigned int scriptLen);

/// Returns 1 if the a transparent input correctly spends the matching output
/// under the additional constraints specified by flags. This function
/// receives only the required information to validate the spend and not
/// the transaction itself. In particular, the sighash for the spend
/// is obtained using a callback function.
///
/// - ctx: an opaque pointer which is forwarded to the callback. It can be used
///   to store context regarding the spend (i.e. the transaction itself,
///   and any precomputed data).
/// - sighash: a callback function which is called to obtain the sighash.
///   - sighash: pointer to a buffer where the sighash must be written to.
///   - sighashLen: the length of the buffer. Will be 32.
///   - ctx: the same opaque pointer
///   - scriptCode: the scriptCode being validated. Note that this not always
///     matches scriptSig, i.e. for P2SH.
///   - scriptCodeLen: the length of the script.
///   - hashType: the hash type being used.
/// - nLockTime: the lock time of the transaction being validated.
/// - isFinal: a boolean indicating whether the input being validated is final
///   (i.e. its sequence number is 0xFFFFFFFF).
/// - scriptPubKey: the scriptPubKey of the output being spent.
/// - scriptPubKeyLen: the length of scriptPubKey.
/// - scriptSig: the scriptSig of the input being validated.
/// - scriptSigLen: the length of scriptSig.
/// - flags: the script verification flags to use.
/// - err: if not NULL, err will contain an error/success code for the operation.
///
/// Note that script verification failure is indicated by a return value of 0.
EXPORT_SYMBOL int zcash_script_verify_callback(
    const void* ctx,
    void (*sighash)(unsigned char* sighash, unsigned int sighashLen, const void* ctx, const unsigned char* scriptCode, unsigned int scriptCodeLen, int hashType),
    int64_t nLockTime,
    uint8_t isFinal,
    const unsigned char* scriptPubKey,
    unsigned int scriptPubKeyLen,
    const unsigned char* scriptSig,
    unsigned int scriptSigLen,
    unsigned int flags,
    ScriptError* err);

EXPORT_SYMBOL struct ZcashScriptState {
    unsigned char const** stack;
    size_t* stackElemLen;
    size_t stackLen;
    unsigned char const** altstack;
    size_t* altstackElemLen;
    size_t altstackLen;
    char* vfExec;
    size_t vfExecLen;
    int nOpCount;
};

EXPORT_SYMBOL int zcash_script_eval_step(
    unsigned int flags,
    const void* ctx,
    void (*sighash)(unsigned char* sighash, unsigned int sighashLen, const void* ctx, const unsigned char* scriptCode, unsigned int scriptCodeLen, int hashType),
    int64_t nLockTime,
    uint8_t isFinal,
    struct ZcashScriptState* state,
    unsigned char const* script,
    size_t scriptLen,
    size_t* pc,
    ScriptError* serror);

#ifdef __cplusplus
} // extern "C"
#endif

#undef EXPORT_SYMBOL

#endif // ZCASH_SCRIPT_ZCASH_SCRIPT_H
