// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2021-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "zcash_script.h"

#include "script/interpreter.h"
#include "version.h"

namespace {
inline int set_error(zcash_script_error* ret, zcash_script_error serror)
{
    if (ret)
        *ret = serror;
    return 0;
}
}

unsigned int zcash_script_version()
{
    // Just use the API version for now
    return ZCASH_SCRIPT_API_VER;
}

unsigned int zcash_script_legacy_sigop_count_script(
    const unsigned char* script,
    unsigned int scriptLen)
{
    CScript cscript = CScript(script, script + scriptLen);
    return cscript.GetSigOpCount(false);
}

int zcash_script_verify_callback(
    const void* ctx,
    void (*sighash)(unsigned char* sighash, unsigned int sighashLen, const void* ctx, const unsigned char* scriptCode, unsigned int scriptCodeLen, int hashType),
    int64_t nLockTime,
    uint8_t isFinal,
    const unsigned char* scriptPubKey,
    unsigned int scriptPubKeyLen,
    const unsigned char* scriptSig,
    unsigned int scriptSigLen,
    unsigned int flags,
    zcash_script_error* err)
{
    try {
        set_error(err, zcash_script_ERR_OK);
        CScriptNum nLockTimeNum = CScriptNum(nLockTime);
        ScriptError script_err = SCRIPT_ERR_OK;
        return VerifyScript(
            CScript(scriptSig, scriptSig + scriptSigLen),
            CScript(scriptPubKey, scriptPubKey + scriptPubKeyLen),
            flags,
            CallbackTransactionSignatureChecker(ctx, sighash, nLockTimeNum, isFinal != 0),
            // consensusBranchId is not longer used with the callback API; the argument
            // was left there to minimize changes to interpreter.cpp
            0,
            &script_err);
    } catch (const std::exception&) {
        return set_error(err, zcash_script_ERR_VERIFY_SCRIPT);
    }
}
