// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2021-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "zcash_script.h"

#include <iostream>
#include <vector>

#include "script/interpreter.h"
#include "script/script_error.h"
#include "version.h"

namespace {
inline int set_error(ScriptError* ret, ScriptError serror)
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
    ScriptError* script_err)
{
    try {
        CScriptNum nLockTimeNum = CScriptNum(nLockTime);
        return VerifyScript(
            CScript(scriptSig, scriptSig + scriptSigLen),
            CScript(scriptPubKey, scriptPubKey + scriptPubKeyLen),
            flags,
            CallbackTransactionSignatureChecker(ctx, sighash, nLockTimeNum, isFinal != 0),
            // consensusBranchId is not longer used with the callback API; the argument
            // was left there to minimize changes to interpreter.cpp
            0,
            script_err);
    } catch (const std::exception&) {
        return set_error(script_err, SCRIPT_ERR_VERIFY_SCRIPT);
    }
}

std::vector<std::vector<unsigned char>> create_stack(
    unsigned char const* const* elems,
    size_t const* elemLens,
    size_t len)
{
    std::vector<std::vector<unsigned char>> stack(len);
    std::vector<size_t> realStackElemLen(elemLens, elemLens + len);
    for (size_t i = 0; i < len; ++i) {
        std::vector<unsigned char> elem(elems[i], elems[i] + realStackElemLen[i]);
        stack[i] = elem;
    }
    return stack;
}

/// Copy the vector back to the C-compatible components for FFI.
void update_stack(
    std::vector<std::vector<unsigned char>> const& stack,
    unsigned char const**& elems,
    size_t*& elemLens,
    size_t& len)
{
    std::vector<unsigned char const*>* stackPtr = new std::vector<unsigned char const*>(stack.size());
    std::vector<size_t>* stackLenPtr = new std::vector<size_t>(stack.size());
    auto real_it = stack.begin();
    auto ptr_it = stackPtr->begin();
    auto len_ptr_it = stackLenPtr->begin();
    for (;
         real_it != stack.end();
         ++real_it, ++ptr_it, ++len_ptr_it) {
        *ptr_it = real_it->data();
        *len_ptr_it = real_it->size();
    }
    elems = stackPtr->data();
    elemLens = stackLenPtr->data();
    len = stack.size();
}

int zcash_script_eval_step(
    unsigned int flags,
    const void* ctx,
    void (*sighash)(unsigned char* sighash, unsigned int sighashLen, const void* ctx, const unsigned char* scriptCode, unsigned int scriptCodeLen, int hashType),
    int64_t nLockTime,
    uint8_t isFinal,
    struct ZcashScriptState* state,
    unsigned char const* script,
    size_t scriptLen,
    size_t* pc,
    ScriptError* serror)
{
    try {
        CScript scriptCode(script, script + scriptLen);
        std::vector<std::vector<unsigned char>> realStack =
            create_stack(state->stack, state->stackElemLen, state->stackLen);
        std::vector<std::vector<unsigned char>> realAltstack =
            create_stack(state->altstack, state->altstackElemLen, state->altstackLen);
        std::vector<bool> realVfExec(state->vfExec, state->vfExec + state->vfExecLen);
        State* realState = new State{realStack, realAltstack, realVfExec, state->nOpCount};
        CScript::const_iterator it = scriptCode.begin() + *pc;
        CScriptNum nLockTimeNum = CScriptNum(nLockTime);

        bool result = EvalStep(
            *realState,
            scriptCode,
            it,
            flags,
            CallbackTransactionSignatureChecker(ctx, sighash, nLockTimeNum, isFinal != 0),
            0,
            serror);
        *pc = it - scriptCode.begin();
        update_stack(realState->stack, state->stack, state->stackElemLen, state->stackLen);
        update_stack(realState->altstack, state->altstack, state->altstackElemLen, state->altstackLen);
        std::vector<char>* vfExecPtr = new std::vector<char>(realState->vfExec.size());
        auto ereal_it = realState->vfExec.begin();
        auto eptr_it = vfExecPtr->begin();
        for (;
             ereal_it != realState->vfExec.end();
             ++ereal_it, ++eptr_it) {
            *eptr_it = *ereal_it;
        }
        state->vfExec = vfExecPtr->data();
        state->vfExecLen = realState->vfExec.size();
        state->nOpCount = realState->nOpCount;
        return result;
    } catch (const std::exception&) {
        return set_error(serror, SCRIPT_ERR_VERIFY_SCRIPT);
    }
}
