// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include "script_error.h"
#include "primitives/transaction.h"

#include <rust/transaction.h>

#include <vector>
#include <stdint.h>
#include <string>
#include <climits>

class CPubKey;
class CScript;
class CTransaction;
class uint256;

/** Special case nIn for signing JoinSplits. */
const unsigned int NOT_AN_INPUT = UINT_MAX;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

/** Script verification flags */
enum
{
    SCRIPT_VERIFY_NONE      = 0,

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    SCRIPT_VERIFY_P2SH      = (1U << 0),

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (softfork safe, but not used or intended as a consensus rule).
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    // In Zcash this is required, and validation of non-strict-DER signatures is not implemented.
    //SCRIPT_VERIFY_DERSIG    = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (softfork safe, BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S     = (1U << 3),

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4),

    // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    // (softfork safe)
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS  = (1U << 7),

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (softfork safe, BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH.
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),
};

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, unsigned int flags, ScriptError* serror);

struct PrecomputedTransactionData
{
    uint256 hashPrevouts, hashSequence, hashOutputs, hashJoinSplits, hashShieldedSpends, hashShieldedOutputs;
    /** Precomputed transaction parts. */
    std::unique_ptr<PrecomputedTxParts, decltype(&zcash_transaction_precomputed_free)> preTx;

    PrecomputedTransactionData(
        const CTransaction& tx,
        const std::vector<CTxOut>& allPrevOutputs);

    PrecomputedTransactionData(
        const CTransaction& tx,
        const unsigned char* allPrevOutputs,
        size_t allPrevOutputsLen);

private:
    void SetPrecomputed(
        const CTransaction& tx,
        const unsigned char* allPrevOutputs,
        size_t allPrevOutputsLen);
};

enum SigVersion
{
    SIGVERSION_SPROUT = 0,
    SIGVERSION_OVERWINTER = 1,
    SIGVERSION_SAPLING = 2,
    SIGVERSION_ZIP244 = 3,
};

uint256 SignatureHash(
    const CScript &scriptCode,
    const CTransaction& txTo,
    unsigned int nIn,
    int nHashType,
    const CAmount& amount,
    uint32_t consensusBranchId,
    const PrecomputedTransactionData& txdata);

class BaseSignatureChecker
{
public:
    virtual bool CheckSig(
        const std::vector<unsigned char>& scriptSig,
        const std::vector<unsigned char>& vchPubKey,
        const CScript& scriptCode,
        uint32_t consensusBranchId) const
    {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum& nLockTime) const
    {
         return false;
    }

    virtual ~BaseSignatureChecker() {}
};

class TransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const CTransaction* txTo;
    unsigned int nIn;
    const CAmount amount;
    const PrecomputedTransactionData& txdata;

protected:
    virtual bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;

public:
    TransactionSignatureChecker(const CTransaction* txToIn, const PrecomputedTransactionData& txdataIn, unsigned int nInIn, const CAmount& amountIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(txdataIn) {}
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, uint32_t consensusBranchId) const;
    bool CheckLockTime(const CScriptNum& nLockTime) const;
};

class MutableTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    const CTransaction txTo;

public:
    MutableTransactionSignatureChecker(const CMutableTransaction* txToIn, const PrecomputedTransactionData& txdataIn, unsigned int nInIn, const CAmount& amount) : TransactionSignatureChecker(&txTo, txdataIn, nInIn, amount), txTo(*txToIn) {}
};

class CallbackTransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const void* tx;
    void (*sighash)(unsigned char* sighash, const void* tx, const unsigned char* scriptCode, unsigned int scriptCodeLen, int hashType);
    const CScriptNum& nLockTime;
    bool isFinal;
    unsigned int nIn;
    const CAmount amount;

protected:
    virtual bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;

public:
    CallbackTransactionSignatureChecker(const void* tx, void (*sighash)(unsigned char* sighash, const void* tx, const unsigned char* scriptCode, unsigned int scriptCodeLen, int hashType), const CScriptNum& nLockTime, bool isFinal, unsigned int nInIn, const CAmount& amountIn) : tx(tx), sighash(sighash), nLockTime(nLockTime), isFinal(isFinal), nIn(nInIn), amount(amountIn) {}
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, uint32_t consensusBranchId) const;
    bool CheckLockTime(const CScriptNum& nLockTime) const;
};


bool EvalScript(
    std::vector<std::vector<unsigned char> >& stack,
    const CScript& script,
    unsigned int flags,
    const BaseSignatureChecker& checker,
    uint32_t consensusBranchId,
    ScriptError* error = NULL);
bool VerifyScript(
    const CScript& scriptSig,
    const CScript& scriptPubKey,
    unsigned int flags,
    const BaseSignatureChecker& checker,
    uint32_t consensusBranchId,
    ScriptError* serror = NULL);

#endif // BITCOIN_SCRIPT_INTERPRETER_H
