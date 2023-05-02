// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2021-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "zcash_script.h"

#include "consensus/upgrades.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "version.h"

namespace {
inline int set_error(zcash_script_error* ret, zcash_script_error serror)
{
    if (ret)
        *ret = serror;
    return 0;
}

struct ECCryptoClosure
{
    ECCVerifyHandle handle;
};

ECCryptoClosure instance_of_eccryptoclosure;

// Copy of GetLegacySigOpCount from main.cpp commit c4b2ef7c4.
// Replace with the copy from src/consensus/tx_verify.{cpp,h} after backporting that refactor.
unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const CTxIn& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const CTxOut& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}
}

struct PrecomputedTransaction {
    const CTransaction tx;
    const PrecomputedTransactionData txdata;

    PrecomputedTransaction(
        CTransaction txIn,
        const unsigned char* allPrevOutputs,
        size_t allPrevOutputsLen) : tx(txIn), txdata(txIn, allPrevOutputs, allPrevOutputsLen) {}
};

void* zcash_script_new_precomputed_tx(
    const unsigned char* txTo,
    unsigned int txToLen,
    zcash_script_error* err)
{
    try {
        const char* txToEnd = (const char *)(txTo + txToLen);
        RustDataStream stream((const char *)txTo, txToEnd, SER_NETWORK, PROTOCOL_VERSION);
        CTransaction tx;
        stream >> tx;
        if (GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) != txToLen) {
            set_error(err, zcash_script_ERR_TX_SIZE_MISMATCH);
            return nullptr;
        }
        if (tx.nVersion >= ZIP225_TX_VERSION) {
            set_error(err, zcash_script_ERR_TX_VERSION);
            return nullptr;
        }

        // Deserializing the tx did not error.
        set_error(err, zcash_script_ERR_OK);
        // This is a pre-v5 tx, so the PrecomputedTransactionData constructor
        // field `allPrevOutputs` is not used.
        auto preTx = new PrecomputedTransaction(tx, nullptr, 0);
        return preTx;
    } catch (const std::exception&) {
        set_error(err, zcash_script_ERR_TX_DESERIALIZE); // Error deserializing
        return nullptr;
    }
}

void* zcash_script_new_precomputed_tx_v5(
    const unsigned char* txTo,
    unsigned int txToLen,
    const unsigned char* allPrevOutputs,
    unsigned int allPrevOutputsLen,
    zcash_script_error* err)
{
    CTransaction tx;
    try {
        const char* txToEnd = (const char *)(txTo + txToLen);
        RustDataStream stream((const char *)txTo, txToEnd, SER_NETWORK, PROTOCOL_VERSION);
        stream >> tx;
        if (GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) != txToLen) {
            set_error(err, zcash_script_ERR_TX_SIZE_MISMATCH);
            return nullptr;
        }
    } catch (const std::exception&) {
        set_error(err, zcash_script_ERR_TX_DESERIALIZE); // Error deserializing
        return nullptr;
    }

    try {
        auto preTx = new PrecomputedTransaction(tx, allPrevOutputs, allPrevOutputsLen);
        // Deserializing the tx did not error.
        set_error(err, zcash_script_ERR_OK);
        return preTx;
    } catch (const std::exception&) {
        // We had some error when parsing allPrevOutputs inside the
        // PrecomputedTransactionData constructor.
        set_error(err, zcash_script_ERR_ALL_PREV_OUTPUTS_DESERIALIZE);
        return nullptr;
    }
}

void zcash_script_free_precomputed_tx(void* pre_preTx)
{
    PrecomputedTransaction* preTx = static_cast<PrecomputedTransaction*>(pre_preTx);
    delete preTx;
    preTx = nullptr;
}

int zcash_script_verify_precomputed(
    const void* pre_preTx,
    unsigned int nIn,
    const unsigned char* scriptPubKey,
    unsigned int scriptPubKeyLen,
    int64_t amount,
    unsigned int flags,
    uint32_t consensusBranchId,
    zcash_script_error* err)
{
    const PrecomputedTransaction* preTx = static_cast<const PrecomputedTransaction*>(pre_preTx);
    if (nIn >= preTx->tx.vin.size())
        return set_error(err, zcash_script_ERR_TX_INDEX);

    // Regardless of the verification result, the tx did not error.
    set_error(err, zcash_script_ERR_OK);
    return VerifyScript(
        preTx->tx.vin[nIn].scriptSig,
        CScript(scriptPubKey, scriptPubKey + scriptPubKeyLen),
        flags,
        TransactionSignatureChecker(&preTx->tx, preTx->txdata, nIn, amount),
        consensusBranchId,
        NULL);
}

int zcash_script_verify(
    const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen,
    int64_t amount,
    const unsigned char *txTo, unsigned int txToLen,
    unsigned int nIn, unsigned int flags,
    uint32_t consensusBranchId,
    zcash_script_error* err)
{
    try {
        const char* txToEnd = (const char *)(txTo + txToLen);
        RustDataStream stream((const char *)txTo, txToEnd, SER_NETWORK, PROTOCOL_VERSION);
        CTransaction tx;
        stream >> tx;
        if (nIn >= tx.vin.size())
            return set_error(err, zcash_script_ERR_TX_INDEX);
        if (GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) != txToLen)
            return set_error(err, zcash_script_ERR_TX_SIZE_MISMATCH);
        if (tx.nVersion >= ZIP225_TX_VERSION) {
            return set_error(err, zcash_script_ERR_TX_VERSION);
        }

         // Regardless of the verification result, the tx did not error.
        set_error(err, zcash_script_ERR_OK);
        // This is a pre-v5 tx, so the PrecomputedTransactionData constructor
        // field `allPrevOutputs` is not used.
        PrecomputedTransactionData txdata(tx, {});
        return VerifyScript(
            tx.vin[nIn].scriptSig,
            CScript(scriptPubKey, scriptPubKey + scriptPubKeyLen),
            flags,
            TransactionSignatureChecker(&tx, txdata, nIn, amount),
            consensusBranchId,
            NULL);
    } catch (const std::exception&) {
        return set_error(err, zcash_script_ERR_TX_DESERIALIZE); // Error deserializing
    }
}

int zcash_script_verify_v5(
    const unsigned char* txTo,
    unsigned int txToLen,
    const unsigned char* allPrevOutputs,
    unsigned int allPrevOutputsLen,
    unsigned int nIn,
    unsigned int flags,
    uint32_t consensusBranchId,
    zcash_script_error* err)
{
    CTransaction tx;
    try {
        const char* txToEnd = (const char *)(txTo + txToLen);
        RustDataStream stream((const char *)txTo, txToEnd, SER_NETWORK, PROTOCOL_VERSION);
        stream >> tx;
        if (nIn >= tx.vin.size())
            return set_error(err, zcash_script_ERR_TX_INDEX);
        if (GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) != txToLen)
            return set_error(err, zcash_script_ERR_TX_SIZE_MISMATCH);
    } catch (const std::exception&) {
        return set_error(err, zcash_script_ERR_TX_DESERIALIZE); // Error deserializing
    }

    std::vector<CTxOut> prevOutputs;
    try {
        // TODO: we can swap this second deserialization for an FFI call by
        // fetching this through PrecomputedTransactionData. Simplicity for now.
        CDataStream sAllPrevOutputs(
            reinterpret_cast<const char*>(allPrevOutputs),
            reinterpret_cast<const char*>(allPrevOutputs + allPrevOutputsLen),
            SER_NETWORK,
            PROTOCOL_VERSION);
        sAllPrevOutputs >> prevOutputs;
        if (!(tx.IsCoinBase() ? prevOutputs.empty() : tx.vin.size() == prevOutputs.size())) {
            return set_error(err, zcash_script_ERR_ALL_PREV_OUTPUTS_SIZE_MISMATCH);
        }
    } catch (const std::exception&) {
        // We had some error when parsing allPrevOutputs inside the
        // PrecomputedTransactionData constructor.
        return set_error(err, zcash_script_ERR_ALL_PREV_OUTPUTS_DESERIALIZE);
    }

    try {
        // Regardless of the verification result, the tx did not error.
        set_error(err, zcash_script_ERR_OK);
        PrecomputedTransactionData txdata(tx, allPrevOutputs, allPrevOutputsLen);
        return VerifyScript(
            tx.vin[nIn].scriptSig,
            prevOutputs[nIn].scriptPubKey,
            flags,
            TransactionSignatureChecker(&tx, txdata, nIn, prevOutputs[nIn].nValue),
            consensusBranchId,
            NULL);
    } catch (const std::exception&) {
        return set_error(err, zcash_script_ERR_VERIFY_SCRIPT); // Error during script verification
    }
}

unsigned int zcash_script_legacy_sigop_count_precomputed(
    const void* pre_preTx,
    zcash_script_error* err)
{
    const PrecomputedTransaction* preTx = static_cast<const PrecomputedTransaction*>(pre_preTx);

    // The current implementation of this method never errors.
    set_error(err, zcash_script_ERR_OK);

    return GetLegacySigOpCount(preTx->tx);
}

unsigned int zcash_script_legacy_sigop_count(
    const unsigned char *txTo,
    unsigned int txToLen,
    zcash_script_error* err)
{
    try {
        const char* txToEnd = (const char *)(txTo + txToLen);
        RustDataStream stream((const char *)txTo, txToEnd, SER_NETWORK, PROTOCOL_VERSION);
        CTransaction tx;
        stream >> tx;
        if (GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) != txToLen) {
            set_error(err, zcash_script_ERR_TX_SIZE_MISMATCH);
            return UINT_MAX;
        }

        // Deserializing the tx did not error.
        set_error(err, zcash_script_ERR_OK);

        return GetLegacySigOpCount(tx);
    } catch (const std::exception&) {
        set_error(err, zcash_script_ERR_TX_DESERIALIZE); // Error deserializing
        return UINT_MAX;
    }
}

unsigned int zcash_script_version()
{
    // Just use the API version for now
    return ZCASH_SCRIPT_API_VER;
}
