// Copyright (c) 2016-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "asyncrpcoperation_sendmany.h"

#include "amount.h"
#include "asyncrpcoperation_common.h"
#include "asyncrpcqueue.h"
#include "consensus/upgrades.h"
#include "core_io.h"
#include "experimental_features.h"
#include "init.h"
#include "key_io.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "proof_verifier.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "transaction_builder.h"
#include "timedata.h"
#include "util/system.h"
#include "util/match.h"
#include "util/moneystr.h"
#include "wallet.h"
#include "walletdb.h"
#include "script/interpreter.h"
#include "util/time.h"
#include "zcash/IncrementalMerkleTree.hpp"
#include "miner.h"
#include "wallet/paymentdisclosuredb.h"
#include "wallet/wallet_tx_builder.h"

#include <array>
#include <iostream>
#include <chrono>
#include <thread>
#include <string>
#include <utility>
#include <variant>

#include <rust/ed25519.h>

using namespace libzcash;

AsyncRPCOperation_sendmany::AsyncRPCOperation_sendmany(
        TransactionBuilder builder,
        ZTXOSelector ztxoSelector,
        std::vector<ResolvedPayment> recipients,
        int minDepth,
        unsigned int anchorDepth,
        TransactionStrategy strategy,
        CAmount fee,
        UniValue contextInfo) :
        builder_(std::move(builder)), ztxoSelector_(ztxoSelector), recipients_(recipients),
        mindepth_(minDepth), anchordepth_(anchorDepth), strategy_(strategy), fee_(fee),
        contextinfo_(contextInfo)
{
    assert(fee_ >= 0);
    assert(mindepth_ >= 0);
    assert(!recipients_.empty());
    assert(ztxoSelector.RequireSpendingKeys());

    sendFromAccount_ = pwalletMain->FindAccountForSelector(ztxoSelector_).value_or(ZCASH_LEGACY_ACCOUNT);

    // Determine the target totals and recipient pools
    for (const ResolvedPayment& recipient : recipients_) {
        std::visit(match {
            [&](const CKeyID& addr) {
                txOutputAmounts_.t_outputs_total += recipient.amount;
                recipientPools_.insert(OutputPool::Transparent);
            },
            [&](const CScriptID& addr) {
                txOutputAmounts_.t_outputs_total += recipient.amount;
                recipientPools_.insert(OutputPool::Transparent);
            },
            [&](const libzcash::SaplingPaymentAddress& addr) {
                txOutputAmounts_.sapling_outputs_total += recipient.amount;
                recipientPools_.insert(OutputPool::Sapling);
            },
            [&](const libzcash::OrchardRawAddress& addr) {
                txOutputAmounts_.orchard_outputs_total += recipient.amount;
                recipientPools_.insert(OutputPool::Orchard);
                // No transaction allows sends from Sprout to Orchard.
                assert(!ztxoSelector_.SelectsSprout());
            }
        }, recipient.address);
    }

    // Log the context info i.e. the call parameters to z_sendmany
    if (LogAcceptCategory("zrpcunsafe")) {
        LogPrint("zrpcunsafe", "%s: z_sendmany initialized (params=%s)\n", getId(), contextInfo.write());
    } else {
        LogPrint("zrpc", "%s: z_sendmany initialized\n", getId());
    }
}

AsyncRPCOperation_sendmany::~AsyncRPCOperation_sendmany() {
}

void AsyncRPCOperation_sendmany::main() {
    if (isCancelled())
        return;

    set_state(OperationStatus::EXECUTING);
    start_execution_clock();

    bool success = false;

#ifdef ENABLE_MINING
    GenerateBitcoins(false, 0, Params());
#endif

    std::optional<uint256> txid;
    try {
        txid = main_impl();
    } catch (const UniValue& objError) {
        int code = find_value(objError, "code").get_int();
        std::string message = find_value(objError, "message").get_str();
        set_error_code(code);
        set_error_message(message);
    } catch (const runtime_error& e) {
        set_error_code(-1);
        set_error_message("runtime error: " + string(e.what()));
    } catch (const logic_error& e) {
        set_error_code(-1);
        set_error_message("logic error: " + string(e.what()));
    } catch (const exception& e) {
        set_error_code(-1);
        set_error_message("general exception: " + string(e.what()));
    } catch (...) {
        set_error_code(-2);
        set_error_message("unknown error");
    }

#ifdef ENABLE_MINING
    GenerateBitcoins(GetBoolArg("-gen", false), GetArg("-genproclimit", 1), Params());
#endif

    stop_execution_clock();

    if (txid.has_value()) {
        set_state(OperationStatus::SUCCESS);
    } else {
        set_state(OperationStatus::FAILED);
    }

    std::string s = strprintf("%s: z_sendmany finished (status=%s", getId(), getStateAsString());
    if (txid.has_value()) {
        s += strprintf(", txid=%s)\n", txid.value().ToString());
    } else {
        s += strprintf(", error=%s)\n", getErrorMessage());
    }
    LogPrintf("%s",s);
}

// Construct and send the transaction, returning the resulting txid.
// Errors in transaction construction will throw.
//
// Notes:
// 1. #1159 Currently there is no limit set on the number of elements, which could
//     make the tx too large.
// 2. #1360 Note selection is not optimal.
// 3. #1277 Spendable notes are not locked, so an operation running in parallel
//    could also try to use them.
// 4. #1614 Anchors are chosen at the most recent block; this is unreliable and leaks
//    information in case of rollback.
// 5. #3615 There is no padding of inputs or outputs, which may leak information.
//
// At least 4. and 5. differ from the Rust transaction builder.
uint256 AsyncRPCOperation_sendmany::main_impl() {
    CAmount sendAmount = (
        txOutputAmounts_.orchard_outputs_total +
        txOutputAmounts_.sapling_outputs_total +
        txOutputAmounts_.t_outputs_total);
    CAmount targetAmount = sendAmount + fee_;

    builder_.SetFee(fee_);

    // Allow transparent coinbase inputs if there are no transparent
    // recipients.
    bool allowTransparentCoinbase = !recipientPools_.count(OutputPool::Transparent);

    // Set the dust threshold so that we can select enough inputs to avoid
    // creating dust change amounts.
    CAmount dustThreshold{DefaultDustThreshold()};

    // Find spendable inputs, and select a minimal set of them that
    // can supply the required target amount.
    SpendableInputs spendable;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        spendable = pwalletMain->FindSpendableInputs(ztxoSelector_, allowTransparentCoinbase, mindepth_, std::nullopt);
    }
    if (!spendable.LimitToAmount(targetAmount, dustThreshold, recipientPools_)) {
        CAmount changeAmount{spendable.Total() - targetAmount};
        std::string insufficientFundsMessage =
            strprintf("Insufficient funds: have %s", FormatMoney(spendable.Total()));
        if (changeAmount > 0 && changeAmount < dustThreshold) {
            // TODO: we should provide the option for the caller to explicitly
            // forego change (definitionally an amount below the dust amount)
            // and send the extra to the recipient or the miner fee to avoid
            // creating dust change, rather than prohibit them from sending
            // entirely in this circumstance.
            // (Daira disagrees, as this could leak information to the recipient
            // or to an external viewing key holder.)
            insufficientFundsMessage +=
                strprintf(
                    ", need %s more to avoid creating invalid change output %s (dust threshold is %s)",
                    FormatMoney(dustThreshold - changeAmount),
                    FormatMoney(changeAmount),
                    FormatMoney(dustThreshold));
        } else {
            insufficientFundsMessage += strprintf(", need %s", FormatMoney(targetAmount));
        }
        bool isFromUa = std::holds_alternative<libzcash::UnifiedAddress>(ztxoSelector_.GetPattern());
        throw JSONRPCError(
                RPC_WALLET_INSUFFICIENT_FUNDS,
                insufficientFundsMessage
                + (allowTransparentCoinbase && ztxoSelector_.SelectsTransparentCoinbase() ? "." :
                   "; note that coinbase outputs will not be selected if you specify "
                   "ANY_TADDR or if any transparent recipients are included.")
                + ((!isFromUa || strategy_.AllowLinkingAccountAddresses()) ? "" :
                   " (This transaction may require selecting transparent coins that were sent "
                   "to multiple Unified Addresses, which is not enabled by default because "
                   "it would create a public link between the transparent receivers of these "
                   "addresses. THIS MAY AFFECT YOUR PRIVACY. Resubmit with the `privacyPolicy` "
                   "parameter set to `AllowLinkingAccountAddresses` or weaker if you wish to "
                   "allow this transaction to proceed anyway.)"));
    }

    if (!(spendable.utxos.empty() || strategy_.AllowRevealedSenders())) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "This transaction requires selecting transparent coins, which is "
            "not enabled by default because it will publicly reveal transaction "
            "senders and amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit "
            "with the `privacyPolicy` parameter set to `AllowRevealedSenders` "
            "or weaker if you wish to allow this transaction to proceed anyway.");
    }

    if (recipientPools_.count(OutputPool::Transparent) && !strategy_.AllowRevealedRecipients()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "This transaction would have transparent recipients, which is not "
            "enabled by default because it will publicly reveal transaction "
            "recipients and amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit "
            "with the `privacyPolicy` parameter set to `AllowRevealedRecipients` "
            "or weaker if you wish to allow this transaction to proceed anyway.");
    }

    if (!spendable.sproutNoteEntries.empty()) {
        if (recipientPools_.count(OutputPool::Sapling) && !strategy_.AllowRevealedAmounts()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Sending from the Sprout shielded pool to the Sapling "
                "shielded pool is not enabled by default because it will "
                "publicly reveal the transaction amount. THIS MAY AFFECT YOUR PRIVACY. "
                "Resubmit with the `privacyPolicy` parameter set to `AllowRevealedAmounts` "
                "or weaker if you wish to allow this transaction to proceed anyway.");
        }
    }

    if (!spendable.saplingNoteEntries.empty()) {
        if (recipientPools_.count(OutputPool::Orchard) && !strategy_.AllowRevealedAmounts()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Sending from the Sapling shielded pool to the Orchard "
                "shielded pool is not enabled by default because it will "
                "publicly reveal the transaction amount. THIS MAY AFFECT YOUR PRIVACY. "
                "Resubmit with the `privacyPolicy` parameter set to `AllowRevealedAmounts` "
                "or weaker if you wish to allow this transaction to proceed anyway.");
        }
        // Sending from Sapling to transparent will be caught above in the
        // AllowRevealedRecipients check; sending to Sprout is disallowed
        // entirely.
    }

    if (!spendable.orchardNoteMetadata.empty()) {
        if (recipientPools_.count(OutputPool::Sapling) && !strategy_.AllowRevealedAmounts()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Sending from the Orchard shielded pool to the Sapling "
                "shielded pool is not enabled by default because it will "
                "publicly reveal the transaction amount. THIS MAY AFFECT YOUR PRIVACY. "
                "Resubmit with the `privacyPolicy` parameter set to `AllowRevealedAmounts` "
                "or weaker if you wish to allow this transaction to proceed anyway.");
        }

        // Sending from Orchard to transparent will be caught above in the
        // AllowRevealedRecipients check; sending to Sprout is disallowed
        // entirely.

        if (spendable.orchardNoteMetadata.size() > nOrchardActionLimit) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "Attempting to spend %u Orchard notes would exceed the current limit "
                    "of %u notes, which exists to prevent memory exhaustion. Restart with "
                    "`-orchardactionlimit=N` where N >= %u to allow the wallet to attempt "
                    "to construct this transaction.",
                    spendable.orchardNoteMetadata.size(),
                    nOrchardActionLimit,
                    spendable.orchardNoteMetadata.size()));
        }
    }

    spendable.LogInputs(getId());

    CAmount t_inputs_total{0};
    CAmount z_inputs_total{0};
    for (const auto& t : spendable.utxos) {
        t_inputs_total += t.Value();
    }
    for (const auto& t : spendable.sproutNoteEntries) {
        z_inputs_total += t.note.value();
    }
    for (const auto& t : spendable.saplingNoteEntries) {
        z_inputs_total += t.note.value();
    }
    for (const auto& t : spendable.orchardNoteMetadata) {
        z_inputs_total += t.GetNoteValue();
    }

    if (z_inputs_total > 0 && mindepth_ == 0) {
        throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Minconf cannot be zero when sending from a shielded address");
    }

    // When spending transparent coinbase outputs, all inputs must be fully
    // consumed, and they may only be sent to shielded recipients.
    if (spendable.HasTransparentCoinbase()) {
        if (t_inputs_total + z_inputs_total != targetAmount) {
            throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    strprintf(
                        "When shielding coinbase funds, the wallet does not allow any change. "
                        "The proposed transaction would result in %s in change.",
                        FormatMoney(t_inputs_total - targetAmount)
                        ));
        }
        if (txOutputAmounts_.t_outputs_total != 0) {
            throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    "Coinbase funds may only be sent to shielded recipients.");
        }
    }

    LogPrint("zrpcunsafe", "%s: spending %s to send %s with fee %s\n",
        getId(), FormatMoney(targetAmount), FormatMoney(sendAmount), FormatMoney(fee_));
    LogPrint("zrpc", "%s: total transparent input: %s (to choose from)\n", getId(), FormatMoney(t_inputs_total));
    LogPrint("zrpcunsafe", "%s: total shielded input: %s (to choose from)\n", getId(), FormatMoney(z_inputs_total));
    LogPrint("zrpc", "%s: total transparent output: %s\n", getId(), FormatMoney(txOutputAmounts_.t_outputs_total));
    LogPrint("zrpcunsafe", "%s: total shielded Sapling output: %s\n", getId(), FormatMoney(txOutputAmounts_.sapling_outputs_total));
    LogPrint("zrpcunsafe", "%s: total shielded Orchard output: %s\n", getId(), FormatMoney(txOutputAmounts_.orchard_outputs_total));
    LogPrint("zrpc", "%s: fee: %s\n", getId(), FormatMoney(fee_));

    // Allow change to go to any pool for which we have recipients.
    std::set<OutputPool> allowedChangeTypes = recipientPools_;

    // We always allow shielded change when not sending from the legacy account.
    if (sendFromAccount_ != ZCASH_LEGACY_ACCOUNT) {
        allowedChangeTypes.insert(OutputPool::Sapling);
    }

    auto ovks = this->SelectOVKs(spendable);
    auto allowChangeTypes = [&](const std::set<ReceiverType>& receiverTypes) {
        for (ReceiverType rtype : receiverTypes) {
            switch (rtype) {
                case ReceiverType::P2PKH:
                case ReceiverType::P2SH:
                    if (!spendable.utxos.empty() || strategy_.AllowRevealedRecipients()) {
                        allowedChangeTypes.insert(OutputPool::Transparent);
                    }
                    break;
                case ReceiverType::Sapling:
                    if (!spendable.saplingNoteEntries.empty() || strategy_.AllowRevealedAmounts()) {
                        allowedChangeTypes.insert(OutputPool::Sapling);
                    }
                    break;
                case ReceiverType::Orchard:
                    if (builder_.SupportsOrchard() &&
                            (!spendable.orchardNoteMetadata.empty() || strategy_.AllowRevealedAmounts())) {
                        allowedChangeTypes.insert(OutputPool::Orchard);
                    }
                    break;
            }
        }
    };

    std::visit(match {
        [&](const CKeyID& keyId) {
            allowedChangeTypes.insert(OutputPool::Transparent);
            auto changeAddr = pwalletMain->GenerateChangeAddressForAccount(
                    sendFromAccount_, allowedChangeTypes);
            assert(changeAddr.has_value());
            builder_.SendChangeTo(changeAddr.value(), ovks.first);
        },
        [&](const CScriptID& scriptId) {
            allowedChangeTypes.insert(OutputPool::Transparent);
            auto changeAddr = pwalletMain->GenerateChangeAddressForAccount(
                    sendFromAccount_, allowedChangeTypes);
            assert(changeAddr.has_value());
            builder_.SendChangeTo(changeAddr.value(), ovks.first);
        },
        [&](const libzcash::SproutPaymentAddress& addr) {
            // for Sprout, we return change to the originating address.
            builder_.SendChangeToSprout(addr);
        },
        [&](const libzcash::SproutViewingKey& vk) {
            // for Sprout, we return change to the originating address.
            builder_.SendChangeToSprout(vk.address());
        },
        [&](const libzcash::SaplingPaymentAddress& addr) {
            // for Sapling, if using a legacy address, return change to the
            // originating address; otherwise return it to the Sapling internal
            // address corresponding to the UFVK.
            if (sendFromAccount_ == ZCASH_LEGACY_ACCOUNT) {
                builder_.SendChangeTo(addr, ovks.first);
            } else {
                auto changeAddr = pwalletMain->GenerateChangeAddressForAccount(
                        sendFromAccount_, allowedChangeTypes);
                assert(changeAddr.has_value());
                builder_.SendChangeTo(changeAddr.value(), ovks.first);
            }
        },
        [&](const libzcash::SaplingExtendedFullViewingKey& fvk) {
            // for Sapling, if using a legacy address, return change to the
            // originating address; otherwise return it to the Sapling internal
            // address corresponding to the UFVK.
            if (sendFromAccount_ == ZCASH_LEGACY_ACCOUNT) {
                builder_.SendChangeTo(fvk.DefaultAddress(), ovks.first);
            } else {
                auto changeAddr = pwalletMain->GenerateChangeAddressForAccount(
                        sendFromAccount_, allowedChangeTypes);
                assert(changeAddr.has_value());
                builder_.SendChangeTo(changeAddr.value(), ovks.first);
            }
        },
        [&](const libzcash::UnifiedAddress& ua) {
            allowChangeTypes(ua.GetKnownReceiverTypes());

            auto zufvk = pwalletMain->GetUFVKForAddress(ua);
            if (!zufvk.has_value()) {
                throw JSONRPCError(
                        RPC_WALLET_ERROR,
                        "Could not determine full viewing key for unified address.");
            }

            auto changeAddr = zufvk.value().GetChangeAddress(allowedChangeTypes);
            if (!changeAddr.has_value()) {
                throw JSONRPCError(
                        RPC_WALLET_ERROR,
                        "Could not generate a change address from the inferred full viewing key.");
            }
            builder_.SendChangeTo(changeAddr.value(), ovks.first);
        },
        [&](const libzcash::UnifiedFullViewingKey& fvk) {
            allowChangeTypes(fvk.GetKnownReceiverTypes());
            auto zufvk = ZcashdUnifiedFullViewingKey::FromUnifiedFullViewingKey(Params(), fvk);
            auto changeAddr = zufvk.GetChangeAddress(allowedChangeTypes);
            if (!changeAddr.has_value()) {
                throw JSONRPCError(
                        RPC_WALLET_ERROR,
                        "Could not generate a change address from the specified full viewing key.");
            }
            builder_.SendChangeTo(changeAddr.value(), ovks.first);
        },
        [&](const AccountZTXOPattern& acct) {
            allowChangeTypes(acct.GetReceiverTypes());
            auto changeAddr = pwalletMain->GenerateChangeAddressForAccount(
                        acct.GetAccountId(),
                        allowedChangeTypes);

            assert(changeAddr.has_value());
            builder_.SendChangeTo(changeAddr.value(), ovks.first);
        }
    }, ztxoSelector_.GetPattern());

    // Track the total of notes that we've added to the builder. This
    // shouldn't strictly be necessary, given `spendable.LimitToAmount`
    CAmount sum = 0;

    // Create Sapling outpoints
    std::vector<SaplingOutPoint> saplingOutPoints;
    std::vector<SaplingNote> saplingNotes;
    std::vector<SaplingExtendedSpendingKey> saplingKeys;

    for (const auto& t : spendable.saplingNoteEntries) {
        saplingOutPoints.push_back(t.op);
        saplingNotes.push_back(t.note);

        libzcash::SaplingExtendedSpendingKey saplingKey;
        assert(pwalletMain->GetSaplingExtendedSpendingKey(t.address, saplingKey));
        saplingKeys.push_back(saplingKey);

        sum += t.note.value();
        if (sum >= targetAmount) {
            break;
        }
    }

    // Fetch Sapling anchor and witnesses, and Orchard Merkle paths.
    uint256 anchor;
    std::vector<std::optional<SaplingWitness>> witnesses;
    std::vector<std::pair<libzcash::OrchardSpendingKey, orchard::SpendInfo>> orchardSpendInfo;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        if (!pwalletMain->GetSaplingNoteWitnesses(saplingOutPoints, anchordepth_, witnesses, anchor)) {
            // This error should not appear once we're nAnchorConfirmations blocks past
            // Sapling activation.
            throw JSONRPCError(RPC_WALLET_ERROR, "Insufficient Sapling witnesses.");
        }
        if (builder_.GetOrchardAnchor().has_value()) {
            orchardSpendInfo = pwalletMain->GetOrchardSpendInfo(spendable.orchardNoteMetadata, builder_.GetOrchardAnchor().value());
        }
    }

    // Add Orchard spends
    for (size_t i = 0; i < orchardSpendInfo.size(); i++) {
        auto spendInfo = std::move(orchardSpendInfo[i]);
        if (!builder_.AddOrchardSpend(
            std::move(spendInfo.first),
            std::move(spendInfo.second)))
        {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf("Failed to add Orchard note to transaction (check %s for details)", GetDebugLogPath())
            );
        }
    }

    // Add Sapling spends
    for (size_t i = 0; i < saplingNotes.size(); i++) {
        if (!witnesses[i]) {
            throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    strprintf(
                        "Missing witness for Sapling note at outpoint %s",
                        spendable.saplingNoteEntries[i].op.ToString())
                    );
        }

        builder_.AddSaplingSpend(saplingKeys[i].expsk, saplingNotes[i], anchor, witnesses[i].value());
    }

    // Add outputs
    for (const auto& r : recipients_) {
        std::visit(match {
            [&](const CKeyID& keyId) {
                builder_.AddTransparentOutput(keyId, r.amount);
            },
            [&](const CScriptID& scriptId) {
                builder_.AddTransparentOutput(scriptId, r.amount);
            },
            [&](const libzcash::SaplingPaymentAddress& addr) {
                builder_.AddSaplingOutput(
                        ovks.second, addr, r.amount,
                        r.memo.has_value() ? r.memo.value().ToBytes() : Memo::NoMemo().ToBytes());
            },
            [&](const libzcash::OrchardRawAddress& addr) {
                builder_.AddOrchardOutput(
                        ovks.second, addr, r.amount,
                        r.memo.has_value() ? std::optional(r.memo.value().ToBytes()) : std::nullopt);
            }
        }, r.address);
    }

    // Add transparent utxos
    for (const auto& out : spendable.utxos) {
        const CTxOut& txOut = out.tx->vout[out.i];
        builder_.AddTransparentInput(COutPoint(out.tx->GetHash(), out.i), txOut.scriptPubKey, txOut.nValue);

        sum += txOut.nValue;
        if (sum >= targetAmount) {
            break;
        }
    }

    // Find Sprout witnesses
    // When spending notes, take a snapshot of note witnesses and anchors as the treestate will
    // change upon arrival of new blocks which contain joinsplit transactions.  This is likely
    // to happen as creating a chained joinsplit transaction can take longer than the block interval.
    // So, we need to take locks on cs_main and pwalletMain->cs_wallet so that the witnesses aren't
    // updated.
    //
    // TODO: these locks would ideally be shared for selection of Sapling anchors and witnesses
    // as well.
    std::vector<std::optional<SproutWitness>> vSproutWitnesses;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        std::vector<JSOutPoint> vOutPoints;
        for (const auto& t : spendable.sproutNoteEntries) {
            vOutPoints.push_back(t.jsop);
        }

        // inputAnchor is not needed by builder_.AddSproutInput as it is for Sapling.
        uint256 inputAnchor;
        if (!pwalletMain->GetSproutNoteWitnesses(vOutPoints, anchordepth_, vSproutWitnesses, inputAnchor)) {
            // This error should not appear once we're nAnchorConfirmations blocks past
            // Sprout activation.
            throw JSONRPCError(RPC_WALLET_ERROR, "Insufficient Sprout witnesses.");
        }
    }

    // Add Sprout spends
    for (int i = 0; i < spendable.sproutNoteEntries.size(); i++) {
        const auto& t = spendable.sproutNoteEntries[i];
        libzcash::SproutSpendingKey sk;
        assert(pwalletMain->GetSproutSpendingKey(t.address, sk));

        builder_.AddSproutInput(sk, t.note, vSproutWitnesses[i].value());

        sum += t.note.value();
        if (sum >= targetAmount) {
            break;
        }
    }

    // Build the transaction
    auto buildResult = builder_.Build();
    auto tx = buildResult.GetTxOrThrow();

    UniValue sendResult = SendTransaction(tx, recipients_, std::nullopt, testmode);
    set_result(sendResult);

    return tx.GetHash();
}

std::pair<uint256, uint256> AsyncRPCOperation_sendmany::SelectOVKs(const SpendableInputs& spendable) const {
    uint256 internalOVK;
    uint256 externalOVK;
    if (!spendable.orchardNoteMetadata.empty()) {
        std::optional<OrchardFullViewingKey> fvk;
        std::visit(match {
            [&](const UnifiedAddress& addr) {
                auto ufvk = pwalletMain->GetUFVKForAddress(addr);
                // This is safe because spending key checks will have ensured that we
                // have a UFVK corresponding to this address, and Orchard notes will
                // not have been selected if the UFVK does not contain an Orchard key.
                fvk = ufvk.value().GetOrchardKey().value();
            },
            [&](const UnifiedFullViewingKey& ufvk) {
                // Orchard notes will not have been selected if the UFVK does not contain
                // an Orchard key.
                fvk = ufvk.GetOrchardKey().value();
            },
            [&](const AccountZTXOPattern& acct) {
                // By definition, we have a UFVK for every known account.
                auto ufvk = pwalletMain->GetUnifiedFullViewingKeyByAccount(acct.GetAccountId());
                // Orchard notes will not have been selected if the UFVK does not contain
                // an Orchard key.
                fvk = ufvk.value().GetOrchardKey().value();
            },
            [&](const auto& other) {
                throw std::runtime_error("SelectOVKs: Selector cannot select Orchard notes.");
            }
        }, this->ztxoSelector_.GetPattern());
        assert(fvk.has_value());

        internalOVK = fvk.value().ToInternalOutgoingViewingKey();
        externalOVK = fvk.value().ToExternalOutgoingViewingKey();
    } else if (!spendable.saplingNoteEntries.empty()) {
        std::optional<SaplingDiversifiableFullViewingKey> dfvk;
        std::visit(match {
            [&](const libzcash::SaplingPaymentAddress& addr) {
                libzcash::SaplingExtendedSpendingKey extsk;
                assert(pwalletMain->GetSaplingExtendedSpendingKey(addr, extsk));
                dfvk = extsk.ToXFVK();
            },
            [&](const UnifiedAddress& addr) {
                auto ufvk = pwalletMain->GetUFVKForAddress(addr);
                // This is safe because spending key checks will have ensured that we
                // have a UFVK corresponding to this address, and Sapling notes will
                // not have been selected if the UFVK does not contain a Sapling key.
                dfvk = ufvk.value().GetSaplingKey().value();
            },
            [&](const UnifiedFullViewingKey& ufvk) {
                // Sapling notes will not have been selected if the UFVK does not contain
                // a Sapling key.
                dfvk = ufvk.GetSaplingKey().value();
            },
            [&](const AccountZTXOPattern& acct) {
                // By definition, we have a UFVK for every known account.
                auto ufvk = pwalletMain->GetUnifiedFullViewingKeyByAccount(acct.GetAccountId());
                // Sapling notes will not have been selected if the UFVK does not contain
                // a Sapling key.
                dfvk = ufvk.value().GetSaplingKey().value();
            },
            [&](const auto& other) {
                throw std::runtime_error("SelectOVKs: Selector cannot select Sapling notes.");
            }
        }, this->ztxoSelector_.GetPattern());
        assert(dfvk.has_value());

        auto ovks = dfvk.value().GetOVKs();
        internalOVK = ovks.first;
        externalOVK = ovks.second;
    } else if (!spendable.utxos.empty()) {
        std::optional<transparent::AccountPubKey> tfvk;
        std::visit(match {
            [&](const CKeyID& keyId) {
                tfvk = pwalletMain->GetLegacyAccountKey().ToAccountPubKey();
            },
            [&](const CScriptID& keyId) {
                tfvk = pwalletMain->GetLegacyAccountKey().ToAccountPubKey();
            },
            [&](const UnifiedAddress& addr) {
                // This is safe because spending key checks will have ensured that we
                // have a UFVK corresponding to this address, and transparent UTXOs will
                // not have been selected if the UFVK does not contain a transparent key.
                auto ufvk = pwalletMain->GetUFVKForAddress(addr);
                tfvk = ufvk.value().GetTransparentKey().value();
            },
            [&](const UnifiedFullViewingKey& ufvk) {
                // Transparent UTXOs will not have been selected if the UFVK does not contain
                // a transparent key.
                tfvk = ufvk.GetTransparentKey().value();
            },
            [&](const AccountZTXOPattern& acct) {
                if (acct.GetAccountId() == ZCASH_LEGACY_ACCOUNT) {
                    tfvk = pwalletMain->GetLegacyAccountKey().ToAccountPubKey();
                } else {
                    // By definition, we have a UFVK for every known account.
                    auto ufvk = pwalletMain->GetUnifiedFullViewingKeyByAccount(acct.GetAccountId()).value();
                    // Transparent UTXOs will not have been selected if the UFVK does not contain
                    // a transparent key.
                    tfvk = ufvk.GetTransparentKey().value();
                }
            },
            [&](const auto& other) {
                throw std::runtime_error("SelectOVKs: Selector cannot select transparent UTXOs.");
            }
        }, this->ztxoSelector_.GetPattern());
        assert(tfvk.has_value());

        auto ovks = tfvk.value().GetOVKsForShielding();
        internalOVK = ovks.first;
        externalOVK = ovks.second;
    } else if (!spendable.sproutNoteEntries.empty()) {
        // use the legacy transparent account OVKs when sending from Sprout
        auto tfvk = pwalletMain->GetLegacyAccountKey().ToAccountPubKey();
        auto ovks = tfvk.GetOVKsForShielding();
        internalOVK = ovks.first;
        externalOVK = ovks.second;
    } else {
        // This should be unreachable; it is left in place as a guard to ensure
        // that when new input types are added to SpendableInputs in the future
        // that we do not accidentally return the all-zeros OVK.
        throw std::runtime_error("No spendable inputs.");
    }

    return std::make_pair(internalOVK, externalOVK);
}

/**
 * Compute a dust threshold based upon a standard p2pkh txout.
 */
CAmount AsyncRPCOperation_sendmany::DefaultDustThreshold() {
    CKey secret{CKey::TestOnlyRandomKey(true)};
    CScript scriptPubKey = GetScriptForDestination(secret.GetPubKey().GetID());
    CTxOut txout(CAmount(1), scriptPubKey);
    // TODO: use a local for minRelayTxFee rather than a global
    return txout.GetDustThreshold(minRelayTxFee);
}

/**
 * Override getStatus() to append the operation's input parameters to the default status object.
 */
UniValue AsyncRPCOperation_sendmany::getStatus() const {
    UniValue v = AsyncRPCOperation::getStatus();
    if (contextinfo_.isNull()) {
        return v;
    }

    UniValue obj = v.get_obj();
    obj.pushKV("method", "z_sendmany");
    obj.pushKV("params", contextinfo_ );
    return obj;
}
