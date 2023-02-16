// Copyright (c) 2021-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "tinyformat.h"
#include "zcash/Address.hpp"
#include "unified.h"
#include "util/match.h"
#include "util/strencodings.h"

#include <rust/unified_keys.h>

using namespace libzcash;

//
// Unified Keys
//

bool libzcash::HasShielded(const std::set<ReceiverType>& receiverTypes) {
    auto has_shielded = [](ReceiverType r) {
        // TODO: update this as support for new shielded protocols is added.
        return r == ReceiverType::Sapling || r == ReceiverType::Orchard;
    };
    return std::find_if(receiverTypes.begin(), receiverTypes.end(), has_shielded) != receiverTypes.end();
}

bool libzcash::HasTransparent(const std::set<ReceiverType>& receiverTypes) {
    auto has_transparent = [](ReceiverType r) {
        // TODO: update this as support for new transparent protocols is added.
        return r == ReceiverType::P2PKH || r == ReceiverType::P2SH;
    };
    return std::find_if(receiverTypes.begin(), receiverTypes.end(), has_transparent) != receiverTypes.end();
}

Receiver libzcash::RecipientAddressToReceiver(const RecipientAddress& recipient) {
    return std::visit(match {
        [](const CKeyID& key) { return Receiver(key); },
        [](const CScriptID& scriptId) { return Receiver(scriptId); },
        [](const libzcash::OrchardRawAddress& addr) { return Receiver(addr); },
        [](const libzcash::SaplingPaymentAddress& addr) { return Receiver(addr); }
    }, recipient);
}

std::string libzcash::DebugPrintReceiver(const Receiver& receiver) {
    return std::visit(match {
        [&](const OrchardRawAddress &zaddr) {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << zaddr;
            return tfm::format("Orchard(%s)", HexStr(ss.begin(), ss.end()));
        },
        [&](const SaplingPaymentAddress &zaddr) {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << zaddr;
            return tfm::format("Sapling(%s)", HexStr(ss.begin(), ss.end()));
        },
        [&](const CScriptID &p2sh) {
            return tfm::format("P2SH(%s)", p2sh.GetHex());
        },
        [&](const CKeyID &p2pkh) {
            return tfm::format("P2PKH(%s)", p2pkh.GetHex());
        },
        [&](const UnknownReceiver &unknown) {
            return tfm::format(
                "Unknown(%x, %s)",
                unknown.typecode,
                HexStr(unknown.data.begin(), unknown.data.end()));
        }
    }, receiver);
};

std::string libzcash::DebugPrintRecipientAddress(const RecipientAddress& addr) {
    return DebugPrintReceiver(RecipientAddressToReceiver(addr));
}

std::optional<ZcashdUnifiedSpendingKey> ZcashdUnifiedSpendingKey::ForAccount(
        const HDSeed& seed,
        uint32_t bip44CoinType,
        AccountId accountId) {

    auto transparentKey = transparent::AccountKey::ForAccount(seed, bip44CoinType, accountId);
    if (!transparentKey.has_value()) return std::nullopt;

    auto saplingKey = SaplingExtendedSpendingKey::ForAccount(seed, bip44CoinType, accountId);

    auto orchardKey = OrchardSpendingKey::ForAccount(seed, bip44CoinType, accountId);

    return ZcashdUnifiedSpendingKey(transparentKey.value(), saplingKey.first, orchardKey);
}

UnifiedFullViewingKey ZcashdUnifiedSpendingKey::ToFullViewingKey() const {
    UnifiedFullViewingKeyBuilder builder;

    builder.AddTransparentKey(transparentKey.ToAccountPubKey());
    builder.AddSaplingKey(saplingKey.ToXFVK());
    builder.AddOrchardKey(orchardKey.ToFullViewingKey());

    // This call to .value() is safe as ZcashdUnifiedSpendingKey values are always
    // constructed to contain all required components.
    return builder.build().value();
}

ZcashdUnifiedFullViewingKey ZcashdUnifiedFullViewingKey::FromUnifiedFullViewingKey(
        const KeyConstants& keyConstants,
        const UnifiedFullViewingKey& ufvk) {
    ZcashdUnifiedFullViewingKey result;
    result.keyId = ufvk.GetKeyID(keyConstants);

    auto transparentKey = ufvk.GetTransparentKey();
    if (transparentKey.has_value()) {
        result.transparentKey = transparentKey.value();
    }

    auto saplingKey = ufvk.GetSaplingKey();
    if (saplingKey.has_value()) {
        result.saplingKey = saplingKey.value();
    }

    auto orchardKey = ufvk.GetOrchardKey();
    if (orchardKey.has_value()) {
        result.orchardKey = orchardKey.value();
    }

    return result;
}

UnifiedAddressGenerationResult ZcashdUnifiedFullViewingKey::Address(
        const diversifier_index_t& j,
        const std::set<ReceiverType>& receiverTypes) const
{
    if (!HasShielded(receiverTypes)) {
        return UnifiedAddressGenerationError::ShieldedReceiverNotFound;
    }

    if (receiverTypes.count(ReceiverType::P2SH) > 0) {
        return UnifiedAddressGenerationError::ReceiverTypeNotAvailable;
    }

    UnifiedAddress ua;
    if (receiverTypes.count(ReceiverType::Orchard) > 0) {
        if (orchardKey.has_value()) {
            ua.AddReceiver(orchardKey.value().ToIncomingViewingKey().Address(j));
        } else {
            return UnifiedAddressGenerationError::ReceiverTypeNotAvailable;
        }
    }

    if (receiverTypes.count(ReceiverType::Sapling) > 0) {
        if (saplingKey.has_value()) {
            auto saplingAddress = saplingKey.value().Address(j);
            if (saplingAddress.has_value()) {
                ua.AddReceiver(saplingAddress.value());
            } else {
                return UnifiedAddressGenerationError::NoAddressForDiversifier;
            }
        } else {
            return UnifiedAddressGenerationError::ReceiverTypeNotAvailable;
        }
    }

    if (receiverTypes.count(ReceiverType::P2PKH) > 0) {
        if (transparentKey.has_value()) {
            const auto& tkey = transparentKey.value();

            auto childIndex = j.ToTransparentChildIndex();
            if (!childIndex.has_value()) return UnifiedAddressGenerationError::InvalidTransparentChildIndex;

            auto externalPubkey = tkey.DeriveExternal(childIndex.value());
            if (!externalPubkey.has_value()) return UnifiedAddressGenerationError::NoAddressForDiversifier;

            ua.AddReceiver(externalPubkey.value().GetID());
        } else {
            return UnifiedAddressGenerationError::ReceiverTypeNotAvailable;
        }
    }

    return std::make_pair(ua, j);
}

UnifiedAddressGenerationResult ZcashdUnifiedFullViewingKey::FindAddress(
        const diversifier_index_t& j,
        const std::set<ReceiverType>& receiverTypes) const {
    diversifier_index_t j0(j);
    bool hasTransparent = HasTransparent(receiverTypes);
    do {
        auto addr = Address(j0, receiverTypes);
        if (addr != UnifiedAddressGenerationResult(UnifiedAddressGenerationError::NoAddressForDiversifier)) {
            return addr;
        }
    } while (j0.increment());

    return UnifiedAddressGenerationError::DiversifierSpaceExhausted;
}

UnifiedAddressGenerationResult ZcashdUnifiedFullViewingKey::FindAddress(
        const diversifier_index_t& j) const {
    return FindAddress(j, {ReceiverType::P2PKH, ReceiverType::Sapling, ReceiverType::Orchard});
}

std::optional<RecipientAddress> ZcashdUnifiedFullViewingKey::GetChangeAddress(const ChangeRequest& req) const {
    std::optional<RecipientAddress> addr;
    std::visit(match {
        [&](const TransparentChangeRequest& req) {
            if (transparentKey.has_value()) {
                auto changeAddr = transparentKey.value().GetChangeAddress(req.GetIndex());
                if (changeAddr.has_value()) {
                    addr = changeAddr.value();
                }
            }
        },
        [&](const SaplingChangeRequest& req) {
            if (saplingKey.has_value()) {
                addr = saplingKey.value().GetChangeAddress();
            }
        },
        [&](const OrchardChangeRequest& req) {
            if (orchardKey.has_value()) {
                addr = orchardKey.value().GetChangeAddress();
            }
        }
    }, req);
    return addr;
}

std::optional<RecipientAddress> ZcashdUnifiedFullViewingKey::GetChangeAddress(
        const std::set<OutputPool>& allowedPools) const {
    if (orchardKey.has_value() && allowedPools.count(OutputPool::Orchard) > 0) {
        return orchardKey.value().GetChangeAddress();
    }
    if (saplingKey.has_value() && allowedPools.count(OutputPool::Sapling) > 0) {
        return saplingKey.value().GetChangeAddress();
    }
    if (transparentKey.has_value() && allowedPools.count(OutputPool::Transparent) > 0) {
        auto changeAddr = transparentKey.value().GetChangeAddress(diversifier_index_t(0));
        if (changeAddr.has_value()) {
            return changeAddr.value();
        }
    }
    return std::nullopt;
}

UnifiedFullViewingKey ZcashdUnifiedFullViewingKey::ToFullViewingKey() const {
    UnifiedFullViewingKeyBuilder builder;

    if (transparentKey.has_value()) {
        builder.AddTransparentKey(transparentKey.value());
    }
    if (saplingKey.has_value()) {
        builder.AddSaplingKey(saplingKey.value());
    }
    if (orchardKey.has_value()) {
        builder.AddOrchardKey(orchardKey.value());
    }

    // This call to .value() is safe as ZcashdUnifiedFullViewingKey values are always
    // constructed to contain all required components.
    return builder.build().value();
}
