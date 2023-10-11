// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "keystore.h"

#include "key.h"
#include "pubkey.h"
#include "util/system.h"


bool CKeyStore::AddKey(const CKey &key) {
    return AddKeyPubKey(key, key.GetPubKey());
}

std::optional<AddressUFVKMetadata> CKeyStore::GetUFVKMetadataForAddress(
        const CTxDestination& address) const
{
    auto self = this;
    return examine(address, match {
            [](const CNoDestination&) -> std::optional<AddressUFVKMetadata> { return std::nullopt; },
            [&](const auto& addr) { return self->GetUFVKMetadataForReceiver(addr); }
    });
}

bool CBasicKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key)) {
        LOCK(cs_KeyStore);
        WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
        if (it != mapWatchKeys.end()) {
            vchPubKeyOut = it->second;
            return true;
        }
        return false;
    }
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CBasicKeyStore::SetMnemonicSeed(const MnemonicSeed& seed)
{
    LOCK(cs_KeyStore);
    if (mnemonicSeed.has_value()) {
        // Don't allow an existing seed to be changed. We can maybe relax this
        // restriction later once we have worked out the UX implications.
        return false;
    }
    mnemonicSeed = seed;
    return true;
}

bool CBasicKeyStore::HaveMnemonicSeed() const
{
    LOCK(cs_KeyStore);
    return mnemonicSeed.has_value();
}

std::optional<MnemonicSeed> CBasicKeyStore::GetMnemonicSeed() const
{
    LOCK(cs_KeyStore);
    return mnemonicSeed;
}

bool CBasicKeyStore::SetLegacyHDSeed(const HDSeed& seed)
{
    LOCK(cs_KeyStore);
    if (legacySeed.has_value()) {
        // Don't allow an existing seed to be changed.
        return false;
    }
    legacySeed = seed;
    return true;
}

std::optional<HDSeed> CBasicKeyStore::GetLegacyHDSeed() const
{
    LOCK(cs_KeyStore);
    return legacySeed;
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
        return error("CBasicKeyStore::AddCScript(): redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    //TODO: Use Solver to extract this?
    CScript::const_iterator pc = dest.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    if (!dest.GetOp(pc, opcode, vch) || vch.size() < 33 || vch.size() > 65)
        return false;
    pubKeyOut = CPubKey(vch);
    if (!pubKeyOut.IsFullyValid())
        return false;
    if (!dest.GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG || dest.GetOp(pc, opcode, vch))
        return false;
    return true;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys[pubKey.GetID()] = pubKey;
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.erase(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys.erase(pubKey.GetID());
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

bool CBasicKeyStore::AddSproutSpendingKey(const libzcash::SproutSpendingKey &sk)
{
    LOCK(cs_KeyStore);
    auto address = sk.address();
    mapSproutSpendingKeys[address] = sk;
    mapNoteDecryptors.insert(std::make_pair(address, ZCNoteDecryption(sk.receiving_key())));
    return true;
}

//! Sapling
bool CBasicKeyStore::AddSaplingSpendingKey(
    const libzcash::SaplingExtendedSpendingKey &sk)
{
    LOCK(cs_KeyStore);
    auto extfvk = sk.ToXFVK();

    // if extfvk is not in SaplingFullViewingKeyMap, add it
    if (!CBasicKeyStore::AddSaplingFullViewingKey(extfvk)) {
        return false;
    }

    mapSaplingSpendingKeys[extfvk] = sk;

    return true;
}

bool CBasicKeyStore::AddSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    LOCK(cs_KeyStore);
    auto address = vk.address();
    mapSproutViewingKeys[address] = vk;
    mapNoteDecryptors.insert(std::make_pair(address, ZCNoteDecryption(vk.sk_enc)));
    return true;
}

bool CBasicKeyStore::AddSaplingFullViewingKey(
    const libzcash::SaplingExtendedFullViewingKey &extfvk)
{
    LOCK(cs_KeyStore);
    auto ivk = extfvk.ToIncomingViewingKey();
    mapSaplingFullViewingKeys[ivk] = extfvk;

    return true;
}

// This function updates the wallet's internal address->ivk map.
// If we add an address that is already in the map, the map will
// remain unchanged as each address only has one ivk.
bool CBasicKeyStore::AddSaplingPaymentAddress(
    const libzcash::SaplingIncomingViewingKey &ivk,
    const libzcash::SaplingPaymentAddress &addr)
{
    LOCK(cs_KeyStore);

    // Add addr -> SaplingIncomingViewing to SaplingIncomingViewingKeyMap
    mapSaplingIncomingViewingKeys[addr] = ivk;

    return true;
}

bool CBasicKeyStore::RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    LOCK(cs_KeyStore);
    mapSproutViewingKeys.erase(vk.address());
    return true;
}

bool CBasicKeyStore::HaveSproutViewingKey(const libzcash::SproutPaymentAddress &address) const
{
    LOCK(cs_KeyStore);
    return mapSproutViewingKeys.count(address) > 0;
}

bool CBasicKeyStore::HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk) const
{
    LOCK(cs_KeyStore);
    return mapSaplingFullViewingKeys.count(ivk) > 0;
}

bool CBasicKeyStore::HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr) const
{
    LOCK(cs_KeyStore);
    return mapSaplingIncomingViewingKeys.count(addr) > 0;
}

bool CBasicKeyStore::GetSproutViewingKey(
    const libzcash::SproutPaymentAddress &address,
    libzcash::SproutViewingKey &vkOut) const
{
    LOCK(cs_KeyStore);
    SproutViewingKeyMap::const_iterator mi = mapSproutViewingKeys.find(address);
    if (mi != mapSproutViewingKeys.end()) {
        vkOut = mi->second;
        return true;
    }
    return false;
}

//
// Sapling Keys
//

bool CBasicKeyStore::GetSaplingFullViewingKey(
    const libzcash::SaplingIncomingViewingKey &ivk,
    libzcash::SaplingExtendedFullViewingKey &extfvkOut) const
{
    LOCK(cs_KeyStore);
    SaplingFullViewingKeyMap::const_iterator mi = mapSaplingFullViewingKeys.find(ivk);
    if (mi != mapSaplingFullViewingKeys.end()) {
        extfvkOut = mi->second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::GetSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr,
                                   libzcash::SaplingIncomingViewingKey &ivkOut) const
{
    LOCK(cs_KeyStore);
    SaplingIncomingViewingKeyMap::const_iterator mi = mapSaplingIncomingViewingKeys.find(addr);
    if (mi != mapSaplingIncomingViewingKeys.end()) {
        ivkOut = mi->second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::GetSaplingExtendedSpendingKey(
        const libzcash::SaplingPaymentAddress &addr,
        libzcash::SaplingExtendedSpendingKey &extskOut) const {
    libzcash::SaplingIncomingViewingKey ivk;
    libzcash::SaplingExtendedFullViewingKey extfvk;

    LOCK(cs_KeyStore);
    return GetSaplingIncomingViewingKey(addr, ivk) &&
            GetSaplingFullViewingKey(ivk, extfvk) &&
            GetSaplingSpendingKey(extfvk, extskOut);
}

bool CBasicKeyStore::HaveSaplingSpendingKeyForAddress(
        const libzcash::SaplingPaymentAddress &addr) const {
    libzcash::SaplingIncomingViewingKey ivk;
    libzcash::SaplingExtendedFullViewingKey extfvk;

    return GetSaplingIncomingViewingKey(addr, ivk) &&
        GetSaplingFullViewingKey(ivk, extfvk) &&
        HaveSaplingSpendingKey(extfvk);
}

//
// Unified Keys
//

bool CBasicKeyStore::AddUnifiedFullViewingKey(
        const libzcash::ZcashdUnifiedFullViewingKey &ufvk)
{
    LOCK(cs_KeyStore);

    auto ufvkId = ufvk.GetKeyID();

    // Add the Orchard component of the UFVK to the wallet.
    auto orchardKey = ufvk.GetOrchardKey();
    if (orchardKey.has_value()) {
        auto ivk = orchardKey.value().ToIncomingViewingKey();
        mapOrchardKeyUnified.insert(std::make_pair(ivk, ufvkId));

        auto ivkInternal = orchardKey.value().ToInternalIncomingViewingKey();
        mapOrchardKeyUnified.insert(std::make_pair(ivkInternal, ufvkId));
    }

    // Add the Sapling component of the UFVK to the wallet.
    auto saplingKey = ufvk.GetSaplingKey();
    if (saplingKey.has_value()) {
        auto ivk = saplingKey.value().ToIncomingViewingKey();
        mapSaplingKeyUnified.insert(std::make_pair(ivk, ufvkId));

        auto changeIvk = saplingKey.value().GetChangeIVK();
        mapSaplingKeyUnified.insert(std::make_pair(changeIvk, ufvkId));
    }

    // We can't reasonably add the transparent component here, because
    // of the way that transparent addresses are generated from the
    // P2PKH part of the unified address. Instead, whenever a new
    // unified address is generated, the keys associated with the
    // transparent part of the address must be added to the keystore.

    // Add the UFVK by key identifier.
    mapUnifiedFullViewingKeys.insert({ufvkId, ufvk});

    return true;
}

bool CBasicKeyStore::AddTransparentReceiverForUnifiedAddress(
        const libzcash::UFVKId& keyId,
        const libzcash::diversifier_index_t& diversifierIndex,
        const libzcash::UnifiedAddress& ua)
{
    LOCK(cs_KeyStore);

    // It's only necessary to add p2pkh and p2sh components of
    // the UA; all other lookups of the associated UFVK will be
    // made via the protocol-specific viewing key that is used
    // to trial-decrypt a transaction.
    auto addrEntry = std::make_pair(keyId, diversifierIndex);

    auto p2pkhReceiver = ua.GetP2PKHReceiver();
    if (p2pkhReceiver.has_value()) {
        mapP2PKHUnified.insert(std::make_pair(p2pkhReceiver.value(), addrEntry));
    }

    auto p2shReceiver = ua.GetP2SHReceiver();
    if (p2shReceiver.has_value()) {
        mapP2SHUnified.insert(std::make_pair(p2shReceiver.value(), addrEntry));
    }

    return true;
}

std::optional<libzcash::ZcashdUnifiedFullViewingKey> CBasicKeyStore::GetUnifiedFullViewingKey(
        const libzcash::UFVKId& keyId) const
{
    auto mi = mapUnifiedFullViewingKeys.find(keyId);
    if (mi != mapUnifiedFullViewingKeys.end()) {
        return mi->second;
    } else {
        return std::nullopt;
    }
}

std::optional<AddressUFVKMetadata>
CBasicKeyStore::GetUFVKMetadataForReceiver(const libzcash::Receiver& receiver) const
{
    return std::visit(FindUFVKId(*this), receiver);
}

std::optional<libzcash::UFVKId>
CBasicKeyStore::GetUFVKIdForAddress(const libzcash::UnifiedAddress& addr) const
{
    std::optional<libzcash::UFVKId> ufvkId;
    for (const auto& receiver : addr) {
        auto rmeta = GetUFVKMetadataForReceiver(receiver);
        if (rmeta.has_value()) {
            // We should never generate unified addresses with internal receivers
            assert(rmeta.value().IsExternalAddress());

            if (ufvkId.has_value()) {
                // If the unified address contains receivers that are associated with
                // different UFVKs, we cannot return a singular value.
                if (rmeta.value().GetUFVKId() != ufvkId.value()) {
                    return std::nullopt;
                }
            } else {
                ufvkId = rmeta.value().GetUFVKId();
            }
        }
    }

    return ufvkId;
}

std::optional<libzcash::UFVKId> CBasicKeyStore::GetUFVKIdForViewingKey(const libzcash::ViewingKey& vk) const
{
    std::optional<libzcash::UFVKId> result;
    examine(vk, match {
        [&](const libzcash::SproutViewingKey& vk) {},
        [&](const libzcash::SaplingExtendedFullViewingKey& extfvk) {
            const auto saplingIvk = extfvk.ToIncomingViewingKey();
            const auto ufvkId = mapSaplingKeyUnified.find(saplingIvk);
            if (ufvkId != mapSaplingKeyUnified.end()) {
                result = ufvkId->second;
            }
        },
        [&](const libzcash::UnifiedFullViewingKey& ufvk) {
            const auto orchardFvk = ufvk.GetOrchardKey();
            if (orchardFvk.has_value()) {
                const auto orchardIvk = orchardFvk.value().ToIncomingViewingKey();
                const auto ufvkId = mapOrchardKeyUnified.find(orchardIvk);
                if (ufvkId != mapOrchardKeyUnified.end()) {
                    result = ufvkId->second;
                    return;
                }
            }
            const auto saplingDfvk = ufvk.GetSaplingKey();
            if (saplingDfvk.has_value()) {
                const auto saplingIvk = saplingDfvk.value().ToIncomingViewingKey();
                const auto ufvkId = mapSaplingKeyUnified.find(saplingIvk);
                if (ufvkId != mapSaplingKeyUnified.end()) {
                    result = ufvkId->second;
                }
            }
        }
    });
    return result;
}

//
// FindUFVKId :: (KeyStore, Receiver) -> std::optional<AddressUFVKMetadata>
//

std::optional<AddressUFVKMetadata> FindUFVKId::operator()(const libzcash::OrchardRawAddress& orchardAddr) const {
    for (const auto& [k, v] : keystore.mapUnifiedFullViewingKeys) {
        auto fvk = v.GetOrchardKey();
        if (fvk.has_value()) {
            auto d_idx = fvk.value().DecryptDiversifier(orchardAddr);
            if (d_idx.has_value()) {
                return AddressUFVKMetadata(k, d_idx->first, d_idx->second);
            }
        }
    }
    return std::nullopt;
}
std::optional<AddressUFVKMetadata> FindUFVKId::operator()(const libzcash::SaplingPaymentAddress& saplingAddr) const {
    const auto saplingIvk = keystore.mapSaplingIncomingViewingKeys.find(saplingAddr);
    if (saplingIvk != keystore.mapSaplingIncomingViewingKeys.end()) {
        // We have either generated this as a receiver via `z_getaddressforaccount` or a
        // legacy Sapling address via `z_getnewaddress`, or we have previously detected
        // this via trial-decryption of a note.
        const auto ufvkId = keystore.mapSaplingKeyUnified.find(saplingIvk->second);
        if (ufvkId != keystore.mapSaplingKeyUnified.end()) {
            // We know that we have a UFVK, and that it has a Sapling key that
            // produced this address, so decrypt the diversifier to determine
            // whether it was an internal or external address
            auto ufvk = keystore.GetUnifiedFullViewingKey(ufvkId->second).value();
            auto saplingKey = ufvk.GetSaplingKey().value();
            auto d_idx = saplingKey.DecryptDiversifier(saplingAddr).value();
            return AddressUFVKMetadata(ufvkId->second, d_idx.first, d_idx.second);
        }

        // If we have the addr -> ivk map entry but not the ivk -> UFVK map entry,
        // then this is definitely a legacy Sapling address.
        return std::nullopt;
    }

    // We haven't generated this receiver via `z_getaddressforaccount` (or this is a
    // recovery from a backed-up mnemonic which doesn't store receiver types selected by
    // users). Trial-decrypt the diversifier of the Sapling address with every UFVK in the
    // wallet, to check directly if it belongs to any of them.
    for (const auto& [k, v] : keystore.mapUnifiedFullViewingKeys) {
        auto dfvk = v.GetSaplingKey();
        if (dfvk.has_value()) {
            auto d_idx = dfvk.value().DecryptDiversifier(saplingAddr);
            if (d_idx.has_value()) {
                return AddressUFVKMetadata(k, d_idx->first, d_idx->second);
            }
        }
    }

    // We definitely don't know of any UFVK linked to this Sapling address.
    return std::nullopt;
}
std::optional<AddressUFVKMetadata> FindUFVKId::operator()(const CScriptID& scriptId) const {
    const auto metadata = keystore.mapP2SHUnified.find(scriptId);
    if (metadata != keystore.mapP2SHUnified.end()) {
        // At present we never generate transparent internal addresses, so this
        // must be an external address
        return AddressUFVKMetadata(metadata->second.first, metadata->second.second, true);
    } else {
        return std::nullopt;
    }
}
std::optional<AddressUFVKMetadata> FindUFVKId::operator()(const CKeyID& keyId) const {
    const auto metadata = keystore.mapP2PKHUnified.find(keyId);
    if (metadata != keystore.mapP2PKHUnified.end()) {
        // At present we never generate transparent internal addresses, so this
        // must be an external address
        return AddressUFVKMetadata(metadata->second.first, metadata->second.second, true);
    } else {
        return std::nullopt;
    }
}
std::optional<AddressUFVKMetadata> FindUFVKId::operator()(const libzcash::UnknownReceiver& receiver) const {
    return std::nullopt;
}
