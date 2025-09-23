// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_KEYSTORE_H
#define BITCOIN_KEYSTORE_H

#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"
#include "zcash/address/mnemonic.h"
#include "zcash/address/unified.h"
#include "zcash/Address.hpp"
#include "zcash/NoteEncryption.hpp"

#include <boost/signals2/signal.hpp>

class AddressUFVKMetadata {
private:
    libzcash::UFVKId ufvkId;
    libzcash::diversifier_index_t j;
    bool externalAddress;
public:
    AddressUFVKMetadata(libzcash::UFVKId ufvkId, libzcash::diversifier_index_t j, bool externalAddress)
        : ufvkId(ufvkId), j(j), externalAddress(externalAddress) {}

    libzcash::UFVKId GetUFVKId() const { return ufvkId; }
    libzcash::diversifier_index_t GetDiversifierIndex() const { return j; }
    bool IsExternalAddress() const { return externalAddress; }
};

/** A virtual base class for key stores */
class CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;

public:
    virtual ~CKeyStore() {}

    //! Set the mnemonic HD seed for this keystore
    virtual bool SetMnemonicSeed(const MnemonicSeed& seed) =0;
    virtual bool HaveMnemonicSeed() const =0;
    //! Get the mnemonic HD seed for this keystore
    virtual std::optional<MnemonicSeed> GetMnemonicSeed() const =0;

    //! Set the legacy HD seed for this keystore
    virtual bool SetLegacyHDSeed(const HDSeed& seed) =0;
    //! Get the legacy HD seed for this keystore
    virtual std::optional<HDSeed> GetLegacyHDSeed() const =0;

    //! Add a key to the store.
    virtual bool AddKeyPubKey(const CKey &key, const CPubKey &pubkey) =0;
    virtual bool AddKey(const CKey &key);

    //! Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const =0;
    virtual bool GetKey(const CKeyID &address, CKey& keyOut) const =0;
    virtual std::set<CKeyID> GetKeys() const =0;
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const =0;

    //! Support for BIP 0013 : see https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const =0;

    //! Support for Watch-only addresses
    virtual bool AddWatchOnly(const CScript &dest) =0;
    virtual bool RemoveWatchOnly(const CScript &dest) =0;
    virtual bool HaveWatchOnly(const CScript &dest) const =0;
    virtual bool HaveWatchOnly() const =0;

    //! Add a spending key to the store.
    virtual bool AddSproutSpendingKey(const libzcash::SproutSpendingKey &sk) =0;

    //! Check whether a spending key corresponding to a given payment address is present in the store.
    virtual bool HaveSproutSpendingKey(const libzcash::SproutPaymentAddress &address) const =0;
    virtual bool GetSproutSpendingKey(const libzcash::SproutPaymentAddress &address, libzcash::SproutSpendingKey& skOut) const =0;
    virtual void GetSproutPaymentAddresses(std::set<libzcash::SproutPaymentAddress> &setAddress) const =0;

    //! Add a Sapling spending key to the store.
    virtual bool AddSaplingSpendingKey(const libzcash::SaplingExtendedSpendingKey &sk) =0;

    //! Check whether a Sapling spending key corresponding to a given Sapling viewing key is present in the store.
    virtual bool HaveSaplingSpendingKey(
        const libzcash::SaplingExtendedFullViewingKey &extfvk) const =0;
    virtual bool HaveSaplingSpendingKeyForAddress(
        const libzcash::SaplingPaymentAddress &addr) const =0;
    virtual bool GetSaplingSpendingKey(
        const libzcash::SaplingExtendedFullViewingKey &extfvk,
        libzcash::SaplingExtendedSpendingKey& skOut) const =0;

    //! Support for Sapling full viewing keys
    virtual bool AddSaplingFullViewingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk) =0;
    virtual bool HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk) const =0;
    virtual bool GetSaplingFullViewingKey(
        const libzcash::SaplingIncomingViewingKey &ivk,
        libzcash::SaplingExtendedFullViewingKey& extfvkOut) const =0;

    //! Sapling payment addresses & incoming viewing keys
    virtual bool AddSaplingPaymentAddress(
        const libzcash::SaplingIncomingViewingKey &ivk,
        const libzcash::SaplingPaymentAddress &addr) =0;
    virtual bool HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr) const =0;
    virtual bool GetSaplingIncomingViewingKey(
        const libzcash::SaplingPaymentAddress &addr,
        libzcash::SaplingIncomingViewingKey& ivkOut) const =0;
    virtual void GetSaplingPaymentAddresses(std::set<libzcash::SaplingPaymentAddress> &setAddress) const =0;

    //! Support for Sprout viewing keys
    virtual bool AddSproutViewingKey(const libzcash::SproutViewingKey &vk) =0;
    virtual bool RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk) =0;
    virtual bool HaveSproutViewingKey(const libzcash::SproutPaymentAddress &address) const =0;
    virtual bool GetSproutViewingKey(
        const libzcash::SproutPaymentAddress &address,
        libzcash::SproutViewingKey& vkOut) const =0;

    //! Unified addresses and keys
    virtual bool AddUnifiedFullViewingKey(
            const libzcash::ZcashdUnifiedFullViewingKey &ufvk
            ) = 0;

    /**
     * Add the transparent component of the unified address, if any,
     * to the keystore to make it possible to identify the unified
     * full viewing key from which a transparent address was derived.
     * It is not necessary for implementations to add shielded address
     * components to the keystore because those will be automatically
     * reconstructed when scanning the chain with a shielded incoming
     * viewing key upon discovery of the address as having received
     * funds.
     */
    virtual bool AddTransparentReceiverForUnifiedAddress(
        const libzcash::UFVKId& keyId,
        const libzcash::diversifier_index_t& diversifierIndex,
        const libzcash::UnifiedAddress& ua) = 0;

    virtual std::optional<libzcash::ZcashdUnifiedFullViewingKey> GetUnifiedFullViewingKey(
            const libzcash::UFVKId& keyId) const = 0;

    virtual std::optional<AddressUFVKMetadata> GetUFVKMetadataForReceiver(
            const libzcash::Receiver& receiver) const = 0;

    std::optional<AddressUFVKMetadata> GetUFVKMetadataForAddress(
            const CTxDestination& address) const;

    /**
     * If all the receivers of the specified address correspond to a single
     * UFVK, return that key's metadata.
     */
    virtual std::optional<libzcash::UFVKId> GetUFVKIdForAddress(
            const libzcash::UnifiedAddress& addr) const = 0;

    virtual std::optional<libzcash::UFVKId> GetUFVKIdForViewingKey(
            const libzcash::ViewingKey& vk) const = 0;
};

typedef std::map<CKeyID, CKey> KeyMap;
typedef std::map<CKeyID, CPubKey> WatchKeyMap;
typedef std::map<CScriptID, CScript > ScriptMap;
typedef std::set<CScript> WatchOnlySet;
typedef std::map<libzcash::SproutPaymentAddress, libzcash::SproutSpendingKey> SproutSpendingKeyMap;
typedef std::map<libzcash::SproutPaymentAddress, libzcash::SproutViewingKey> SproutViewingKeyMap;
typedef std::map<libzcash::SproutPaymentAddress, ZCNoteDecryption> NoteDecryptorMap;

// Full viewing key has equivalent functionality to a transparent address
// When encrypting wallet, encrypt SaplingSpendingKeyMap, while leaving SaplingFullViewingKeyMap unencrypted
typedef std::map<
    libzcash::SaplingExtendedFullViewingKey,
    libzcash::SaplingExtendedSpendingKey> SaplingSpendingKeyMap;
typedef std::map<
    libzcash::SaplingIncomingViewingKey,
    libzcash::SaplingExtendedFullViewingKey> SaplingFullViewingKeyMap;
// Only maps from default addresses to ivk, may need to be reworked when adding diversified addresses.
typedef std::map<libzcash::SaplingPaymentAddress, libzcash::SaplingIncomingViewingKey> SaplingIncomingViewingKeyMap;

class FindUFVKId;

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    // All wallets will have a mnemonic seed, but this field must be declared
    // as optional to avoid the need to construct or hold an invalid seed before the
    // wallet's contents have been loaded from the database.
    std::optional<MnemonicSeed> mnemonicSeed;
    std::optional<HDSeed> legacySeed;
    KeyMap mapKeys;
    WatchKeyMap mapWatchKeys;
    ScriptMap mapScripts;
    WatchOnlySet setWatchOnly;
    SproutSpendingKeyMap mapSproutSpendingKeys;
    SproutViewingKeyMap mapSproutViewingKeys;
    NoteDecryptorMap mapNoteDecryptors;

    SaplingSpendingKeyMap mapSaplingSpendingKeys;
    SaplingFullViewingKeyMap mapSaplingFullViewingKeys;
    SaplingIncomingViewingKeyMap mapSaplingIncomingViewingKeys;

    // Unified key support
    std::map<CKeyID, std::pair<libzcash::UFVKId, libzcash::diversifier_index_t>> mapP2PKHUnified;
    std::map<CScriptID, std::pair<libzcash::UFVKId, libzcash::diversifier_index_t>> mapP2SHUnified;
    std::map<libzcash::SaplingIncomingViewingKey, libzcash::UFVKId> mapSaplingKeyUnified;
    std::map<libzcash::OrchardIncomingViewingKey, libzcash::UFVKId> mapOrchardKeyUnified;
    std::map<libzcash::UFVKId, libzcash::ZcashdUnifiedFullViewingKey> mapUnifiedFullViewingKeys;

    friend class FindUFVKId;
public:
    bool SetMnemonicSeed(const MnemonicSeed& seed);
    bool HaveMnemonicSeed() const;
    std::optional<MnemonicSeed> GetMnemonicSeed() const;

    bool SetLegacyHDSeed(const HDSeed& seed);
    std::optional<HDSeed> GetLegacyHDSeed() const;

    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey);
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;
    bool HaveKey(const CKeyID &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }
    std::set<CKeyID> GetKeys() const
    {
        std::set<CKeyID> set_address;
        LOCK(cs_KeyStore);
        for (const auto& mi : mapKeys) {
            set_address.insert(mi.first);
        }
        return set_address;
    }
    bool GetKey(const CKeyID &address, CKey &keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end())
            {
                keyOut = mi->second;
                return true;
            }
        }
        return false;
    }
    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID &hash) const;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const;

    virtual bool AddWatchOnly(const CScript &dest);
    virtual bool RemoveWatchOnly(const CScript &dest);
    virtual bool HaveWatchOnly(const CScript &dest) const;
    virtual bool HaveWatchOnly() const;

    bool AddSproutSpendingKey(const libzcash::SproutSpendingKey &sk);
    bool HaveSproutSpendingKey(const libzcash::SproutPaymentAddress &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapSproutSpendingKeys.count(address) > 0);
        }
        return result;
    }
    bool GetSproutSpendingKey(const libzcash::SproutPaymentAddress &address, libzcash::SproutSpendingKey &skOut) const
    {
        {
            LOCK(cs_KeyStore);
            SproutSpendingKeyMap::const_iterator mi = mapSproutSpendingKeys.find(address);
            if (mi != mapSproutSpendingKeys.end())
            {
                skOut = mi->second;
                return true;
            }
        }
        return false;
    }
    bool GetNoteDecryptor(const libzcash::SproutPaymentAddress &address, ZCNoteDecryption &decOut) const
    {
        {
            LOCK(cs_KeyStore);
            NoteDecryptorMap::const_iterator mi = mapNoteDecryptors.find(address);
            if (mi != mapNoteDecryptors.end())
            {
                decOut = mi->second;
                return true;
            }
        }
        return false;
    }
    void GetSproutPaymentAddresses(std::set<libzcash::SproutPaymentAddress> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            SproutSpendingKeyMap::const_iterator mi = mapSproutSpendingKeys.begin();
            while (mi != mapSproutSpendingKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
            SproutViewingKeyMap::const_iterator mvi = mapSproutViewingKeys.begin();
            while (mvi != mapSproutViewingKeys.end())
            {
                setAddress.insert((*mvi).first);
                mvi++;
            }
        }
    }

    //! Sapling
    bool AddSaplingSpendingKey(const libzcash::SaplingExtendedSpendingKey &sk);
    bool HaveSaplingSpendingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapSaplingSpendingKeys.count(extfvk) > 0);
        }
        return result;
    }
    bool HaveSaplingSpendingKeyForAddress(const libzcash::SaplingPaymentAddress &addr) const;
    bool GetSaplingSpendingKey(
        const libzcash::SaplingExtendedFullViewingKey &extfvk,
        libzcash::SaplingExtendedSpendingKey &skOut) const
    {
        {
            LOCK(cs_KeyStore);

            SaplingSpendingKeyMap::const_iterator mi = mapSaplingSpendingKeys.find(extfvk);
            if (mi != mapSaplingSpendingKeys.end())
            {
                skOut = mi->second;
                return true;
            }
        }
        return false;
    }

    virtual bool AddSaplingFullViewingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk);
    virtual bool HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk) const;
    virtual bool GetSaplingFullViewingKey(
        const libzcash::SaplingIncomingViewingKey &ivk,
        libzcash::SaplingExtendedFullViewingKey& extfvkOut) const;

    virtual bool AddSaplingPaymentAddress(
        const libzcash::SaplingIncomingViewingKey &ivk,
        const libzcash::SaplingPaymentAddress &addr);
    virtual bool HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr) const;
    virtual bool GetSaplingIncomingViewingKey(
        const libzcash::SaplingPaymentAddress &addr,
        libzcash::SaplingIncomingViewingKey& ivkOut) const;

    bool GetSaplingExtendedSpendingKey(
        const libzcash::SaplingPaymentAddress &addr,
        libzcash::SaplingExtendedSpendingKey &extskOut) const;

    void GetSaplingPaymentAddresses(std::set<libzcash::SaplingPaymentAddress> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            auto mi = mapSaplingIncomingViewingKeys.begin();
            while (mi != mapSaplingIncomingViewingKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }

    virtual bool AddSproutViewingKey(const libzcash::SproutViewingKey &vk);
    virtual bool RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk);
    virtual bool HaveSproutViewingKey(const libzcash::SproutPaymentAddress &address) const;
    virtual bool GetSproutViewingKey(
        const libzcash::SproutPaymentAddress &address,
        libzcash::SproutViewingKey& vkOut) const;

    virtual bool AddUnifiedFullViewingKey(
            const libzcash::ZcashdUnifiedFullViewingKey &ufvk);

    virtual bool AddTransparentReceiverForUnifiedAddress(
        const libzcash::UFVKId& keyId,
        const libzcash::diversifier_index_t& diversifierIndex,
        const libzcash::UnifiedAddress& ua);

    virtual std::optional<libzcash::ZcashdUnifiedFullViewingKey> GetUnifiedFullViewingKey(
            const libzcash::UFVKId& keyId) const;

    virtual std::optional<AddressUFVKMetadata> GetUFVKMetadataForReceiver(
            const libzcash::Receiver& receiver) const;

    std::optional<libzcash::ZcashdUnifiedFullViewingKey> GetUFVKForReceiver(
            const libzcash::Receiver& receiver) const {
        auto ufvkMeta = GetUFVKMetadataForReceiver(receiver);
        if (ufvkMeta.has_value()) {
            return GetUnifiedFullViewingKey(ufvkMeta.value().GetUFVKId());
        } else {
            return std::nullopt;
        }
    }

    virtual std::optional<libzcash::UFVKId> GetUFVKIdForAddress(
            const libzcash::UnifiedAddress& addr) const;

    std::optional<libzcash::ZcashdUnifiedFullViewingKey> GetUFVKForAddress(
            const libzcash::UnifiedAddress& addr) const {
        auto ufvkId = GetUFVKIdForAddress(addr);
        if (ufvkId.has_value()) {
            return GetUnifiedFullViewingKey(ufvkId.value());
        } else {
            return std::nullopt;
        }
    }

    virtual std::optional<libzcash::UFVKId> GetUFVKIdForViewingKey(
            const libzcash::ViewingKey& vk) const;
};

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial;
typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;
typedef std::map<libzcash::SproutPaymentAddress, std::vector<unsigned char> > CryptedSproutSpendingKeyMap;

//! Sapling
typedef std::map<libzcash::SaplingExtendedFullViewingKey, std::vector<unsigned char> > CryptedSaplingSpendingKeyMap;

class FindUFVKId {
private:
    const CBasicKeyStore& keystore;

public:
    FindUFVKId(const CBasicKeyStore& keystore): keystore(keystore) {}

    std::optional<AddressUFVKMetadata> operator()(const libzcash::OrchardRawAddress& orchardAddr) const;
    std::optional<AddressUFVKMetadata> operator()(const libzcash::SaplingPaymentAddress& saplingAddr) const;
    std::optional<AddressUFVKMetadata> operator()(const CScriptID& scriptId) const;
    std::optional<AddressUFVKMetadata> operator()(const CKeyID& keyId) const;
    std::optional<AddressUFVKMetadata> operator()(const libzcash::UnknownReceiver& receiver) const;
};

#endif // BITCOIN_KEYSTORE_H
