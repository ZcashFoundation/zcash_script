// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_COINS_H
#define BITCOIN_COINS_H

#include "compressor.h"
#include "core_memusage.h"
#include "hash.h"
#include "memusage.h"
#include "serialize.h"
#include "uint256.h"

#include <assert.h>
#include <stdint.h>

#include <boost/unordered_map.hpp>
#include <tl/expected.hpp>
#include "zcash/History.hpp"
#include "zcash/IncrementalMerkleTree.hpp"

/**
 * Pruned version of CTransaction: only retains metadata and unspent transaction outputs
 *
 * Serialized format:
 * - VARINT(nVersion)
 * - VARINT(nCode)
 * - unspentness bitvector, for vout[2] and further; least significant byte first
 * - the non-spent CTxOuts (via CTxOutCompressor)
 * - VARINT(nHeight)
 *
 * The nCode value consists of:
 * - bit 1: IsCoinBase()
 * - bit 2: vout[0] is not spent
 * - bit 4: vout[1] is not spent
 * - The higher bits encode N, the number of non-zero bytes in the following bitvector.
 *   - In case both bit 2 and bit 4 are unset, they encode N-1, as there must be at
 *     least one non-spent output).
 *
 * Example: 0104835800816115944e077fe7c803cfa57f29b36bf87c1d358bb85e
 *          <><><--------------------------------------------><---->
 *          |  \                  |                             /
 *    version   code             vout[1]                  height
 *
 *    - version = 1
 *    - code = 4 (vout[1] is not spent, and 0 non-zero bytes of bitvector follow)
 *    - unspentness bitvector: as 0 non-zero bytes follow, it has length 0
 *    - vout[1]: 835800816115944e077fe7c803cfa57f29b36bf87c1d35
 *               * 8358: compact amount representation for 60000000000 (600 ZEC)
 *               * 00: special txout type pay-to-pubkey-hash
 *               * 816115944e077fe7c803cfa57f29b36bf87c1d35: address uint160
 *    - height = 203998
 *
 *
 * Example: 0109044086ef97d5790061b01caab50f1b8e9c50a5057eb43c2d9563a4eebbd123008c988f1a4a4de2161e0f50aac7f17e7f9555caa486af3b
 *          <><><--><--------------------------------------------------><----------------------------------------------><---->
 *         /  \   \                     |                                                           |                     /
 *  version  code  unspentness       vout[4]                                                     vout[16]           height
 *
 *  - version = 1
 *  - code = 9 (coinbase, neither vout[0] or vout[1] are unspent,
 *                2 (1, +1 because both bit 2 and bit 4 are unset) non-zero bitvector bytes follow)
 *  - unspentness bitvector: bits 2 (0x04) and 14 (0x4000) are set, so vout[2+2] and vout[14+2] are unspent
 *  - vout[4]: 86ef97d5790061b01caab50f1b8e9c50a5057eb43c2d9563a4ee
 *             * 86ef97d579: compact amount representation for 234925952 (2.35 ZEC)
 *             * 00: special txout type pay-to-pubkey-hash
 *             * 61b01caab50f1b8e9c50a5057eb43c2d9563a4ee: address uint160
 *  - vout[16]: bbd123008c988f1a4a4de2161e0f50aac7f17e7f9555caa4
 *              * bbd123: compact amount representation for 110397 (0.001 ZEC)
 *              * 00: special txout type pay-to-pubkey-hash
 *              * 8c988f1a4a4de2161e0f50aac7f17e7f9555caa4: address uint160
 *  - height = 120891
 */
class CCoins
{
public:
    //! whether transaction is a coinbase
    bool fCoinBase;

    //! unspent transaction outputs; spent outputs are .IsNull(); spent outputs at the end of the array are dropped
    std::vector<CTxOut> vout;

    //! at which height this transaction was included in the active block chain
    int nHeight;

    //! version of the CTransaction; accesses to this value should probably check for nHeight as well,
    //! as new tx version will probably only be introduced at certain heights
    int nVersion;

    void FromTx(const CTransaction &tx, int nHeightIn) {
        fCoinBase = tx.IsCoinBase();
        vout = tx.vout;
        nHeight = nHeightIn;
        nVersion = tx.nVersion;
        ClearUnspendable();
    }

    //! construct a CCoins from a CTransaction, at a given height
    CCoins(const CTransaction &tx, int nHeightIn) {
        FromTx(tx, nHeightIn);
    }

    void Clear() {
        fCoinBase = false;
        std::vector<CTxOut>().swap(vout);
        nHeight = 0;
        nVersion = 0;
    }

    //! empty constructor
    CCoins() : fCoinBase(false), vout(0), nHeight(0), nVersion(0) { }

    //!remove spent outputs at the end of vout
    void Cleanup() {
        while (vout.size() > 0 && vout.back().IsNull())
            vout.pop_back();
        if (vout.empty())
            std::vector<CTxOut>().swap(vout);
    }

    void ClearUnspendable() {
        for (CTxOut &txout : vout) {
            if (txout.scriptPubKey.IsUnspendable())
                txout.SetNull();
        }
        Cleanup();
    }

    void swap(CCoins &to) {
        std::swap(to.fCoinBase, fCoinBase);
        to.vout.swap(vout);
        std::swap(to.nHeight, nHeight);
        std::swap(to.nVersion, nVersion);
    }

    //! equality test
    friend bool operator==(const CCoins &a, const CCoins &b) {
         // Empty CCoins objects are always equal.
         if (a.IsPruned() && b.IsPruned())
             return true;
         return a.fCoinBase == b.fCoinBase &&
                a.nHeight == b.nHeight &&
                a.nVersion == b.nVersion &&
                a.vout == b.vout;
    }
    friend bool operator!=(const CCoins &a, const CCoins &b) {
        return !(a == b);
    }

    void CalcMaskSize(unsigned int &nBytes, unsigned int &nNonzeroBytes) const;

    bool IsCoinBase() const {
        return fCoinBase;
    }

    template<typename Stream>
    void Serialize(Stream &s) const {
        unsigned int nMaskSize = 0, nMaskCode = 0;
        CalcMaskSize(nMaskSize, nMaskCode);
        bool fFirst = vout.size() > 0 && !vout[0].IsNull();
        bool fSecond = vout.size() > 1 && !vout[1].IsNull();
        assert(fFirst || fSecond || nMaskCode);
        unsigned int nCode = 8*(nMaskCode - (fFirst || fSecond ? 0 : 1)) + (fCoinBase ? 1 : 0) + (fFirst ? 2 : 0) + (fSecond ? 4 : 0);
        // version
        ::Serialize(s, VARINT(this->nVersion));
        // header code
        ::Serialize(s, VARINT(nCode));
        // spentness bitmask
        for (unsigned int b = 0; b<nMaskSize; b++) {
            unsigned char chAvail = 0;
            for (unsigned int i = 0; i < 8 && 2+b*8+i < vout.size(); i++)
                if (!vout[2+b*8+i].IsNull())
                    chAvail |= (1 << i);
            ::Serialize(s, chAvail);
        }
        // txouts themself
        for (unsigned int i = 0; i < vout.size(); i++) {
            if (!vout[i].IsNull())
                ::Serialize(s, CTxOutCompressor(REF(vout[i])));
        }
        // coinbase height
        ::Serialize(s, VARINT(nHeight));
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nCode = 0;
        // version
        ::Unserialize(s, VARINT(this->nVersion));
        // header code
        ::Unserialize(s, VARINT(nCode));
        fCoinBase = nCode & 1;
        std::vector<bool> vAvail(2, false);
        vAvail[0] = (nCode & 2) != 0;
        vAvail[1] = (nCode & 4) != 0;
        unsigned int nMaskCode = (nCode / 8) + ((nCode & 6) != 0 ? 0 : 1);
        // spentness bitmask
        while (nMaskCode > 0) {
            unsigned char chAvail = 0;
            ::Unserialize(s, chAvail);
            for (unsigned int p = 0; p < 8; p++) {
                bool f = (chAvail & (1 << p)) != 0;
                vAvail.push_back(f);
            }
            if (chAvail != 0)
                nMaskCode--;
        }
        // txouts themself
        vout.assign(vAvail.size(), CTxOut());
        for (unsigned int i = 0; i < vAvail.size(); i++) {
            if (vAvail[i])
                ::Unserialize(s, REF(CTxOutCompressor(vout[i])));
        }
        // coinbase height
        ::Unserialize(s, VARINT(nHeight));
        Cleanup();
    }

    //! mark a vout spent
    bool Spend(uint32_t nPos);

    //! check whether a particular output is still available
    bool IsAvailable(unsigned int nPos) const {
        return (nPos < vout.size() && !vout[nPos].IsNull());
    }

    //! check whether the entire CCoins is spent
    //! note that only !IsPruned() CCoins can be serialized
    bool IsPruned() const {
        for (const CTxOut &out : vout)
            if (!out.IsNull())
                return false;
        return true;
    }

    size_t DynamicMemoryUsage() const {
        size_t ret = memusage::DynamicUsage(vout);
        for (const CTxOut &out : vout) {
            ret += RecursiveDynamicUsage(out.scriptPubKey);
        }
        return ret;
    }
};

class SaltedTxidHasher
{
private:
    /** Salt */
    const uint64_t k0, k1;

public:
    SaltedTxidHasher();

    /**
     * This *must* return size_t. With Boost 1.46 on 32-bit systems the
     * unordered_map will behave unpredictably if the custom hasher returns a
     * uint64_t, resulting in failures when syncing the chain (#4634).
     */
    size_t operator()(const uint256& txid) const {
        return SipHashUint256(k0, k1, txid);
    }
};

struct CCoinsCacheEntry
{
    CCoins coins; // The actual cached data.
    unsigned char flags;

    enum Flags {
        DIRTY = (1 << 0), // This cache entry is potentially different from the version in the parent view.
        FRESH = (1 << 1), // The parent view does not have this entry (or it is pruned).
    };

    CCoinsCacheEntry() : coins(), flags(0) {}
};

struct CAnchorsSproutCacheEntry
{
    bool entered; // This will be false if the anchor is removed from the cache
    SproutMerkleTree tree; // The tree itself
    unsigned char flags;

    enum Flags {
        DIRTY = (1 << 0), // This cache entry is potentially different from the version in the parent view.
    };

    CAnchorsSproutCacheEntry() : entered(false), flags(0) {}
};

struct CAnchorsSaplingCacheEntry
{
    bool entered; // This will be false if the anchor is removed from the cache
    SaplingMerkleTree tree; // The tree itself
    unsigned char flags;

    enum Flags {
        DIRTY = (1 << 0), // This cache entry is potentially different from the version in the parent view.
    };

    CAnchorsSaplingCacheEntry() : entered(false), flags(0) {}
};

struct CAnchorsOrchardCacheEntry
{
    bool entered; // This will be false if the anchor is removed from the cache
    OrchardMerkleFrontier tree; // The tree itself
    unsigned char flags;

    enum Flags {
        DIRTY = (1 << 0), // This cache entry is potentially different from the version in the parent view.
    };

    CAnchorsOrchardCacheEntry() : entered(false), flags(0) {}
};

struct CNullifiersCacheEntry
{
    bool entered; // If the nullifier is spent or not
    unsigned char flags;

    enum Flags {
        DIRTY = (1 << 0), // This cache entry is potentially different from the version in the parent view.
    };

    CNullifiersCacheEntry() : entered(false), flags(0) {}
};

/// These identify the value pool, and as such, Canopy (for example)
/// isn't here, since value created during the Canopy network upgrade
/// is part of the Sapling pool.
enum ShieldedType: uint8_t
{
    SPROUT = 0x01,
    SAPLING = 0x02,
    ORCHARD = 0x03,
};

typedef boost::unordered_map<uint256, CCoinsCacheEntry, SaltedTxidHasher> CCoinsMap;
typedef boost::unordered_map<uint256, CAnchorsSproutCacheEntry, SaltedTxidHasher> CAnchorsSproutMap;
typedef boost::unordered_map<uint256, CAnchorsSaplingCacheEntry, SaltedTxidHasher> CAnchorsSaplingMap;
typedef boost::unordered_map<uint256, CAnchorsOrchardCacheEntry, SaltedTxidHasher> CAnchorsOrchardMap;
typedef boost::unordered_map<uint256, CNullifiersCacheEntry, SaltedTxidHasher> CNullifiersMap;
typedef boost::unordered_map<uint32_t, HistoryCache> CHistoryCacheMap;

struct CCoinsStats
{
    int nHeight;
    uint256 hashBlock;
    uint64_t nTransactions;
    uint64_t nTransactionOutputs;
    uint64_t nSerializedSize;
    uint256 hashSerialized;
    CAmount nTotalAmount;

    CCoinsStats() : nHeight(0), nTransactions(0), nTransactionOutputs(0), nSerializedSize(0), nTotalAmount(0) {}
};

class SubtreeCache;

/** Abstract view on the open txout dataset. */
class CCoinsView
{
public:
    //! Retrieve the tree (Sprout) at a particular anchored root in the chain
    virtual bool GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const = 0;

    //! Retrieve the tree (Sapling) at a particular anchored root in the chain
    virtual bool GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const = 0;

    //! Retrieve the tree (Orchard) at a particular anchored root in the chain
    virtual bool GetOrchardAnchorAt(const uint256 &rt, OrchardMerkleFrontier &tree) const = 0;

    //! Determine whether a nullifier is spent or not
    virtual bool GetNullifier(const uint256 &nullifier, ShieldedType type) const = 0;

    //! Retrieve the CCoins (unspent transaction outputs) for a given txid
    virtual bool GetCoins(const uint256 &txid, CCoins &coins) const = 0;

    //! Just check whether we have data for a given txid.
    //! This may (but cannot always) return true for fully spent transactions
    virtual bool HaveCoins(const uint256 &txid) const = 0;

    //! Retrieve the block hash whose state this CCoinsView currently represents
    virtual uint256 GetBestBlock() const = 0;

    //! Get the current "tip" or the latest anchored tree root in the chain
    virtual uint256 GetBestAnchor(ShieldedType type) const = 0;

    //! Get the current chain history length (which should be roughly chain height x2)
    virtual HistoryIndex GetHistoryLength(uint32_t epochId) const = 0;

    //! Get history node at specified index
    virtual HistoryNode GetHistoryAt(uint32_t epochId, HistoryIndex index) const = 0;

    //! Get current history root
    virtual uint256 GetHistoryRoot(uint32_t epochId) const = 0;

    //! Get the largest completed subtree data for the TRACKED_SUBTREE_HEIGHT depth subtrees known
    //! to the node for a given protocol. std::nullopt is returned in the event there are no
    //! complete subtrees.
    virtual std::optional<libzcash::LatestSubtree> GetLatestSubtree(ShieldedType type) const = 0;

    //! Returns the index of the (expected) current TRACKED_SUBTREE_HEIGHT depth subtree. This
    //! is essentially just one larger than the latest complete subtree's index (or zero, if
    //! there is no latest subtree)
    libzcash::SubtreeIndex CurrentSubtreeIndex(ShieldedType type) const {
        auto latestSubtree = GetLatestSubtree(type);
        if (latestSubtree.has_value()) {
            return latestSubtree->index + 1;
        } else {
            return 0;
        }
    }

    //! Gets the cached data about the TRACKED_SUBTREE_HEIGHT subtree for the specified
    //! protocol at the provided index, if that subtree is complete.
    virtual std::optional<libzcash::SubtreeData> GetSubtreeData(
            ShieldedType type,
            libzcash::SubtreeIndex index) const = 0;

    //! Do a bulk modification onto this cache. All of the provided
    //! caches may be modified and should be cleared by the caller
    //! after this batch write.
    virtual bool BatchWrite(CCoinsMap &mapCoins,
                            const uint256 &hashBlock,
                            const uint256 &hashSproutAnchor,
                            const uint256 &hashSaplingAnchor,
                            const uint256 &hashOrchardAnchor,
                            CAnchorsSproutMap &mapSproutAnchors,
                            CAnchorsSaplingMap &mapSaplingAnchors,
                            CAnchorsOrchardMap &mapOrchardAnchors,
                            CNullifiersMap &mapSproutNullifiers,
                            CNullifiersMap &mapSaplingNullifiers,
                            CNullifiersMap &mapOrchardNullifiers,
                            CHistoryCacheMap &historyCacheMap,
                            SubtreeCache &cacheSaplingSubtrees,
                            SubtreeCache &cacheOrchardSubtrees) = 0;

    //! Calculate statistics about the unspent transaction output set
    virtual bool GetStats(CCoinsStats &stats) const = 0;

    //! As we use CCoinsViews polymorphically, have a virtual destructor
    virtual ~CCoinsView() {}
};

//! This class is used by `CCoinsViewCache` to internally store, for each
//! shielded type, the roots of complete subtrees that have not yet been flushed
//! to the backing `CCoinsView`. This allows the cache to both store new
//! subtree roots and handle removing subtree roots from the backing view when the
//! cache is flushed.
class SubtreeCache {
    public:

    bool initialized = false;
    //! We store in `parentLatestSubtree` our perspective of what the latest
    //! subtree ought to be in the backing `CCoinsView`. If subtrees are
    //! removed from this subtree cache but no new complete subtrees exist,
    //! they must be removed from the backing view later when it is flushed.
    std::optional<libzcash::LatestSubtree> parentLatestSubtree;
    //! New subtrees slated to be written to the backing `CCoinsView`.
    std::vector<libzcash::SubtreeData> newSubtrees;
    ShieldedType type;

    SubtreeCache(ShieldedType type) : type(type) { };

    //! Initializes the subtree cache so that the `parentLatestSubtree`
    //! stored internally is consistent with the parent view.
    void Initialize(CCoinsView *parentView);

    //! Resets this cache to its original uninitialized state.
    void clear();

    //! Gets the latest subtree for this cache, using the parent view
    //! as a reference if needed.
    std::optional<libzcash::LatestSubtree> GetLatestSubtree(CCoinsView *parentView);

    //! Gets the subtree data for a given index, if available.
    std::optional<libzcash::SubtreeData> GetSubtreeData(CCoinsView *parentView, libzcash::SubtreeIndex index);

    //! Inserts a new subtree into the view.
    void PushSubtree(CCoinsView *parentView, libzcash::SubtreeData subtree);

    //! Removes the last subtree added to the view; this will throw an
    //! exception if the view has no subtrees.
    void PopSubtree(CCoinsView *parentView);

    //! Effectively pops all subtrees from the view
    void ResetSubtrees();

    //! Writes a child map to this cache; this clears the child map.
    void BatchWrite(CCoinsView *parentView, SubtreeCache &childMap);
};

namespace memusage {
    static inline size_t DynamicUsage(const SubtreeCache& cache) {
        return DynamicUsage(cache.newSubtrees);
    }
}

class CCoinsViewDummy : public CCoinsView
{
public:
    ~CCoinsViewDummy() {}

    bool GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const { return false; }
    bool GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const { return false; }
    bool GetOrchardAnchorAt(const uint256 &rt, OrchardMerkleFrontier &tree) const { return false; }
    bool GetNullifier(const uint256 &nullifier, ShieldedType type) const { return false; }
    bool GetCoins(const uint256 &txid, CCoins &coins) const { return false; }
    bool HaveCoins(const uint256 &txid) const { return false; }
    uint256 GetBestBlock() const { return uint256(); }
    uint256 GetBestAnchor(ShieldedType type) const { return uint256(); };
    HistoryIndex GetHistoryLength(uint32_t epochId) const { return 0; }
    HistoryNode GetHistoryAt(uint32_t epochId, HistoryIndex index) const { return HistoryNode(); }
    uint256 GetHistoryRoot(uint32_t epochId) const { return uint256(); }
    std::optional<libzcash::LatestSubtree> GetLatestSubtree(ShieldedType type) const { return std::nullopt; };
    std::optional<libzcash::SubtreeData> GetSubtreeData(
            ShieldedType type,
            libzcash::SubtreeIndex index) const { return std::nullopt; };
    bool BatchWrite(CCoinsMap &mapCoins,
                    const uint256 &hashBlock,
                    const uint256 &hashSproutAnchor,
                    const uint256 &hashSaplingAnchor,
                    const uint256 &hashOrchardAnchor,
                    CAnchorsSproutMap &mapSproutAnchors,
                    CAnchorsSaplingMap &mapSaplingAnchors,
                    CAnchorsOrchardMap &mapOrchardAnchors,
                    CNullifiersMap &mapSproutNullifiers,
                    CNullifiersMap &mapSaplingNullifiers,
                    CNullifiersMap &mapOrchardNullifiers,
                    CHistoryCacheMap &historyCacheMap,
                    SubtreeCache &cacheSaplingSubtrees,
                    SubtreeCache &cacheOrchardSubtrees) { return false; }

    bool GetStats(CCoinsStats &stats) const { return false; }
};

/** CCoinsView backed by another CCoinsView */
class CCoinsViewBacked : public CCoinsView
{
protected:
    CCoinsView *base;

public:
    CCoinsViewBacked(CCoinsView *viewIn);
    ~CCoinsViewBacked() {}

    bool GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const;
    bool GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const;
    bool GetOrchardAnchorAt(const uint256 &rt, OrchardMerkleFrontier &tree) const;
    bool GetNullifier(const uint256 &nullifier, ShieldedType type) const;
    bool GetCoins(const uint256 &txid, CCoins &coins) const;
    bool HaveCoins(const uint256 &txid) const;
    uint256 GetBestBlock() const;
    uint256 GetBestAnchor(ShieldedType type) const;
    HistoryIndex GetHistoryLength(uint32_t epochId) const;
    HistoryNode GetHistoryAt(uint32_t epochId, HistoryIndex index) const;
    uint256 GetHistoryRoot(uint32_t epochId) const;
    std::optional<libzcash::LatestSubtree> GetLatestSubtree(ShieldedType type) const;
    std::optional<libzcash::SubtreeData> GetSubtreeData(
            ShieldedType type,
            libzcash::SubtreeIndex index) const;
    void SetBackend(CCoinsView &viewIn);
    bool BatchWrite(CCoinsMap &mapCoins,
                    const uint256 &hashBlock,
                    const uint256 &hashSproutAnchor,
                    const uint256 &hashSaplingAnchor,
                    const uint256 &hashOrchardAnchor,
                    CAnchorsSproutMap &mapSproutAnchors,
                    CAnchorsSaplingMap &mapSaplingAnchors,
                    CAnchorsOrchardMap &mapOrchardAnchors,
                    CNullifiersMap &mapSproutNullifiers,
                    CNullifiersMap &mapSaplingNullifiers,
                    CNullifiersMap &mapOrchardNullifiers,
                    CHistoryCacheMap &historyCacheMap,
                    SubtreeCache &cacheSaplingSubtrees,
                    SubtreeCache &cacheOrchardSubtrees);
    bool GetStats(CCoinsStats &stats) const;
};


class CCoinsViewCache;

/**
 * A reference to a mutable cache entry. Encapsulating it allows us to run
 *  cleanup code after the modification is finished, and keeping track of
 *  concurrent modifications.
 */
class CCoinsModifier
{
private:
    CCoinsViewCache& cache;
    CCoinsMap::iterator it;
    size_t cachedCoinUsage; // Cached memory usage of the CCoins object before modification
    CCoinsModifier(CCoinsViewCache& cache_, CCoinsMap::iterator it_, size_t usage);

public:
    CCoins* operator->() { return &it->second.coins; }
    CCoins& operator*() { return it->second.coins; }
    ~CCoinsModifier();
    friend class CCoinsViewCache;
};

/** The set of shielded requirements that might be unsatisfied. */
enum class UnsatisfiedShieldedReq {
    SproutDuplicateNullifier,
    SproutUnknownAnchor,
    SaplingDuplicateNullifier,
    SaplingUnknownAnchor,
    OrchardDuplicateNullifier,
    OrchardUnknownAnchor,
};

/** CCoinsView that adds a memory cache for transactions to another CCoinsView */
class CCoinsViewCache : public CCoinsViewBacked
{
protected:
    /* Whether this cache has an active modifier. */
    bool hasModifier;


    /**
     * Make mutable so that we can "fill the cache" even from Get-methods
     * declared as "const".
     */
    mutable uint256 hashBlock;
    mutable CCoinsMap cacheCoins;
    mutable uint256 hashSproutAnchor;
    mutable uint256 hashSaplingAnchor;
    mutable uint256 hashOrchardAnchor;
    mutable CAnchorsSproutMap cacheSproutAnchors;
    mutable CAnchorsSaplingMap cacheSaplingAnchors;
    mutable CAnchorsOrchardMap cacheOrchardAnchors;
    mutable CNullifiersMap cacheSproutNullifiers;
    mutable CNullifiersMap cacheSaplingNullifiers;
    mutable CNullifiersMap cacheOrchardNullifiers;
    mutable CHistoryCacheMap historyCacheMap;
    mutable SubtreeCache cacheSaplingSubtrees = SubtreeCache(SAPLING);
    mutable SubtreeCache cacheOrchardSubtrees = SubtreeCache(ORCHARD);

    /* Cached dynamic memory usage for the inner CCoins objects. */
    mutable size_t cachedCoinsUsage;

public:
    CCoinsViewCache(CCoinsView *baseIn);
    ~CCoinsViewCache();

    // Standard CCoinsView methods
    bool GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const;
    bool GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const;
    bool GetOrchardAnchorAt(const uint256 &rt, OrchardMerkleFrontier &tree) const;
    bool GetNullifier(const uint256 &nullifier, ShieldedType type) const;
    bool GetCoins(const uint256 &txid, CCoins &coins) const;
    bool HaveCoins(const uint256 &txid) const;
    uint256 GetBestBlock() const;
    uint256 GetBestAnchor(ShieldedType type) const;
    HistoryIndex GetHistoryLength(uint32_t epochId) const;
    HistoryNode GetHistoryAt(uint32_t epochId, HistoryIndex index) const;
    uint256 GetHistoryRoot(uint32_t epochId) const;
    std::optional<libzcash::LatestSubtree> GetLatestSubtree(ShieldedType type) const;
    std::optional<libzcash::SubtreeData> GetSubtreeData(
            ShieldedType type,
            libzcash::SubtreeIndex index) const;
    void SetBestBlock(const uint256 &hashBlock);
    bool BatchWrite(CCoinsMap &mapCoins,
                    const uint256 &hashBlock,
                    const uint256 &hashSproutAnchor,
                    const uint256 &hashSaplingAnchor,
                    const uint256 &hashOrchardAnchor,
                    CAnchorsSproutMap &mapSproutAnchors,
                    CAnchorsSaplingMap &mapSaplingAnchors,
                    CAnchorsOrchardMap &mapOrchardAnchors,
                    CNullifiersMap &mapSproutNullifiers,
                    CNullifiersMap &mapSaplingNullifiers,
                    CNullifiersMap &mapOrchardNullifiers,
                    CHistoryCacheMap &historyCacheMap,
                    SubtreeCache &cacheSaplingSubtrees,
                    SubtreeCache &cacheOrchardSubtrees);

    // Adds the tree to mapSproutAnchors, mapSaplingAnchors, or mapOrchardAnchors
    // based on the type of tree and sets the current commitment root to this root.
    template<typename Tree> void PushAnchor(const Tree &tree);

    // Removes the current commitment root from mapAnchors and sets
    // the new current root.
    void PopAnchor(const uint256 &rt, ShieldedType type);

    // Marks nullifiers for a given transaction as spent or not.
    void SetNullifiers(const CTransaction& tx, bool spent);

    // Push MMR node history at the end of the history tree
    void PushHistoryNode(uint32_t epochId, const HistoryNode node);

    // Pop MMR node history from the end of the history tree
    void PopHistoryNode(uint32_t epochId);

    // Push a new subtree for a given shielded type. Only Sapling
    // and Orchard supported.
    void PushSubtree(ShieldedType type, libzcash::SubtreeData subtree);

    // Pop a subtree out of the database. Only Sapling and Orchard
    // supported. Throws an exception if there isn't a subtree present
    // in the database.
    void PopSubtree(ShieldedType type);

    //! Effectively pops all subtrees from the view
    void ResetSubtrees(ShieldedType type);

    /**
     * Return a pointer to CCoins in the cache, or NULL if not found. This is
     * more efficient than GetCoins. Modifications to other cache entries are
     * allowed while accessing the returned pointer.
     */
    const CCoins* AccessCoins(const uint256 &txid) const;

    /**
     * Return a modifiable reference to a CCoins. If no entry with the given
     * txid exists, a new one is created. Simultaneous modifications are not
     * allowed.
     */
    CCoinsModifier ModifyCoins(const uint256 &txid);

    /**
     * Return a modifiable reference to a CCoins. Assumes that no entry with the given
     * txid exists and creates a new one. This saves a database access in the case where
     * the coins were to be wiped out by FromTx anyway. We rely on Zcash-derived block chains
     * having no duplicate transactions, since BIP 30 and (except for the genesis block)
     * BIP 34 have been enforced since launch. See the Zcash protocol specification, section
     * "Bitcoin Improvement Proposals". Simultaneous modifications are not allowed.
     */
    CCoinsModifier ModifyNewCoins(const uint256 &txid);

    /**
     * Push the modifications applied to this cache to its base.
     * Failure to call this method before destruction will cause the changes to be forgotten.
     * If false is returned, the state of this cache (and its backing view) will be undefined.
     */
    bool Flush();

    //! Calculate the size of the cache (in number of transactions)
    unsigned int GetCacheSize() const;

    //! Calculate the size of the cache (in bytes)
    size_t DynamicMemoryUsage() const;

    /**
     * Amount of coins coming in to a transaction
     *
     * @param[in] tx	transaction for which we are checking input total
     * @return	Sum of value of all inputs (scriptSigs), JoinSplit vpub_new, and
     *          positive values of valueBalanceSapling, and valueBalanceOrchard.
     */
    CAmount GetValueIn(const CTransaction& tx) const;

    /**
     * Amount of coins coming in to a transaction in the transparent inputs.
     *
     * @param[in] tx	transaction for which we are checking input total
     * @return	Sum of value of all inputs (scriptSigs)
     */
    CAmount GetTransparentValueIn(const CTransaction& tx) const;

    //! Check whether all prevouts of the transaction are present in the UTXO set represented by this view
    bool HaveInputs(const CTransaction& tx) const;

    //! Check whether all shielded spend requirements (anchors/nullifiers) are satisfied
    tl::expected<void, UnsatisfiedShieldedReq> CheckShieldedRequirements(const CTransaction& tx) const;

    const CTxOut &GetOutputFor(const CTxIn& input) const;

    friend class CCoinsModifier;

private:
    CCoinsMap::iterator FetchCoins(const uint256 &txid);
    CCoinsMap::const_iterator FetchCoins(const uint256 &txid) const;

    /**
     * By making the copy constructor private, we prevent accidentally using it
     * when one intends to create a cache on top of a base cache.
     */
    CCoinsViewCache(const CCoinsViewCache &);

    //! Generalized interface for popping anchors
    template<typename Tree, typename Cache, typename CacheEntry>
    void AbstractPopAnchor(
        const uint256 &newrt,
        ShieldedType type,
        Cache &cacheAnchors,
        uint256 &hash
    );

    //! Generalized interface for pushing anchors
    template<typename Tree, typename Cache, typename CacheIterator, typename CacheEntry>
    void AbstractPushAnchor(
        const Tree &tree,
        ShieldedType type,
        Cache &cacheAnchors,
        uint256 &hash
    );

    //! Interface for bringing an anchor into the cache.
    template<typename Tree>
    void BringBestAnchorIntoCache(
        const uint256 &currentRoot,
        Tree &tree
    );

    //! Preload history tree for further update.
    //!
    //! If extra = true, extra nodes for deletion are also preloaded.
    //! This will allow to delete tail entries from preloaded tree without
    //! any further database lookups.
    //!
    //! Returns number of peaks, not total number of loaded nodes.
    uint32_t PreloadHistoryTree(uint32_t epochId, bool extra, std::vector<HistoryEntry> &entries, std::vector<uint32_t> &entry_indices);

    //! Selects history cache for specified epoch.
    HistoryCache& SelectHistoryCache(uint32_t epochId) const;
};

#endif // BITCOIN_COINS_H
