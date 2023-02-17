// Copyright (c) 2021-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZCASH_PRIMITIVES_ORCHARD_H
#define ZCASH_PRIMITIVES_ORCHARD_H

#include "streams.h"

#include <amount.h>
#include <rust/orchard.h>
#include <rust/orchard_bundle.h>
#include <rust/orchard/wallet.h>
#include "zcash/address/orchard.hpp"

class OrchardMerkleFrontier;
class OrchardWallet;
namespace orchard { class UnauthorizedBundle; }

/**
 * The Orchard component of an authorized transaction.
 */
class OrchardBundle
{
private:
    /// An optional Orchard bundle (with `nullptr` corresponding to `None`).
    /// Memory is allocated by Rust.
    std::unique_ptr<OrchardBundlePtr, decltype(&orchard_bundle_free)> inner;

    OrchardBundle(OrchardBundlePtr* bundle) : inner(bundle, orchard_bundle_free) {}

    friend class OrchardMerkleFrontier;
    friend class OrchardWallet;
    friend class orchard::UnauthorizedBundle;
public:
    OrchardBundle() : inner(nullptr, orchard_bundle_free) {}

    OrchardBundle(OrchardBundle&& bundle) : inner(std::move(bundle.inner)) {}

    OrchardBundle(const OrchardBundle& bundle) :
        inner(orchard_bundle_clone(bundle.inner.get()), orchard_bundle_free) {}

    OrchardBundle& operator=(OrchardBundle&& bundle)
    {
        if (this != &bundle) {
            inner = std::move(bundle.inner);
        }
        return *this;
    }

    OrchardBundle& operator=(const OrchardBundle& bundle)
    {
        if (this != &bundle) {
            inner.reset(orchard_bundle_clone(bundle.inner.get()));
        }
        return *this;
    }

    rust::Box<orchard_bundle::Bundle> GetDetails() const {
        return orchard_bundle::from_tx_bundle(reinterpret_cast<orchard_bundle::OrchardBundle*>(inner.get()));
    }

    size_t RecursiveDynamicUsage() const {
        return orchard_bundle_recursive_dynamic_usage(inner.get());
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        RustStream rs(s);
        if (!orchard_bundle_serialize(inner.get(), &rs, RustStream<Stream>::write_callback)) {
            throw std::ios_base::failure("Failed to serialize v5 Orchard bundle");
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        RustStream rs(s);
        OrchardBundlePtr* bundle;
        if (!orchard_bundle_parse(&rs, RustStream<Stream>::read_callback, &bundle)) {
            throw std::ios_base::failure("Failed to parse v5 Orchard bundle");
        }
        inner.reset(bundle);
    }

    /// Returns true if this contains an Orchard bundle, or false if there is no
    /// Orchard component.
    bool IsPresent() const { return (bool)inner; }

    /// Returns the net value entering or exiting the Orchard pool as a result of this
    /// bundle.
    CAmount GetValueBalance() const {
        return orchard_bundle_value_balance(inner.get());
    }

    /// Queues this bundle's authorization for validation.
    ///
    /// `sighash` must be for the transaction this bundle is within.
    void QueueAuthValidation(
        orchard::AuthValidator& batch, const uint256& sighash) const
    {
        batch.Queue(inner.get(), sighash.begin());
    }

    const size_t GetNumActions() const {
        return orchard_bundle_actions_len(inner.get());
    }

    const std::vector<uint256> GetNullifiers() const {
        size_t actions_len = orchard_bundle_actions_len(inner.get());
        std::vector<uint256> result(actions_len);
        auto nullifiers_ok = orchard_bundle_nullifiers(inner.get(), result.data(), actions_len);
        assert(nullifiers_ok);
        return result;
    }

    const std::optional<uint256> GetAnchor() const {
        uint256 result;
        if (orchard_bundle_anchor(inner.get(), result.begin())) {
            return result;
        } else {
            return std::nullopt;
        }
    }

    bool OutputsEnabled() const {
        return orchard_bundle_outputs_enabled(inner.get());
    }

    bool SpendsEnabled() const {
        return orchard_bundle_spends_enabled(inner.get());
    }

    bool CoinbaseOutputsAreValid() const {
        return orchard_bundle_coinbase_outputs_are_valid(inner.get());
    }
};

#endif // ZCASH_PRIMITIVES_ORCHARD_H

