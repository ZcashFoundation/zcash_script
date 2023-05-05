// Copyright (c) 2016-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZCASH_WALLET_ASYNCRPCOPERATION_SENDMANY_H
#define ZCASH_WALLET_ASYNCRPCOPERATION_SENDMANY_H

#include "asyncrpcoperation.h"
#include "amount.h"
#include "primitives/transaction.h"
#include "transaction_builder.h"
#include "zcash/JoinSplit.hpp"
#include "zcash/Address.hpp"
#include "wallet.h"
#include "wallet/paymentdisclosure.h"
#include "wallet/wallet_tx_builder.h"

#include <array>
#include <optional>
#include <unordered_map>
#include <tuple>

#include <univalue.h>

using namespace libzcash;

class AsyncRPCOperation_sendmany : public AsyncRPCOperation {
public:
    AsyncRPCOperation_sendmany(
        WalletTxBuilder builder,
        ZTXOSelector ztxoSelector,
        std::vector<Payment> recipients,
        int minDepth,
        unsigned int anchorDepth,
        TransactionStrategy strategy,
        std::optional<CAmount> fee,
        UniValue contextInfo = NullUniValue);

    virtual ~AsyncRPCOperation_sendmany();

    // We don't want to be copied or moved around
    AsyncRPCOperation_sendmany(AsyncRPCOperation_sendmany const&) = delete;             // Copy construct
    AsyncRPCOperation_sendmany(AsyncRPCOperation_sendmany&&) = delete;                  // Move construct
    AsyncRPCOperation_sendmany& operator=(AsyncRPCOperation_sendmany const&) = delete;  // Copy assign
    AsyncRPCOperation_sendmany& operator=(AsyncRPCOperation_sendmany &&) = delete;      // Move assign

    virtual void main();

    virtual UniValue getStatus() const;

    bool testmode{false};  // Set to true to disable sending txs and generating proofs

private:
    friend class TEST_FRIEND_AsyncRPCOperation_sendmany;    // class for unit testing

    WalletTxBuilder builder_;
    ZTXOSelector ztxoSelector_;
    std::vector<Payment> recipients_;
    TransactionStrategy strategy_;
    int mindepth_{1};
    unsigned int anchordepth_{nAnchorConfirmations};
    std::optional<CAmount> fee_;
    UniValue contextinfo_;     // optional data to include in return value from getStatus()

    tl::expected<uint256, InputSelectionError> main_impl(CWallet& wallet);
};

// To test private methods, a friend class can act as a proxy
class TEST_FRIEND_AsyncRPCOperation_sendmany {
public:
    std::shared_ptr<AsyncRPCOperation_sendmany> delegate;

    TEST_FRIEND_AsyncRPCOperation_sendmany(std::shared_ptr<AsyncRPCOperation_sendmany> ptr) : delegate(ptr) {}

    tl::expected<uint256, InputSelectionError> main_impl(CWallet& wallet) {
        return delegate->main_impl(wallet);
    }

    void set_state(OperationStatus state) {
        delegate->state_.store(state);
    }
};


#endif // ZCASH_WALLET_ASYNCRPCOPERATION_SENDMANY_H
