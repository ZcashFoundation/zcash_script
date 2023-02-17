// Copyright (c) 2021-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <gtest/gtest.h>

#include "zcash/address/mnemonic.h"
#include "zcash/address/orchard.hpp"

TEST(OrchardZkeysTest, IVKSerializationRoundtrip) {
    auto seed = MnemonicSeed::Random(1); //testnet coin type
    auto sk = libzcash::OrchardSpendingKey::ForAccount(seed, 1, 0);
    auto fvk = sk.ToFullViewingKey();
    auto ivk = fvk.ToIncomingViewingKey();

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << ivk;

    auto ivk0 = libzcash::OrchardIncomingViewingKey::Read(ss);

    ASSERT_EQ(ivk, ivk0);
}

TEST(OrchardZkeysTest, FVKSerializationRoundtrip) {
    auto seed = MnemonicSeed::Random(1); //testnet coin type
    auto sk = libzcash::OrchardSpendingKey::ForAccount(seed, 1, 0);
    auto fvk = sk.ToFullViewingKey();

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << fvk;

    auto fvk0 = libzcash::OrchardFullViewingKey::Read(ss);

    ASSERT_EQ(fvk, fvk0);
}
