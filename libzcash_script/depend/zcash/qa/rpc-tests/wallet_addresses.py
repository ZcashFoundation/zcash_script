#!/usr/bin/env python3
# Copyright (c) 2018 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    start_nodes,
    stop_nodes,
    wait_bitcoinds,
    NU5_BRANCH_ID,
)
from test_framework.mininode import nuparams

# Test wallet address behaviour across network upgrades
class WalletAddressesTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        # need 2 nodes to import addresses
        self.num_nodes = 2
        self.cache_behavior = 'clean'

    def setup_network(self):
        self.nodes = start_nodes(
            self.num_nodes, self.options.tmpdir, extra_args=[[
                nuparams(NU5_BRANCH_ID, 2),
                '-allowdeprecated=getnewaddress',
                '-allowdeprecated=z_getnewaddress',
            ]] * self.num_nodes)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def list_addresses(self, node, expected_sources):
        addrs = self.nodes[node].listaddresses()
        sources = [s['source'] for s in addrs]
        # Sources should be unique.
        assert_equal(len(set(sources)), len(sources))
        assert_equal(set(sources), set(expected_sources))

        # Extract a list of all addresses from the output.
        all_addrs = [
            source.get('transparent', {}).get('addresses', []) +
            source.get('transparent', {}).get('changeAddresses', []) +
            source.get('sprout', {}).get('addresses', []) +
            [s['addresses'] for s in source.get('sapling', [])] +
            [[a['address'] for a in s['addresses']] for s in source.get('unified', [])]
        for source in addrs]
        all_addrs = [a for s in all_addrs for a in s]
        all_addrs = [a if type(a) == list else [a] for a in all_addrs]
        all_addrs = [a for s in all_addrs for a in s]

        assert_equal(len(set(all_addrs)), len(all_addrs), "Duplicates in listaddresses output: %s" % addrs)
        return addrs

    def run_test(self):
        def get_source(listed_addresses, source):
            return next(src for src in listed_addresses if src['source'] == source)

        print("Testing height 1 (Sapling)")
        self.nodes[0].generate(1)
        self.sync_all()
        assert_equal(self.nodes[0].getblockcount(), 1)
        listed_addresses = self.list_addresses(0, ['mnemonic_seed'])
        # There should be a single address from the coinbase, which was derived
        # from the mnemonic seed.
        assert 'transparent' in get_source(listed_addresses, 'mnemonic_seed')

        # If we import a t-address, we should see imported_watchonly as a source.
        taddr_import = self.nodes[1].getnewaddress()
        self.nodes[0].importaddress(taddr_import)
        listed_addresses = self.list_addresses(0, ['imported_watchonly', 'mnemonic_seed'])
        imported_watchonly_src = get_source(listed_addresses, 'imported_watchonly')
        assert_equal(imported_watchonly_src['transparent']['addresses'][0], taddr_import)

        account = self.nodes[0].z_getnewaccount()['account']
        sprout_1 = self.nodes[0].z_getnewaddress('sprout')
        sapling_1 = self.nodes[0].z_getnewaddress('sapling')
        unified_1 = self.nodes[0].z_getaddressforaccount(account)['address']
        types_and_addresses = [
            ('sprout', sprout_1),
            ('sapling', sapling_1),
            ('unified', unified_1),
        ]

        for addr_type, addr in types_and_addresses:
            res = self.nodes[0].z_validateaddress(addr)
            assert res['isvalid']
            # assert res['ismine'] # this isn't present for unified addresses
            assert_equal(res['address_type'], addr_type)

        # We should see the following sources:
        # - imported_watchonly (for the previously-imported t-addr)
        # - legacy_random (for the new Sprout address)
        # - mnemonic_seed (for the previous t-addrs and the new Sapling and Unified addrs)
        listed_addresses = self.list_addresses(0, ['imported_watchonly', 'legacy_random', 'mnemonic_seed'])
        legacy_random_src = get_source(listed_addresses, 'legacy_random')
        mnemonic_seed_src = get_source(listed_addresses, 'mnemonic_seed')

        # Check Sprout addrs
        assert_equal(legacy_random_src['sprout']['addresses'], [sprout_1])

        # Check Sapling addrs
        assert_equal(
            set([(obj['zip32KeyPath'], x) for obj in mnemonic_seed_src['sapling'] for x in obj['addresses']]),
            set([("m/32'/1'/2147483647'/0'", sapling_1)]),
        )

        # Check Unified addrs
        unified_obj = mnemonic_seed_src['unified']
        assert_equal(unified_obj[0]['account'], 0)
        assert_equal(unified_obj[0]['addresses'][0]['address'], unified_1)
        assert 'diversifier_index' in unified_obj[0]['addresses'][0]
        assert_equal(unified_obj[0]['addresses'][0]['receiver_types'], ['p2pkh', 'sapling', 'orchard'])

        # import the key for sapling_1 into node 1
        sapling_1_key = self.nodes[0].z_exportkey(sapling_1)
        self.nodes[1].z_importkey(sapling_1_key)

        # verify that we see the imported source
        listed_addresses = self.list_addresses(1, ['imported', 'mnemonic_seed'])
        imported_src = get_source(listed_addresses, 'imported')
        assert_equal(imported_src['sapling'][0]['addresses'], [sapling_1])

        # stop the nodes & restart to ensure that the imported address
        # still shows up in listaddresses output
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.setup_network()

        listed_addresses = self.list_addresses(1, ['imported', 'mnemonic_seed'])
        imported_src = get_source(listed_addresses, 'imported')
        assert_equal(imported_src['sapling'][0]['addresses'], [sapling_1])

        print("Testing height 2 (NU5)")
        self.nodes[0].generate(1)
        self.sync_all()
        assert_equal(self.nodes[0].getblockcount(), 2)
        # Sprout address generation is no longer allowed
        sapling_2 = self.nodes[0].z_getnewaddress('sapling')
        unified_2 = self.nodes[0].z_getaddressforaccount(account)['address']
        types_and_addresses = [
            ('sapling', sapling_2),
            ('unified', unified_2),
        ]

        for addr_type, addr in types_and_addresses:
            res = self.nodes[0].z_validateaddress(addr)
            assert res['isvalid']
            # assert res['ismine'] # this isn't present for unified addresses
            assert_equal(res['address_type'], addr_type)

        # We should see the same sources (address generation does not change across the NU5 boundary).
        listed_addresses = self.list_addresses(0, ['imported_watchonly', 'legacy_random', 'mnemonic_seed'])
        legacy_random_src = get_source(listed_addresses, 'legacy_random')
        mnemonic_seed_src = get_source(listed_addresses, 'mnemonic_seed')

        # Check Sprout addrs
        assert_equal(legacy_random_src['sprout']['addresses'], [sprout_1])

        # Check Sapling addrs
        assert_equal(
            set([(obj['zip32KeyPath'], x) for obj in mnemonic_seed_src['sapling'] for x in obj['addresses']]),
            set([
                ("m/32'/1'/2147483647'/0'", sapling_1),
                ("m/32'/1'/2147483647'/1'", sapling_2),
            ]),
        )

        # Check Unified addrs
        unified_obj = mnemonic_seed_src['unified']
        assert_equal(unified_obj[0]['account'], 0)
        assert_equal(
            set([addr['address'] for addr in unified_obj[0]['addresses']]),
            set([unified_1, unified_2]),
        )
        assert 'diversifier_index' in unified_obj[0]['addresses'][0]
        assert 'diversifier_index' in unified_obj[0]['addresses'][1]
        assert_equal(unified_obj[0]['addresses'][0]['receiver_types'], ['p2pkh', 'sapling', 'orchard'])
        assert_equal(unified_obj[0]['addresses'][1]['receiver_types'], ['p2pkh', 'sapling', 'orchard'])

        print("Generate mature coinbase, spend to create and detect change")
        self.nodes[0].generate(100)
        self.sync_all()
        self.nodes[0].sendmany('', {taddr_import: 1})
        listed_addresses = self.list_addresses(0, ['imported_watchonly', 'legacy_random', 'mnemonic_seed'])
        mnemonic_seed_src = get_source(listed_addresses, 'mnemonic_seed')
        assert len(mnemonic_seed_src['transparent']['changeAddresses']) > 0


if __name__ == '__main__':
    WalletAddressesTest().main()
