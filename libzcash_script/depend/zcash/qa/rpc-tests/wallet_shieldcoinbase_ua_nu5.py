#!/usr/bin/env python3

from wallet_shieldcoinbase import WalletShieldCoinbaseTest
from test_framework.util import assert_equal
from test_framework.mininode import COIN

class WalletShieldCoinbaseUANU5(WalletShieldCoinbaseTest):
    def __init__(self):
        super(WalletShieldCoinbaseUANU5, self).__init__()
        self.account = None
        # activate after initial setup, before the first z_shieldcoinbase RPC
        self.nu5_activation = 109

    def test_init_zaddr(self, node):
        # this function may be called no more than once
        assert(self.account is None)
        self.account = node.z_getnewaccount()['account']
        self.addr = node.z_getaddressforaccount(self.account)['address']
        return self.addr

    def test_check_balance_zaddr(self, node, expected):
        balances = node.z_getbalanceforaccount(self.account)
        assert('transparent' not in balances['pools'])
        assert('sprout' not in balances['pools'])
        # Remove the following after Orchard support is added to z_shieldcoinbase
        sapling_balance = balances['pools']['sapling']['valueZat']
        assert_equal(sapling_balance, expected * COIN)
        # TODO: Uncomment after Orchard support is added to z_shieldcoinbase
        #assert('sapling' not in balances['pools'])
        #orchard_balance = balances['pools']['orchard']['valueZat']
        #assert_equal(orchard_balance, expected * COIN)

        # While we're at it, check that z_listunspent only shows outputs with
        # the Unified Address (not the Orchard receiver), and of the expected
        # pool.
        unspent = node.z_listunspent(1, 999999, False, [self.addr])
        assert_equal(
            # TODO: Fix after Orchard support is added to z_shieldcoinbase
            #[{'pool': 'orchard', 'address': self.addr} for _ in unspent],
            [{'pool': 'sapling', 'address': self.addr} for _ in unspent],
            [{'pool': x['pool'], 'address': x['address']} for x in unspent],
        )

        total_balance = node.z_getbalance(self.addr) * COIN
        assert_equal(total_balance, sapling_balance)

if __name__ == '__main__':
    print("Test shielding to a unified address with NU5 activated")
    WalletShieldCoinbaseUANU5().main()
