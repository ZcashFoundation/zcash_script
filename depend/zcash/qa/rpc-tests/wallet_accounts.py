#!/usr/bin/env python3
# Copyright (c) 2022 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

from test_framework.authproxy import JSONRPCException
from test_framework.mininode import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    NU5_BRANCH_ID,
    assert_equal,
    assert_raises_message,
    assert_true,
    get_coinbase_address,
    nuparams,
    start_nodes,
    wait_and_assert_operationid_status,
)

from decimal import Decimal

# Test wallet accounts behaviour
class WalletAccountsTest(BitcoinTestFramework):
    def setup_nodes(self):
        return start_nodes(self.num_nodes, self.options.tmpdir, [[
            nuparams(NU5_BRANCH_ID, 210),
            '-allowdeprecated=z_getnewaddress',
            '-allowdeprecated=z_getbalance',
            '-allowdeprecated=z_gettotalbalance',
            '-allowdeprecated=z_listaddresses',
        ]] * self.num_nodes)

    def check_receiver_types(self, ua, expected):
        actual = self.nodes[0].z_listunifiedreceivers(ua)
        assert_equal(set(expected), set(actual))

    def check_z_listaccounts(self, node, acct_id, addr_id, ua):
        accounts = self.nodes[node].z_listaccounts()
        assert_equal(accounts[acct_id]['addresses'][addr_id]['ua'], ua['address'])
        assert_equal(accounts[acct_id]['addresses'][addr_id]['diversifier_index'], ua['diversifier_index'])

    # Check we only have balances in the expected pools.
    # Remember that empty pools are omitted from the output.
    def _check_balance_for_rpc(self, rpcmethod, node, account, expected, minconf):
        rpc = getattr(self.nodes[node], rpcmethod)
        actual = rpc(account, minconf)
        assert_equal(set(expected), set(actual['pools']))
        total_balance = 0
        for pool in expected:
            assert_equal(expected[pool] * COIN, actual['pools'][pool]['valueZat'])
            total_balance += expected[pool]
        assert_equal(actual['minimum_confirmations'], minconf)
        return total_balance

    def check_balance(self, node, account, address, expected, minconf=1):
        acct_balance = self._check_balance_for_rpc('z_getbalanceforaccount', node, account, expected, minconf)
        z_getbalance = self.nodes[node].z_getbalance(address, minconf)
        assert_equal(acct_balance, z_getbalance)
        fvk = self.nodes[node].z_exportviewingkey(address)
        self._check_balance_for_rpc('z_getbalanceforviewingkey', node, fvk, expected, minconf)

    def run_test(self):
        # With a new wallet, the first account will be 0.
        account0 = self.nodes[0].z_getnewaccount()
        assert_equal(account0['account'], 0)

        # Verify that just creating the account does not generate any visible addresses
        addresses = self.nodes[0].z_listaddresses()
        assert_equal([], addresses)
        accounts = self.nodes[0].z_listaccounts()
        assert_equal(len(accounts), 1)
        assert_equal(accounts[0]['account'], 0)

        # The next account will be 1.
        account1 = self.nodes[0].z_getnewaccount()
        assert_equal(account1['account'], 1)
        accounts = self.nodes[0].z_listaccounts()
        assert_equal(len(accounts), 2)
        assert_equal(accounts[1]['account'], 1)

        # Generate the first address for account 0.
        addr0 = self.nodes[0].z_getaddressforaccount(0)
        assert_equal(addr0['account'], 0)
        assert_equal(set(addr0['receiver_types']), set(['p2pkh', 'sapling', 'orchard']))
        ua0 = addr0['address']
        self.check_z_listaccounts(0, 0, 0, addr0)

        # We pick mnemonic phrases to ensure that we can always generate the default
        # address in account 0; this is however not necessarily at diversifier index 0.
        # We should be able to generate it directly and get the exact same data.
        j = addr0['diversifier_index']
        assert_equal(self.nodes[0].z_getaddressforaccount(0, [], j), addr0)
        if j > 0:
            # We should get an error if we generate the address at diversifier index 0.
            assert_raises_message(
                JSONRPCException,
                'no address at diversifier index 0',
                self.nodes[0].z_getaddressforaccount, 0, [], 0)

        # The second address for account 0 is different to the first address.
        addr0_2 = self.nodes[0].z_getaddressforaccount(0)
        assert_equal(addr0_2['account'], 0)
        assert_equal(set(addr0_2['receiver_types']), set(['p2pkh', 'sapling', 'orchard']))
        ua0_2 = addr0_2['address']
        assert(ua0 != ua0_2)
        self.check_z_listaccounts(0, 0, 1, addr0_2)

        # We can generate a fully-shielded address.
        addr0_3 = self.nodes[0].z_getaddressforaccount(0, ['sapling', 'orchard'])
        assert_equal(addr0_3['account'], 0)
        assert_equal(set(addr0_3['receiver_types']), set(['sapling', 'orchard']))
        ua0_3 = addr0_3['address']
        self.check_z_listaccounts(0, 0, 2, addr0_3)

        # We can generate an address without a Sapling receiver.
        addr0_4 = self.nodes[0].z_getaddressforaccount(0, ['p2pkh', 'orchard'])
        assert_equal(addr0_4['account'], 0)
        assert_equal(set(addr0_4['receiver_types']), set(['p2pkh', 'orchard']))
        ua0_4 = addr0_4['address']
        self.check_z_listaccounts(0, 0, 3, addr0_4)

        # The first address for account 1 is different to account 0.
        addr1 = self.nodes[0].z_getaddressforaccount(1)
        assert_equal(addr1['account'], 1)
        assert_equal(set(addr1['receiver_types']), set(['p2pkh', 'sapling', 'orchard']))
        ua1 = addr1['address']
        assert(ua0 != ua1)
        self.check_z_listaccounts(0, 1, 0, addr1)

        # The UA contains the expected receiver kinds.
        self.check_receiver_types(ua0,   ['p2pkh', 'sapling', 'orchard'])
        self.check_receiver_types(ua0_2, ['p2pkh', 'sapling', 'orchard'])
        self.check_receiver_types(ua0_3, [         'sapling', 'orchard'])
        self.check_receiver_types(ua0_4, ['p2pkh',            'orchard'])
        self.check_receiver_types(ua1,   ['p2pkh', 'sapling', 'orchard'])

        # The balances of the accounts are all zero.
        self.check_balance(0, 0, ua0, {})
        self.check_balance(0, 1, ua1, {})

        # Send coinbase funds to the UA.
        print('Sending coinbase funds to account')
        recipients = [{'address': ua0, 'amount': Decimal('10')}]
        opid = self.nodes[0].z_sendmany(get_coinbase_address(self.nodes[0]), recipients, 1, 0, 'AllowRevealedSenders')
        txid = wait_and_assert_operationid_status(self.nodes[0], opid)

        # The wallet should detect the new note as belonging to the UA.
        tx_details = self.nodes[0].z_viewtransaction(txid)
        assert_equal(len(tx_details['outputs']), 1)
        assert_equal(tx_details['outputs'][0]['pool'], 'sapling')
        assert_equal(tx_details['outputs'][0]['address'], ua0)

        # The new balance should not be visible with the default minconf, but should be
        # visible with minconf=0.
        self.sync_all()
        self.check_balance(0, 0, ua0, {})
        self.check_balance(0, 0, ua0, {'sapling': 10}, 0)

        self.nodes[2].generate(1)
        self.sync_all()

        # The default minconf should now detect the balance.
        self.check_balance(0, 0, ua0, {'sapling': 10})

        # Send Sapling funds from the UA.
        print('Sending account funds to Sapling address')
        node1sapling = self.nodes[1].z_getnewaddress('sapling')

        recipients = [{'address': node1sapling, 'amount': Decimal('1')}]
        opid = self.nodes[0].z_sendmany(ua0, recipients, 1, 0)
        txid = wait_and_assert_operationid_status(self.nodes[0], opid)

        # The wallet should detect the spent note as belonging to the UA.
        tx_details = self.nodes[0].z_viewtransaction(txid)
        assert_equal(len(tx_details['spends']), 1)
        assert_equal(tx_details['spends'][0]['pool'], 'sapling')
        assert_equal(tx_details['spends'][0]['address'], ua0)

        # The balances of the account should reflect whether zero-conf transactions are
        # being considered. We will show either 0 (because the spent 10-ZEC note is never
        # shown, as that transaction has been created and broadcast, and _might_ get mined
        # up until the transaction expires), or 9 (if we include the unmined transaction).
        self.sync_all()
        self.check_balance(0, 0, ua0, {})
        self.check_balance(0, 0, ua0, {'sapling': 9}, 0)

        # Activate NU5
        print('Activating NU5')
        self.nodes[2].generate(9)
        self.sync_all()
        assert_equal(self.nodes[0].getblockchaininfo()['blocks'], 210)

        # Send more coinbase funds to the UA.
        print('Sending coinbase funds to account')
        recipients = [{'address': ua0, 'amount': Decimal('10')}]
        opid = self.nodes[0].z_sendmany(get_coinbase_address(self.nodes[0]), recipients, 1, 0, 'AllowRevealedSenders')
        txid = wait_and_assert_operationid_status(self.nodes[0], opid)

        # The wallet should detect the new note as belonging to the UA.
        tx_details = self.nodes[0].z_viewtransaction(txid)
        assert_equal(len(tx_details['outputs']), 1)
        assert_equal(tx_details['outputs'][0]['pool'], 'orchard')
        assert_equal(tx_details['outputs'][0]['address'], ua0)

        # The new balance should not be visible with the default minconf, but should be
        # visible with minconf=0.
        self.sync_all()
        self.check_balance(0, 0, ua0, {'sapling': 9})
        self.check_balance(0, 0, ua0, {'sapling': 9, 'orchard': 10}, 0)

        # The total balance with the default minconf should be just the Sapling balance
        assert_equal('9.00', self.nodes[0].z_gettotalbalance()['private'])
        assert_equal('19.00', self.nodes[0].z_gettotalbalance(0)['private'])

        self.nodes[2].generate(1)
        self.sync_all()

        # Send Orchard funds from the UA.
        print('Sending account funds to Orchard-only UA')
        node1account = self.nodes[1].z_getnewaccount()['account']
        node1orchard = self.nodes[1].z_getaddressforaccount(node1account, ['orchard'])
        self.check_z_listaccounts(1, 0, 0, node1orchard)
        node1orchard = node1orchard['address']

        recipients = [{'address': node1orchard, 'amount': Decimal('1')}]
        opid = self.nodes[0].z_sendmany(ua0, recipients, 1, 0)
        txid = wait_and_assert_operationid_status(self.nodes[0], opid)

        # The wallet should detect the spent note as belonging to the UA.
        tx_details = self.nodes[0].z_viewtransaction(txid)
        assert_equal(len(tx_details['spends']), 1)
        assert_equal(tx_details['spends'][0]['pool'], 'orchard')
        assert_equal(tx_details['spends'][0]['address'], ua0)

        assert_equal(len(tx_details['outputs']), 2)
        outputs = sorted(tx_details['outputs'], key=lambda x: x['valueZat'])
        assert_equal(outputs[0]['pool'], 'orchard')
        assert_equal(outputs[0]['address'], node1orchard)
        assert_equal(outputs[0]['valueZat'], 100000000)
        # outputs[1] is change
        assert_equal(outputs[1]['pool'], 'orchard')
        assert_true('address' not in outputs[1]) #

        # The balances of the account should reflect whether zero-conf transactions are
        # being considered. The Sapling balance should remain at 9, while the Orchard
        # balance will show either 0 (because the spent 10-ZEC note is never shown, as
        # that transaction has been created and broadcast, and _might_ get mined up until
        # the transaction expires), or 9 (if we include the unmined transaction).
        self.sync_all()
        self.check_balance(0, 0, ua0, {'sapling': 9})
        self.check_balance(0, 0, ua0, {'sapling': 9, 'orchard': 9}, 0)


if __name__ == '__main__':
    WalletAccountsTest().main()
