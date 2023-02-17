#!/usr/bin/env python3
# Copyright (c) 2018 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    NU5_BRANCH_ID,
    assert_equal,
    assert_true,
    get_coinbase_address,
    nuparams,
    start_nodes,
    wait_and_assert_operationid_status,
    DEFAULT_FEE
)

from decimal import Decimal

# Test wallet z_listunspent behaviour across network upgrades
class WalletListNotes(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.cache_behavior = 'sprout'

    def setup_nodes(self):
        return start_nodes(4, self.options.tmpdir, [[
            nuparams(NU5_BRANCH_ID, 215),
            '-allowdeprecated=z_getnewaddress',
            '-allowdeprecated=z_getbalance',
            '-allowdeprecated=z_gettotalbalance',
        ]] * 4)

    def run_test(self):
        # Current height = 200 -> Sapling
        assert_equal(200, self.nodes[0].getblockcount())
        sproutzaddr = self.nodes[0].listaddresses()[0]['sprout']['addresses'][0]
        receive_amount_1 = self.nodes[0].z_getbalance(sproutzaddr)

        # Set current height to 201
        self.nodes[0].generate(1)
        self.sync_all()
        assert_equal(201, self.nodes[0].getblockcount())

        # Send 1.0 minus default fee from sproutzaddr to a new Sapling zaddr
        saplingzaddr = self.nodes[0].z_getnewaddress('sapling')
        receive_amount_2 = Decimal('1.0')
        change_amount_2 = receive_amount_1 - receive_amount_2 - DEFAULT_FEE
        assert_equal('sapling', self.nodes[0].z_validateaddress(saplingzaddr)['address_type'])
        recipients = [{"address": saplingzaddr, "amount":receive_amount_2}]
        myopid = self.nodes[0].z_sendmany(sproutzaddr, recipients, 1, DEFAULT_FEE, 'AllowRevealedAmounts')
        txid_2 = wait_and_assert_operationid_status(self.nodes[0], myopid)
        self.sync_all()

        # list unspent, allowing 0conf txs
        unspent_tx = self.nodes[0].z_listunspent(0)
        assert_equal(len(unspent_tx), 2)
        # sort low-to-high by amount (order of returned entries is not guaranteed)
        unspent_tx = sorted(unspent_tx, key=lambda k: k['amount'])
        assert_equal(txid_2,            unspent_tx[0]['txid'])
        assert_equal('sapling',         unspent_tx[0]['pool'])
        assert_equal(True,              unspent_tx[0]['spendable'])
        assert_equal(saplingzaddr,      unspent_tx[0]['address'])
        assert_equal(receive_amount_2,  unspent_tx[0]['amount'])
        assert_equal(False,             unspent_tx[0]['change'])

        assert_equal(txid_2,            unspent_tx[1]['txid'])
        assert_equal('sprout',          unspent_tx[1]['pool'])
        assert_equal(True,              unspent_tx[1]['spendable'])
        assert_equal(sproutzaddr,       unspent_tx[1]['address'])
        assert_equal(change_amount_2,   unspent_tx[1]['amount'])
        assert_equal(True,              unspent_tx[1]['change'])

        unspent_tx_filter = self.nodes[0].z_listunspent(0, 9999, False, [saplingzaddr])
        assert_equal(1, len(unspent_tx_filter))
        assert_equal(unspent_tx[0], unspent_tx_filter[0])

        unspent_tx_filter = self.nodes[0].z_listunspent(0, 9999, False, [sproutzaddr])
        assert_equal(1, len(unspent_tx_filter))
        assert_equal(unspent_tx[1], unspent_tx_filter[0])

        self.nodes[0].generate(1)
        self.sync_all()

        # Send 2.0 minus default fee to a new sapling zaddr
        saplingzaddr2 = self.nodes[0].z_getnewaddress('sapling')
        receive_amount_3 = Decimal('2.0')
        change_amount_3 = change_amount_2 - receive_amount_3 - DEFAULT_FEE
        recipients = [{"address": saplingzaddr2, "amount":receive_amount_3}]
        myopid = self.nodes[0].z_sendmany(sproutzaddr, recipients, 1, DEFAULT_FEE, 'AllowRevealedAmounts')
        txid_3 = wait_and_assert_operationid_status(self.nodes[0], myopid)
        self.sync_all()
        unspent_tx = self.nodes[0].z_listunspent(0)
        assert_equal(3, len(unspent_tx))

        # low-to-high in amount
        unspent_tx = sorted(unspent_tx, key=lambda k: k['amount'])

        assert_equal(txid_2,            unspent_tx[0]['txid'])
        assert_equal('sapling',         unspent_tx[0]['pool'])
        assert_equal(True,              unspent_tx[0]['spendable'])
        assert_equal(saplingzaddr,      unspent_tx[0]['address'])
        assert_equal(receive_amount_2,  unspent_tx[0]['amount'])
        assert_equal(False,             unspent_tx[0]['change'])

        assert_equal(txid_3,            unspent_tx[1]['txid'])
        assert_equal('sapling',         unspent_tx[1]['pool'])
        assert_equal(True,              unspent_tx[1]['spendable'])
        assert_equal(saplingzaddr2,     unspent_tx[1]['address'])
        assert_equal(receive_amount_3,  unspent_tx[1]['amount'])
        assert_equal(False,             unspent_tx[1]['change'])

        assert_equal(txid_3,            unspent_tx[2]['txid'])
        assert_equal('sprout',          unspent_tx[2]['pool'])
        assert_equal(True,              unspent_tx[2]['spendable'])
        assert_equal(sproutzaddr,       unspent_tx[2]['address'])
        assert_equal(change_amount_3,   unspent_tx[2]['amount'])
        assert_equal(True,              unspent_tx[2]['change'])

        unspent_tx_filter = self.nodes[0].z_listunspent(0, 9999, False, [saplingzaddr])
        assert_equal(1, len(unspent_tx_filter))
        assert_equal(unspent_tx[0], unspent_tx_filter[0])

        # test that pre- and post-sapling can be filtered in a single call
        unspent_tx_filter = self.nodes[0].z_listunspent(0, 9999, False,
            [sproutzaddr, saplingzaddr])
        assert_equal(2, len(unspent_tx_filter))
        unspent_tx_filter = sorted(unspent_tx_filter, key=lambda k: k['amount'])
        assert_equal(unspent_tx[0], unspent_tx_filter[0])
        assert_equal(unspent_tx[2], unspent_tx_filter[1])

        # so far, this node has no watchonly addresses, so results are the same
        unspent_tx_watchonly = self.nodes[0].z_listunspent(0, 9999, True)
        unspent_tx_watchonly = sorted(unspent_tx_watchonly, key=lambda k: k['amount'])
        assert_equal(unspent_tx, unspent_tx_watchonly)

        # TODO: use z_exportviewingkey, z_importviewingkey to test includeWatchonly
        # but this requires Sapling support for those RPCs

        # Set current height to 215 -> NU5
        self.nodes[0].generate(13)
        self.sync_all()
        assert_equal(215, self.nodes[0].getblockcount())

        # Create an Orchard note.
        account0 = self.nodes[0].z_getnewaccount()['account']
        ua0 = self.nodes[0].z_getaddressforaccount(account0)['address']
        receive_amount_4 = Decimal('10.0')
        recipients = [{"address": ua0, "amount": receive_amount_4}]
        myopid = self.nodes[0].z_sendmany(get_coinbase_address(self.nodes[0]), recipients, 1, 0, 'AllowRevealedSenders')
        txid_4 = wait_and_assert_operationid_status(self.nodes[0], myopid)
        self.sync_all()

        unspent_tx = self.nodes[0].z_listunspent(0)
        assert_equal(4, len(unspent_tx))
        # low-to-high in amount
        unspent_tx = sorted(unspent_tx, key=lambda k: k['amount'])

        assert_equal(txid_2,            unspent_tx[0]['txid'])
        assert_equal('sapling',         unspent_tx[0]['pool'])
        assert_equal(True,              unspent_tx[0]['spendable'])
        assert_true('account'    not in unspent_tx[0])
        assert_equal(saplingzaddr,      unspent_tx[0]['address'])
        assert_equal(receive_amount_2,  unspent_tx[0]['amount'])
        assert_equal(False,             unspent_tx[0]['change'])

        assert_equal(txid_3,            unspent_tx[1]['txid'])
        assert_equal('sapling',         unspent_tx[1]['pool'])
        assert_equal(True,              unspent_tx[1]['spendable'])
        assert_true('account'    not in unspent_tx[1])
        assert_equal(saplingzaddr2,     unspent_tx[1]['address'])
        assert_equal(receive_amount_3,  unspent_tx[1]['amount'])
        assert_equal(False,             unspent_tx[1]['change'])

        assert_equal(txid_4,            unspent_tx[2]['txid'])
        assert_equal('orchard',         unspent_tx[2]['pool'])
        assert_equal(True,              unspent_tx[2]['spendable'])
        assert_equal(account0,          unspent_tx[2]['account'])
        assert_equal(ua0,               unspent_tx[2]['address'])
        assert_equal(receive_amount_4,  unspent_tx[2]['amount'])
        assert_equal(False,             unspent_tx[2]['change'])

        assert_equal(txid_3,            unspent_tx[3]['txid'])
        assert_equal('sprout',          unspent_tx[3]['pool'])
        assert_equal(True,              unspent_tx[3]['spendable'])
        assert_true('account'    not in unspent_tx[3])
        assert_equal(sproutzaddr,       unspent_tx[3]['address'])
        assert_equal(change_amount_3,   unspent_tx[3]['amount'])
        assert_equal(True,              unspent_tx[3]['change'])

if __name__ == '__main__':
    WalletListNotes().main()
