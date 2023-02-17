#!/usr/bin/env python3
# Copyright (c) 2018 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises_message,
    connect_nodes_bi,
    nuparams,
    DEFAULT_FEE,
    DEFAULT_FEE_ZATS,
    NU5_BRANCH_ID,
)
from test_framework.util import wait_and_assert_operationid_status, start_nodes
from decimal import Decimal

my_memo_str = 'c0ffee' # stay awake
my_memo = '633066666565'
my_memo = my_memo + '0'*(1024-len(my_memo))

no_memo = 'f6' + ('0'*1022) # see section 5.5 of the protocol spec

class ListReceivedTest (BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.cache_behavior = 'clean'

    def setup_network(self):
        self.nodes = start_nodes(
            self.num_nodes, self.options.tmpdir,
            extra_args=[[
                nuparams(NU5_BRANCH_ID, 225),
                '-allowdeprecated=getnewaddress',
                '-allowdeprecated=z_getnewaddress',
            ]] * self.num_nodes
            )
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 0, 2)
        self.is_network_split = False
        self.sync_all()

    def generate_and_sync(self, new_height):
        current_height = self.nodes[0].getblockcount()
        assert(new_height > current_height)
        self.sync_all()
        self.nodes[0].generate(new_height - current_height)
        self.sync_all()
        assert_equal(new_height, self.nodes[0].getblockcount())

    def test_received_sapling(self, height):
        self.generate_and_sync(height+1)
        taddr = self.nodes[1].getnewaddress()
        zaddr1 = self.nodes[1].z_getnewaddress('sapling')
        zaddrExt = self.nodes[2].z_getnewaddress('sapling')

        txid_taddr = self.nodes[0].sendtoaddress(taddr, 4.0)
        self.generate_and_sync(height+2)

        # Send 1 ZEC to zaddr1
        opid = self.nodes[1].z_sendmany(taddr, [
            {'address': zaddr1, 'amount': 1, 'memo': my_memo},
            {'address': zaddrExt, 'amount': 2},
        ], 1, DEFAULT_FEE, 'AllowRevealedSenders')
        txid = wait_and_assert_operationid_status(self.nodes[1], opid)
        self.sync_all()

        # Decrypted transaction details should be correct
        pt = self.nodes[1].z_viewtransaction(txid)

        assert_equal(pt['txid'], txid)
        assert_equal(len(pt['spends']), 0)
        assert_equal(len(pt['outputs']), 2)

        # Outputs are not returned in a defined order but the amounts are deterministic
        outputs = sorted(pt['outputs'], key=lambda x: x['valueZat'])
        assert_equal(outputs[0]['pool'], 'sapling')
        assert_equal(outputs[0]['address'], zaddr1)
        assert_equal(outputs[0]['value'], Decimal('1'))
        assert_equal(outputs[0]['valueZat'], 100000000)
        assert_equal(outputs[0]['output'], 0)
        assert_equal(outputs[0]['outgoing'], False)
        assert_equal(outputs[0]['memo'], my_memo)
        assert_equal(outputs[0]['memoStr'], my_memo_str)

        assert_equal(outputs[1]['pool'], 'sapling')
        assert_equal(outputs[1]['address'], zaddrExt)
        assert_equal(outputs[1]['value'], Decimal('2'))
        assert_equal(outputs[1]['valueZat'], 200000000)
        assert_equal(outputs[1]['output'], 1)
        assert_equal(outputs[1]['outgoing'], True)
        assert_equal(outputs[1]['memo'], no_memo)
        assert 'memoStr' not in outputs[1]

        r = self.nodes[1].z_listreceivedbyaddress(zaddr1)
        assert_equal(0, len(r), "Should have received no confirmed note")
        c = self.nodes[1].z_getnotescount()
        assert_equal(0, c['sapling'], "Count of confirmed notes should be 0")

        # No confirmation required, one note should be present
        r = self.nodes[1].z_listreceivedbyaddress(zaddr1, 0)
        assert_equal(1, len(r), "Should have received one (unconfirmed) note")
        assert_equal(txid, r[0]['txid'])
        assert_equal(1, r[0]['amount'])
        assert_equal(100000000, r[0]['amountZat'])
        assert_false(r[0]['change'], "Note should not be change")
        assert_equal(my_memo, r[0]['memo'])
        assert_equal(0, r[0]['confirmations'])
        assert_equal(-1, r[0]['blockindex'])
        assert_equal(0, r[0]['blockheight'])

        c = self.nodes[1].z_getnotescount(0)
        assert_equal(1, c['sapling'], "Count of unconfirmed notes should be 1")

        # Confirm transaction (1 ZEC from taddr to zaddr1)
        self.generate_and_sync(height+3)

        # adjust confirmations
        r[0]['confirmations'] = 1
        # adjust blockindex
        r[0]['blockindex'] = 1
        # adjust height
        r[0]['blockheight'] = height + 3

        # Require one confirmation, note should be present
        assert_equal(r, self.nodes[1].z_listreceivedbyaddress(zaddr1))

        # Generate some change by sending part of zaddr1 to zaddr2
        txidPrev = txid
        zaddr2 = self.nodes[1].z_getnewaddress('sapling')
        opid = self.nodes[1].z_sendmany(zaddr1, [{'address': zaddr2, 'amount': 0.6}], 1)
        txid = wait_and_assert_operationid_status(self.nodes[1], opid)
        self.sync_all()
        self.generate_and_sync(height+4)

        # Decrypted transaction details should be correct
        pt = self.nodes[1].z_viewtransaction(txid)
        assert_equal(pt['txid'], txid)
        assert_equal(len(pt['spends']), 1)
        assert_equal(len(pt['outputs']), 2)

        assert_equal(pt['spends'][0]['pool'], 'sapling')
        assert_equal(pt['spends'][0]['txidPrev'], txidPrev)
        assert_equal(pt['spends'][0]['spend'], 0)
        assert_equal(pt['spends'][0]['outputPrev'], 0)
        assert_equal(pt['spends'][0]['address'], zaddr1)
        assert_equal(pt['spends'][0]['value'], Decimal('1.0'))
        assert_equal(pt['spends'][0]['valueZat'], 100000000)

        # Outputs are not returned in a defined order but the amounts are deterministic
        outputs = sorted(pt['outputs'], key=lambda x: x['valueZat'])
        assert_equal(outputs[0]['pool'], 'sapling')
        assert_equal(outputs[0]['address'], zaddr1)
        assert_equal(outputs[0]['value'], Decimal('0.4') - DEFAULT_FEE)
        assert_equal(outputs[0]['valueZat'], 40000000 - DEFAULT_FEE_ZATS)
        assert_equal(outputs[0]['output'], 1)
        assert_equal(outputs[0]['outgoing'], False)
        assert_equal(outputs[0]['memo'], no_memo)
        assert 'memoStr' not in outputs[0]

        assert_equal(outputs[1]['pool'], 'sapling')
        assert_equal(outputs[1]['address'], zaddr2)
        assert_equal(outputs[1]['value'], Decimal('0.6'))
        assert_equal(outputs[1]['valueZat'], 60000000)
        assert_equal(outputs[1]['output'], 0)
        assert_equal(outputs[1]['outgoing'], False)
        assert_equal(outputs[1]['memo'], no_memo)
        assert 'memoStr' not in outputs[1]

        # zaddr1 should have a note with change
        r = self.nodes[1].z_listreceivedbyaddress(zaddr1, 0)
        assert_equal(2, len(r), "zaddr1 Should have received 2 notes")
        r = sorted(r, key = lambda received: received['amount'])
        assert_equal(txid, r[0]['txid'])
        assert_equal(Decimal('0.4')-DEFAULT_FEE, r[0]['amount'])
        assert_equal(40000000-DEFAULT_FEE_ZATS, r[0]['amountZat'])
        assert_equal(r[0]['change'], True, "Note valued at (0.4-"+str(DEFAULT_FEE)+") should be change")
        assert_equal(no_memo, r[0]['memo'])

        # The old note still exists (it's immutable), even though it is spent
        assert_equal(Decimal('1.0'), r[1]['amount'])
        assert_equal(100000000, r[1]['amountZat'])
        assert_equal(r[1]['change'], False, "Note valued at 1.0 should not be change")
        assert_equal(my_memo, r[1]['memo'])

        # zaddr2 should not have change
        r = self.nodes[1].z_listreceivedbyaddress(zaddr2, 0)
        assert_equal(len(r), 1, "zaddr2 Should have received 1 notes")
        r = sorted(r, key = lambda received: received['amount'])
        assert_equal(r[0]['txid'], txid)
        assert_equal(r[0]['amount'], Decimal('0.6'))
        assert_equal(r[0]['amountZat'], 60000000)
        assert_equal(r[0]['change'], False, "Note valued at 0.6 should not be change")
        assert_equal(r[0]['memo'], no_memo)
        assert 0 <= r[0]['outindex'] < 2

        c = self.nodes[1].z_getnotescount(0)
        assert_equal(c['sapling'], 3, "Count of unconfirmed notes should be 3(2 in zaddr1 + 1 in zaddr2)")

        # As part of UA support, a transparent address is now accepted
        r = self.nodes[1].z_listreceivedbyaddress(taddr, 0)
        assert_equal(len(r), 1)
        assert_equal(r[0]['pool'], 'transparent')
        assert_equal(r[0]['txid'], txid_taddr)
        assert_equal(r[0]['amount'], Decimal('4'))
        assert_equal(r[0]['amountZat'], 400000000)
        assert_equal(r[0]['confirmations'], 3)
        assert 0 <= r[0]['outindex'] < 2

        # Test unified address
        node = self.nodes[1]

        # Create a unified address on one node, try z_listreceivedbyaddress on another node
        account = self.nodes[0].z_getnewaccount()['account']
        r = self.nodes[0].z_getaddressforaccount(account)
        unified_addr = r['address']
        # this address isn't in node1's wallet
        assert_raises_message(
            JSONRPCException,
            "From address does not belong to this node",
            node.z_listreceivedbyaddress, unified_addr, 0)

        # create a UA on node1
        r = node.z_getnewaccount()
        account = r['account']
        r = node.z_getaddressforaccount(account)
        unified_addr = r['address']
        receivers = node.z_listunifiedreceivers(unified_addr)
        assert_equal(len(receivers), 3)
        assert 'p2pkh' in receivers
        assert 'sapling' in receivers
        assert 'orchard' in receivers
        assert_raises_message(
            JSONRPCException,
            "The provided address is a bare receiver from a Unified Address in this wallet.",
            node.z_listreceivedbyaddress, receivers['p2pkh'], 0)
        assert_raises_message(
            JSONRPCException,
            "The provided address is a bare receiver from a Unified Address in this wallet.",
            node.z_listreceivedbyaddress, receivers['sapling'], 0)

        # Wallet contains no notes
        r = node.z_listreceivedbyaddress(unified_addr, 0)
        assert_equal(len(r), 0, "unified_addr should have received zero notes")

        # Create a note in this UA on node1
        opid = node.z_sendmany(zaddr1, [{'address': unified_addr, 'amount': 0.1}], 1)
        txid_sapling = wait_and_assert_operationid_status(node, opid)
        self.generate_and_sync(height+5)

        # Create a UTXO that unified_address's transparent component references, on node1
        outputs = {receivers['p2pkh']: 0.2}
        txid_taddr = node.sendmany("", outputs)

        r = node.z_listreceivedbyaddress(unified_addr, 0)
        assert_equal(len(r), 2, "unified_addr should have received 2 payments")
        # The return list order isn't defined, so sort by pool name
        r = sorted(r, key=lambda x: x['pool'])
        assert_equal(r[0]['pool'], 'sapling')
        assert_equal(r[0]['txid'], txid_sapling)
        assert_equal(r[0]['amount'], Decimal('0.1'))
        assert_equal(r[0]['amountZat'], 10000000)
        assert_equal(r[0]['memo'], no_memo)
        assert 0 <= r[0]['outindex'] < 2
        assert_equal(r[0]['confirmations'], 1)
        assert_equal(r[0]['change'], False)
        assert_equal(r[0]['blockheight'], height+5)
        assert_equal(r[0]['blockindex'], 1)
        assert 'blocktime' in r[0]

        assert_equal(r[1]['pool'], 'transparent')
        assert_equal(r[1]['txid'], txid_taddr)
        assert_equal(r[1]['amount'], Decimal('0.2'))
        assert_equal(r[1]['amountZat'], 20000000)
        assert 0 <= r[1]['outindex'] < 2
        assert_equal(r[1]['confirmations'], 0)
        assert_equal(r[1]['change'], False)
        assert 'memo' not in r[1]
        assert_equal(r[1]['blockheight'], 0) # not yet mined
        assert_equal(r[1]['blockindex'], -1) # not yet mined
        assert 'blocktime' in r[1]

    def test_received_orchard(self, height):
        self.generate_and_sync(height+1)
        taddr = self.nodes[1].getnewaddress()
        acct1 = self.nodes[1].z_getnewaccount()['account']
        acct2 = self.nodes[1].z_getnewaccount()['account']

        addrResO = self.nodes[1].z_getaddressforaccount(acct1, ['orchard'])
        assert_equal(addrResO['receiver_types'], ['orchard'])
        uao = addrResO['address']

        addrResSO = self.nodes[1].z_getaddressforaccount(acct2, ['sapling', 'orchard'])
        assert_equal(addrResSO['receiver_types'], ['sapling', 'orchard'])
        uaso = addrResSO['address']

        self.nodes[0].sendtoaddress(taddr, 4.0)
        self.generate_and_sync(height+2)

        acct_node0 = self.nodes[0].z_getnewaccount()['account']
        ua_node0 = self.nodes[0].z_getaddressforaccount(acct_node0, ['sapling', 'orchard'])['address']

        opid = self.nodes[1].z_sendmany(taddr, [
            {'address': uao, 'amount': 1, 'memo': my_memo},
            {'address': uaso, 'amount': 2},
        ], 1, 0, 'AllowRevealedSenders')
        txid0 = wait_and_assert_operationid_status(self.nodes[1], opid)
        self.sync_all()

        # Decrypted transaction details should be correct, even though
        # the transaction is still just in the mempool
        pt = self.nodes[1].z_viewtransaction(txid0)

        assert_equal(pt['txid'], txid0)
        assert_equal(len(pt['spends']), 0)
        assert_equal(len(pt['outputs']), 2)

        # Outputs are not returned in a defined order but the amounts are deterministic
        outputs = sorted(pt['outputs'], key=lambda x: x['valueZat'])
        assert_equal(outputs[0]['pool'], 'orchard')
        assert_equal(outputs[0]['address'], uao)
        assert_equal(outputs[0]['value'], Decimal('1'))
        assert_equal(outputs[0]['valueZat'], 100000000)
        assert_equal(outputs[0]['outgoing'], False)
        assert_equal(outputs[0]['memo'], my_memo)
        assert_equal(outputs[0]['memoStr'], my_memo_str)
        actionToSpend = outputs[0]['action']

        assert_equal(outputs[1]['pool'], 'orchard')
        assert_equal(outputs[1]['address'], uaso)
        assert_equal(outputs[1]['value'], Decimal('2'))
        assert_equal(outputs[1]['valueZat'], 200000000)
        assert_equal(outputs[1]['outgoing'], False)
        assert_equal(outputs[1]['memo'], no_memo)
        assert 'memoStr' not in outputs[1]

        self.generate_and_sync(height+3)

        opid = self.nodes[1].z_sendmany(uao, [
            {'address': uaso, 'amount': Decimal('0.3')},
            {'address': ua_node0, 'amount': Decimal('0.2')}
        ], 1)
        txid1 = wait_and_assert_operationid_status(self.nodes[1], opid)
        self.sync_all()

        pt = self.nodes[1].z_viewtransaction(txid1)

        assert_equal(pt['txid'], txid1)
        assert_equal(len(pt['spends']), 1) # one spend we can see
        assert_equal(len(pt['outputs']), 3) # one output + one change output we can see

        spends = pt['spends']
        assert_equal(spends[0]['pool'], 'orchard')
        assert_equal(spends[0]['txidPrev'], txid0)
        assert_equal(spends[0]['actionPrev'], actionToSpend)
        assert_equal(spends[0]['address'], uao)
        assert_equal(spends[0]['value'], Decimal('1.0'))
        assert_equal(spends[0]['valueZat'], 100000000)

        outputs = sorted(pt['outputs'], key=lambda x: x['valueZat'])
        assert_equal(outputs[0]['pool'], 'orchard')
        assert_equal(outputs[0]['address'], ua_node0)
        assert_equal(outputs[0]['value'], Decimal('0.2'))
        assert_equal(outputs[0]['valueZat'], 20000000)
        assert_equal(outputs[0]['outgoing'], True)
        assert_equal(outputs[0]['walletInternal'], False)
        assert_equal(outputs[0]['memo'], no_memo)

        assert_equal(outputs[1]['pool'], 'orchard')
        assert_equal(outputs[1]['address'], uaso)
        assert_equal(outputs[1]['value'], Decimal('0.3'))
        assert_equal(outputs[1]['valueZat'], 30000000)
        assert_equal(outputs[1]['outgoing'], False)
        assert_equal(outputs[1]['walletInternal'], False)
        assert_equal(outputs[1]['memo'], no_memo)

        # Verify that we observe the change output
        assert_equal(outputs[2]['pool'], 'orchard')
        assert_equal(outputs[2]['value'], Decimal('0.49999'))
        assert_equal(outputs[2]['valueZat'], 49999000)
        assert_equal(outputs[2]['outgoing'], False)
        assert_equal(outputs[2]['walletInternal'], True)
        assert_equal(outputs[2]['memo'], no_memo)
        # The change address should have been erased
        assert_true('address' not in outputs[2])

    def run_test(self):
        self.test_received_sapling(214)
        self.test_received_orchard(230)


if __name__ == '__main__':
    ListReceivedTest().main()
