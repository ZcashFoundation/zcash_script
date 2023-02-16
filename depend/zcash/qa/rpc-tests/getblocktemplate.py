#!/usr/bin/env python3
# Copyright (c) 2016 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

from io import BytesIO
import codecs
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    CANOPY_BRANCH_ID,
    DEFAULT_FEE,
    NU5_BRANCH_ID,
    get_coinbase_address,
    hex_str_to_bytes,
    nuparams,
    nustr,
    start_nodes,
    wait_and_assert_operationid_status,
)
from test_framework.mininode import (
    CTransaction,
)
from test_framework.blocktools import (
    create_block
)
from decimal import Decimal

class GetBlockTemplateTest(BitcoinTestFramework):
    '''
    Test getblocktemplate, ensure that a block created from its result
    can be submitted and accepted.
    '''

    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.cache_behavior = 'sprout'

    def setup_network(self, split=False):
        args = [
            nuparams(CANOPY_BRANCH_ID, 215),
            nuparams(NU5_BRANCH_ID, 230),
            "-allowdeprecated=getnewaddress",
            "-allowdeprecated=z_getbalance",
        ]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [args] * self.num_nodes)
        self.is_network_split = False
        self.node = self.nodes[0]

    def add_nu5_v4_tx_to_mempool(self):
        node = self.node
        # sprout to transparent (v4)
        recipients = [{"address": self.transparent_addr, "amount": Decimal('0.1')}]
        myopid = node.z_sendmany(self.sprout_addr, recipients, 1, DEFAULT_FEE, 'AllowRevealedRecipients')
        wait_and_assert_operationid_status(node, myopid)

    def add_nu5_v5_tx_to_mempool(self):
        node = self.node
        recipients = [{"address": self.unified_addr, "amount": Decimal('9.99999')}]
        myopid = node.z_sendmany(get_coinbase_address(node), recipients, 1, DEFAULT_FEE, 'AllowRevealedSenders')
        wait_and_assert_operationid_status(node, myopid)

    def add_transparent_tx_to_mempool(self):
        node = self.node
        # transparent to transparent (v5 after nu5)
        outputs = {self.transparent_addr: 0.1}
        node.sendmany('', outputs)

    def gbt_submitblock(self, nu5_active):
        node = self.node
        mempool_tx_list = node.getrawmempool()

        gbt = node.getblocktemplate()

        # make sure no transactions were left out (or added)
        assert_equal(len(mempool_tx_list), len(gbt['transactions']))
        assert_equal(set(mempool_tx_list), set([tx['hash'] for tx in gbt['transactions']]))

        prevhash = int(gbt['previousblockhash'], 16)
        nTime = gbt['mintime']
        nBits = int(gbt['bits'], 16)

        if nu5_active:
            blockcommitmentshash = int(gbt['defaultroots']['blockcommitmentshash'], 16)
        else:
            blockcommitmentshash = int(gbt['defaultroots']['chainhistoryroot'], 16)
            assert 'blockcommitmentshash' not in gbt['defaultroots']
        # Confirm that the legacy fields match this default value.
        assert_equal(blockcommitmentshash, int(gbt['blockcommitmentshash'], 16))
        assert_equal(blockcommitmentshash, int(gbt['lightclientroothash'], 16))
        assert_equal(blockcommitmentshash, int(gbt['finalsaplingroothash'], 16))

        f = BytesIO(hex_str_to_bytes(gbt['coinbasetxn']['data']))
        coinbase = CTransaction()
        coinbase.deserialize(f)
        coinbase.calc_sha256()
        assert_equal(coinbase.hash, gbt['coinbasetxn']['hash'])
        assert_equal(coinbase.auth_digest_hex, gbt['coinbasetxn']['authdigest'])

        block = create_block(prevhash, coinbase, nTime, nBits, blockcommitmentshash)

        # copy the non-coinbase transactions from the block template to the block
        for gbt_tx in gbt['transactions']:
            f = BytesIO(hex_str_to_bytes(gbt_tx['data']))
            tx = CTransaction()
            tx.deserialize(f)
            tx.calc_sha256()
            assert_equal(tx.hash, gbt_tx['hash'])
            assert_equal(tx.auth_digest_hex, node.getrawtransaction(tx.hash, 1)['authdigest'])
            block.vtx.append(tx)
        block.hashMerkleRoot = int(gbt['defaultroots']['merkleroot'], 16)
        assert_equal(block.hashMerkleRoot, block.calc_merkle_root(), "merkleroot")
        assert_equal(len(block.vtx), len(gbt['transactions']) + 1, "number of transactions")
        assert_equal(block.hashPrevBlock, int(gbt['previousblockhash'], 16), "prevhash")
        if nu5_active:
            block.hashAuthDataRoot = int(gbt['defaultroots']['authdataroot'], 16)
            assert_equal(block.hashAuthDataRoot, block.calc_auth_data_root(), "authdataroot")
        else:
            assert 'authdataroot' not in gbt['defaultroots']
        block.solve()
        block.calc_sha256()

        submitblock_reply = node.submitblock(codecs.encode(block.serialize(), 'hex_codec'))
        assert_equal(None, submitblock_reply)
        assert_equal(block.hash, node.getbestblockhash())
        # Wait until the wallet has been notified of all blocks, so that it doesn't try to
        # double-spend transparent coins in subsequent test phases.
        self.sync_all()

    def run_test(self):
        node = self.node

        self.sprout_addr = node.listaddresses()[0]['sprout']['addresses'][0]

        self.transparent_addr = node.getnewaddress()
        account = node.z_getnewaccount()['account']
        self.unified_addr = node.z_getaddressforaccount(account)['address']
        node.generate(20)

        # at height 220, NU5 is not active
        assert_equal(node.getblockchaininfo()['upgrades'][nustr(NU5_BRANCH_ID)]['status'], 'pending')

        print("Testing getblocktemplate for pre-NU5")

        # Only the coinbase; this covers the case where the Merkle root
        # is equal to the coinbase txid.
        print("- only coinbase")
        self.gbt_submitblock(False)

        # Adding one transaction triggering a single Merkle digest.
        print("- one transaction (plus coinbase)")
        self.add_transparent_tx_to_mempool()
        self.gbt_submitblock(False)

        # Adding two transactions to trigger hash Merkle root edge case.
        print("- two transactions (plus coinbase)")
        self.add_transparent_tx_to_mempool()
        self.add_transparent_tx_to_mempool()
        self.gbt_submitblock(False)

        # Activate NU5, repeat the above cases
        node.generate(7)
        assert_equal(node.getblockchaininfo()['upgrades'][nustr(NU5_BRANCH_ID)]['status'], 'active')

        print("Testing getblocktemplate for post-NU5")

        # Only the coinbase; this covers the case where the block authdata root
        # is equal to the coinbase authdata
        print("- only coinbase")
        self.gbt_submitblock(True)

        # Adding one transaction triggering a single Merkle digest.
        print("- one transaction (plus coinbase)")
        self.add_transparent_tx_to_mempool()
        self.gbt_submitblock(True)

        # Adding two transactions to trigger hash Merkle root edge case.
        print("- two transactions (plus coinbase)")
        self.add_transparent_tx_to_mempool()
        self.add_transparent_tx_to_mempool()
        self.gbt_submitblock(True)

        # Adding both v4 and v5 to cover legacy auth digest (without full auth digest subtree).
        print("- both v4 and v5 transactions (plus coinbase)")
        self.add_nu5_v4_tx_to_mempool()
        self.add_transparent_tx_to_mempool()
        self.gbt_submitblock(True)

        # Adding both v4 and v5 to cover legacy auth digest (with full auth digest subtree).
        print("- both v4 and v5 transactions (plus coinbase)")
        self.add_nu5_v4_tx_to_mempool()
        self.add_transparent_tx_to_mempool()
        self.add_transparent_tx_to_mempool()
        self.gbt_submitblock(True)

        print("- block with 6 Orchard transactions (plus coinbase)")
        for i in range(0, 6):
            print(str(node.z_getbalance(self.transparent_addr)))
            self.add_nu5_v5_tx_to_mempool()
        self.gbt_submitblock(True)

        print("- block with 7 Orchard transactions (plus coinbase)")
        for i in range(0, 7):
            self.add_nu5_v5_tx_to_mempool()
        self.gbt_submitblock(True)

if __name__ == '__main__':
    GetBlockTemplateTest().main()
