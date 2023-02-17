#!/usr/bin/env python3
# Copyright (c) 2018 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_true, start_nodes

class WalletImportExportTest (BitcoinTestFramework):
    def setup_network(self, split=False):
        num_nodes = 3
        extra_args = [([
            "-exportdir={}/export{}".format(self.options.tmpdir, i), 
            '-allowdeprecated=getnewaddress',
            '-allowdeprecated=z_getnewaddress',
            ] + (["-walletrequirebackup"] if i == 0 else [])) for i in range(num_nodes)] 
        self.nodes = start_nodes(num_nodes, self.options.tmpdir, extra_args)

    def run_test(self):
        sapling_address2 = self.nodes[2].z_getnewaddress('sapling')
        privkey2 = self.nodes[2].z_exportkey(sapling_address2)
        self.nodes[0].z_importkey(privkey2)

        # test walletconfirmbackup
        try:
            self.nodes[0].getnewaddress()
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Error: Please acknowledge that you have backed up" in errorString, True)
        try:
            self.nodes[0].z_getnewaddress('sapling')
        except JSONRPCException as e:
            errorString = e.error['message']
        assert_equal("Error: Please acknowledge that you have backed up" in errorString, True)
        dump_path0 = self.nodes[0].z_exportwallet('walletdumpmnem')
        (mnemonic, _, _, _) = parse_wallet_file(dump_path0)
        self.nodes[0].walletconfirmbackup(mnemonic)

        # Now that we've confirmed backup, we can generate addresses
        sprout_address0 = self.nodes[0].z_getnewaddress('sprout')
        sapling_address0 = self.nodes[0].z_getnewaddress('sapling')

        # node 0 should have the keys
        dump_path0 = self.nodes[0].z_exportwallet('walletdump')
        (_, t_keys0, sprout_keys0, sapling_keys0) = parse_wallet_file(dump_path0)

        sapling_line_lengths = [len(sapling_key0.split(' #')[0].split()) for sapling_key0 in sapling_keys0.splitlines()]
        assert_equal(2, len(sapling_line_lengths), "Should have 2 sapling keys")
        assert_true(2 in sapling_line_lengths, "Should have a key with 2 parameters")
        assert_true(4 in sapling_line_lengths, "Should have a key with 4 parameters")

        assert_true(sprout_address0 in sprout_keys0)
        assert_true(sapling_address0 in sapling_keys0)
        assert_true(sapling_address2 in sapling_keys0)

        # node 1 should not have the keys
        dump_path1 = self.nodes[1].z_exportwallet('walletdumpbefore')
        (_, t_keys1, sprout_keys1, sapling_keys1) = parse_wallet_file(dump_path1)
        
        assert_true(sprout_address0 not in sprout_keys1)
        assert_true(sapling_address0 not in sapling_keys1)

        # import wallet to node 1
        self.nodes[1].z_importwallet(dump_path0)

        # node 1 should now have the keys
        dump_path1 = self.nodes[1].z_exportwallet('walletdumpafter')
        (_, t_keys1, sprout_keys1, sapling_keys1) = parse_wallet_file(dump_path1)
        
        assert_true(sprout_address0 in sprout_keys1)
        assert_true(sapling_address0 in sapling_keys1)
        assert_true(sapling_address2 in sapling_keys1)

        # make sure we have preserved the metadata
        for sapling_key0 in sapling_keys0.splitlines():
            assert_true(sapling_key0 in sapling_keys1)

# Helper functions
def parse_wallet_file(dump_path):
    file_lines = open(dump_path, "r", encoding="utf8").readlines()
    # We expect information about the HDSeed and fingerpring in the header
    assert_true("recovery_phrase" in file_lines[5], "Expected emergency recovery phrase")
    assert_true("language" in file_lines[6], "Expected mnemonic seed language")
    assert_true("fingerprint" in file_lines[7], "Expected mnemonic seed fingerprint")
    mnemonic = file_lines[5].split("=")[1].replace("\"", "").strip()
    (t_keys, i) = parse_wallet_file_lines(file_lines, 0)
    (sprout_keys, i) = parse_wallet_file_lines(file_lines, i)
    (sapling_keys, i) = parse_wallet_file_lines(file_lines, i)

    return (mnemonic, t_keys, sprout_keys, sapling_keys)

def parse_wallet_file_lines(file_lines, i):
    keys = []
    # skip blank lines and comments
    while i < len(file_lines) and (file_lines[i] == '\n' or file_lines[i].startswith("#")):
        i += 1
    # add keys until we hit another blank line or comment
    while  i < len(file_lines) and not (file_lines[i] == '\n' or file_lines[i].startswith("#")):
        keys.append(file_lines[i])
        i += 1
    return ("".join(keys), i)

if __name__ == '__main__':
    WalletImportExportTest().main()
