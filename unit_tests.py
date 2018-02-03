# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import random
import unittest
from test import support
from utilitybelt import base64_chars
from secretsharing import secret_int_to_points, points_to_secret_int, \
    point_to_share_string, share_string_to_point, SecretSharer, \
    HexToHexSecretSharer, PlaintextToHexSecretSharer, \
    BitcoinToB58SecretSharer, BitcoinToB32SecretSharer, \
    BitcoinToZB32SecretSharer
from secretsharing.sharing import SecretSharerNew


class ShamirSharingTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    @staticmethod
    def split_and_recover_secret(sharer_class, m, n, secret):
        shares = sharer_class.split_secret(secret, m, n)
        random.shuffle(shares)
        recovered_secret = sharer_class.recover_secret(shares[0:m])
        assert (recovered_secret == secret)

    def test_hex_to_hex_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            SecretSharer, 3, 5,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_printable_ascii_to_hex_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            PlaintextToHexSecretSharer, 3, 5,
            "correct horse battery staple")

    def test_b58_to_b32_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            BitcoinToB32SecretSharer, 3, 5,
            "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")

    def test_b58_to_zb32_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            BitcoinToZB32SecretSharer, 3, 5,
            "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")

    def test_b58_to_b58_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            BitcoinToB58SecretSharer, 3, 5,
            "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")

    def test_hex_to_base64_sharing(self):
        sharer_class = SecretSharer
        sharer_class.share_charset = base64_chars
        recovered_secret = self.split_and_recover_secret(
            sharer_class, 3, 5,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_2_of_3_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            SecretSharer, 2, 3,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_4_of_7_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            SecretSharer, 4, 7,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_5_of_9_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            SecretSharer, 5, 9,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_2_of_2_sharing(self):
        recovered_secret = self.split_and_recover_secret(
            SecretSharer, 2, 2,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")


class ShamirSharingNewTest(unittest.TestCase):
    def test_4_of_7_sharing(self):
        # A simple test works
        ShamirSharingTest.split_and_recover_secret(
            SecretSharerNew, 4, 7,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_5_of_30_sharing(self):
        # Generate new shares for the same secret
        secret = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
        sharer = SecretSharerNew()

        # Shares can recover secret
        shares_10 = sharer.generate_shares(secret, 5, 10)
        assert SecretSharerNew.recover_secret(shares_10) == secret
        shares_15 = sharer.generate_shares(secret, 5, 15)
        assert SecretSharerNew.recover_secret(shares_15) == secret
        shares_25 = sharer.generate_shares(secret, 5, 25)
        assert SecretSharerNew.recover_secret(shares_25) == secret
        shares_30 = sharer.generate_shares(secret, 5, 30)
        assert SecretSharerNew.recover_secret(shares_30) == secret
        shares_50 = sharer.generate_shares(secret, 5, 50)
        assert SecretSharerNew.recover_secret(shares_50) == secret

        # Mix shares from different `generate_shares` calls
        # Ranges for all except `shares_10` are used so that shares don't repeat
        assert SecretSharerNew.recover_secret(random.sample(shares_10, 2) +
                                              random.sample(shares_15[10:15], 3)) == secret
        assert SecretSharerNew.recover_secret(random.sample(shares_15, 1) +
                                              random.sample(shares_25[15:25],
                                                            4)) == secret

        assert SecretSharerNew.recover_secret([random.sample(i, 1)[0]
                                               for i in [shares_10,
                                                         shares_15[10:15],
                                                         shares_25[15:25],
                                                         shares_30[25:30],
                                                         shares_50[30:50]
                                                         ]]) == secret


def test_main():
    support.run_unittest(
        ShamirSharingTest,
        ShamirSharingNewTest
    )


if __name__ == '__main__':
    test_main()