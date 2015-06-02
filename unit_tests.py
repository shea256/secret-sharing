# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import unittest
from test import test_support
import random

from secretsharing import *


class ShamirSharingTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def split_and_recover_secret(self, sharer_class, m, n, secret):
        shares = sharer_class.split_secret(secret, m, n)
        random.shuffle(shares)
        recovered_secret = sharer_class.recover_secret(shares[0:m])
        assert(recovered_secret == secret)

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


def test_main():

    test_support.run_unittest(
        ShamirSharingTest,
    )

if __name__ == '__main__':
    test_main()
