# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import random
import unittest
from test import test_support
from utilitybelt import base64_chars, is_hex
from secretsharing import secret_int_to_points, points_to_secret_int, \
    point_to_share_string, share_string_to_point, \
    HexToHexSecretSharer, PlaintextToHexSecretSharer, \
    BitcoinToB58SecretSharer, BitcoinToB32SecretSharer, \
    BitcoinToZB32SecretSharer
from secretsharing import SecretSharer


class ShamirSharingTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def check_shared_secret(self, sharer_class, format_check_function, m, n, secret):
        shares = sharer_class.split_secret(secret, m, n)
        random.shuffle(shares)
        if format_check_function:
            for share in shares:
                has_the_right_base = format_check_function(share.split('-')[1])
                self.assertTrue(has_the_right_base)
        return shares

    def check_recovered_secret(self, sharer_class, shares, m, original_secret):
        recovered_secret = sharer_class.recover_secret(shares[0:m])
        self.assertEqual(recovered_secret, original_secret)
        return recovered_secret

    def check_splitting_and_recovery(self, sharer_class, check_function, m, n, secret):
        shares = self.check_shared_secret(
            sharer_class, check_function, m, n, secret)
        recovered_secret = self.check_recovered_secret(
            sharer_class, shares, m, secret)
        return recovered_secret

    def test_hex_to_hex_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            SecretSharer, is_hex, 3, 5,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_hex_with_zero_to_hex_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            SecretSharer, is_hex, 3, 5,
            "04bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_printable_ascii_to_hex_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            PlaintextToHexSecretSharer, is_hex, 3, 5,
            "correct horse battery staple")

    def test_printable_with_zero_ascii_to_hex_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            PlaintextToHexSecretSharer, is_hex, 3, 5,
            "000correct horse battery staple")

    def test_b58_to_b32_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            BitcoinToB32SecretSharer, None, 3, 5,
            "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")

    def test_b58_to_zb32_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            BitcoinToZB32SecretSharer, None, 3, 5,
            "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")

    def test_b58_to_b58_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            BitcoinToB58SecretSharer, None, 3, 5,
            "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")

    def test_hex_to_base64_sharing(self):
        class HexToBase64SecretSharer(SecretSharer):
            share_charset = base64_chars
        sharer_class = HexToBase64SecretSharer
        recovered_secret = self.check_splitting_and_recovery(
            sharer_class, None, 3, 5,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_2_of_3_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            SecretSharer, is_hex, 2, 3,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_4_of_7_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            SecretSharer, is_hex, 4, 7,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_5_of_9_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            SecretSharer, is_hex, 5, 9,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

    def test_2_of_2_sharing(self):
        recovered_secret = self.check_splitting_and_recovery(
            SecretSharer, is_hex, 2, 2,
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")


def test_main():
    test_support.run_unittest(
        ShamirSharingTest
    )


if __name__ == '__main__':
    test_main()