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

	def split_and_recover_secret(self, secret, sharer, m, n):
		shares = sharer.split_secret(secret, m, n)
		random.shuffle(shares)
		recovered_secret = sharer.recover_secret(shares[0:m])
		return recovered_secret
		
	def test_hex_to_hex_sharing(self):
		secret = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
		sharer = SecretSharer()
		recovered_secret = self.split_and_recover_secret(secret, sharer, 3, 5)
		assert(recovered_secret == secret)

	def test_ascii_to_hex_sharing(self):
		secret = "correct horse battery staple"
		sharer = WordsToHexSecretSharer()
		recovered_secret = self.split_and_recover_secret(secret, sharer, 3, 5)
		assert(recovered_secret == secret)

	def test_b58_to_zb32_sharing(self):
		secret = "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS"
		sharer = BitcoinSecretSharer()
		recovered_secret = self.split_and_recover_secret(secret, sharer, 3, 5)
		assert(recovered_secret == secret)

	def test_2_of_3_sharing(self):
		secret = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
		sharer = SecretSharer()
		recovered_secret = self.split_and_recover_secret(secret, sharer, 2, 3)
		assert(recovered_secret == secret)

	def test_4_of_7_sharing(self):
		secret = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
		sharer = SecretSharer()
		recovered_secret = self.split_and_recover_secret(secret, sharer, 4, 7)
		assert(recovered_secret == secret)

	def test_5_of_9_sharing(self):
		secret = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
		sharer = SecretSharer()
		recovered_secret = self.split_and_recover_secret(secret, sharer, 5, 9)
		assert(recovered_secret == secret)

	def test_2_of_2_sharing(self):
		secret = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
		sharer = SecretSharer()
		recovered_secret = self.split_and_recover_secret(secret, sharer, 2, 2)
		assert(recovered_secret == secret)

def test_main():

	test_support.run_unittest(
		ShamirSharingTest,
	)

if __name__ == '__main__':
    test_main()


