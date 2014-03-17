# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import unittest
from test import test_support

from secretsharing.shamir import Secret

class ShamirSharingTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def secret_message_to_shares(secret_message):
        # FIXME?
        return shares

    def test_short_secret(self):
        secret_message = 'Hello, world!'
        secret = Secret.from_printable_ascii(secret_message)
        shares = secret.split(3, 5)
        assert(Secret.from_shares(shares[0:3]).as_printable_ascii() == secret_message)

    def test_long_secret(self):
        secret_message = '1054dcaf130fd0c0a51cb0aa762df16faa5f9ee444f3a82f45f62c579635d1b7cba1b5f76587ecba66b'
        secret = Secret.from_hex(secret_message)
        shares = secret.split(3, 5)
        assert(Secret.from_shares(shares[0:3]).as_hex() == secret_message)

    def test_b58_secret(self):
        secret_message = '9rG6GosV4AgRcJD'
        secret = Secret.from_b58(secret_message)
        shares = secret.split(3, 5, share_enc='b58')
        assert(secret.as_printable_ascii() == 'Hello, world!')
        assert(Secret.from_shares(shares[0:3], share_enc='b58').as_b58() == secret_message)

def test_main():

    test_support.run_unittest(
        ShamirSharingTest,
    )

if __name__ == '__main__':
    test_main()


