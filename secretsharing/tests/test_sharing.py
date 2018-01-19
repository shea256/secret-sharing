# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import random
import pytest

from ..charset import base64_chars
from .. import (secret_int_to_points, points_to_secret_int,
    point_to_share_string, share_string_to_point, SecretSharer,
    HexToHexSecretSharer, PlaintextToHexSecretSharer,
    BitcoinToB58SecretSharer, BitcoinToB32SecretSharer,
    BitcoinToZB32SecretSharer)


@pytest.fixture(params=[BitcoinToB32SecretSharer, BitcoinToB58SecretSharer,
                        BitcoinToZB32SecretSharer])
def btc_sharer_class(request):
    return request.param

splits = [(2, 2), (2, 3), (4, 7), (5, 9)]

def split_and_recover_secret(sharer_class, m, n, secret):
    shares = sharer_class.split_secret(secret, m, n)
    random.shuffle(shares)
    for i in range(n - m):
        recovered_secret = sharer_class.recover_secret(shares[i:m+i])
        assert(recovered_secret == secret)
        recovered_secret = sharer_class.recover_secret(shares[i:m+i+1])
        assert(recovered_secret == secret)
        unrecovered_secret = sharer_class.recover_secret(shares[i:m+i-1])
        assert(unrecovered_secret != secret)


@pytest.mark.parametrize(['m', 'n'], splits)
def test_hex_to_hex_sharing(m, n):
    split_and_recover_secret(SecretSharer, m, n,
        "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")

@pytest.mark.parametrize(['m', 'n'], splits)
def test_printable_ascii_to_hex_sharing(m, n):
    split_and_recover_secret(PlaintextToHexSecretSharer, m, n,
        "0000correct horse battery staple")

@pytest.mark.parametrize(['m', 'n'], splits)
def test_btc_sharing(btc_sharer_class, m, n):
    split_and_recover_secret(btc_sharer_class, m, n,
        "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS")

@pytest.mark.parametrize(['m', 'n'], splits)
def test_hex_to_base64_sharing(m, n):
    sharer_class = SecretSharer
    sharer_class.share_charset = base64_chars
    split_and_recover_secret(sharer_class, m, n,
        "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")
