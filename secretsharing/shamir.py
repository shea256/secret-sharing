# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import string
from characters import (charset_to_int, int_to_charset, is_int,
                        hex_to_int, int_to_hex, is_hex,
                        b58_to_int, int_to_b58, is_b58, B58_CHARS,
                        nato_to_int, int_to_nato, is_nato, NATO_CHARS)

from .utils import get_large_enough_prime, random_polynomial, \
    get_polynomial_points, modular_lagrange_interpolation

def assert_share_enc_valid(share_enc):
    assert share_enc in ('hex', 'b58', 'int', 'nato'), share_enc


def share_to_point(share, share_enc='hex'):
    '''
    share should be in the format:
      `01-d051080de...` for hex
      `1-2130008653...` for int
      `2-3AwSUjLj59...` for b58
      `2-3ciz388ixs...` for nato
    '''
    assert_share_enc_valid(share_enc)
    if isinstance(share, str) and share.count('-') == 1:
        x, y = share.split('-')
        if share_enc == 'hex':
            if is_hex(x) and is_hex(y):
                return (hex_to_int(x), hex_to_int(y))
        elif share_enc == 'b58':
            if is_b58(x) and is_b58(y):
                return (b58_to_int(x), b58_to_int(y))
        elif share_enc == 'int':
            if is_int(x) and is_int(y):
                return (int(x), int(y))
        elif share_enc == 'nato':
            if is_nato(x) and is_nato(y):
                return (nato_to_int(x), nato_to_int(y))
    raise ValueError('Share format is invalid.')


def point_to_share(point, share_enc='enc'):
    '''
    point should be in the format (1, 4938573982723...)
    '''
    assert_share_enc_valid(share_enc)
    if isinstance(point, tuple) and len(point) == 2:
        if isinstance(point[0], (int, long)) and isinstance(point[1],
                                                            (int, long)):
            x, y = point
            if x > 255:
                msg = 'The largest x coordinate for a share is 255.'
                raise ValueError(msg)

            if share_enc == 'hex':
                clean_x = int_to_hex(x).zfill(2)
                clean_y = int_to_hex(y)
            elif share_enc == 'b58':
                clean_x = int_to_b58(x)
                clean_y = int_to_b58(y)
            elif share_enc == 'int':
                clean_x = x
                clean_y = y
            elif share_enc == 'nato':
                clean_x = int_to_nato(x)
                clean_y = int_to_nato(y)
            else:
                raise ValueError('No matching share_enc found')

            return '%s-%s' % (clean_x, clean_y)

    raise ValueError('Point format is invalid. Must be a pair of integers.')


class Secret():
    def __init__(self, secret_int):
        if not isinstance(secret_int, (int, long)) and secret_int >= 0:
            raise ValueError("Secret must be a non-negative integer.")
        self._secret = secret_int

    @classmethod
    def from_charset(cls, secret, charset):
        if not isinstance(secret, str):
            raise ValueError("Secret must be a string.")
        if not isinstance(charset, str):
            raise ValueError("Charset must be a string.")
        if (set(secret) - set(charset)):
            msg = "Secret contains characters that aren't in the charset."
            raise ValueError(msg)
        secret_int = charset_to_int(secret, charset)
        return cls(secret_int)

    @classmethod
    def from_hex(cls, secret):
        return cls.from_charset(secret, string.hexdigits[0:16])

    @classmethod
    def from_b58(cls, secret):
        return cls.from_charset(secret, B58_CHARS)

    @classmethod
    def from_printable_ascii(cls, secret):
        return cls.from_charset(secret, string.printable)

    @classmethod
    def from_shares(cls, shares, share_enc='hex'):
        assert_share_enc_valid(share_enc)
        if not isinstance(shares, list):
            raise ValueError("Shares must be in list form.")
        for share in shares:
            if not isinstance(share, str):
                raise ValueError("Each share must be a string.")
        points = []
        for share in shares:
            points.append(share_to_point(share, share_enc=share_enc))
        x_values, y_values = zip(*points)
        prime = get_large_enough_prime(y_values)
        free_coefficient = modular_lagrange_interpolation(0, points, prime)
        secret_int = free_coefficient
        return cls(secret_int)

    def split(self, threshold, num_shares, share_enc='hex'):
        '''
        Split the secret into shares.
        The threshold is the total # of shares required to recover the secret.

        Currently, you can return shares in hex, int, or b58 formats.
        Feel free to add your own.
        '''
        assert_share_enc_valid(share_enc)
        if threshold < 2:
            raise ValueError("Threshold must be >= 2.")
        if threshold > num_shares:
            raise ValueError("Threshold must be < the total number of shares.")
        prime = get_large_enough_prime([self._secret, num_shares])
        if not prime:
            msg = "Error! Secret is too long for share calculation!"
            raise ValueError(msg)
        coefficients = random_polynomial(threshold-1, self._secret, prime)
        points = get_polynomial_points(coefficients, num_shares, prime)
        shares = []
        for point in points:
            shares.append(point_to_share(point, share_enc=share_enc))
        return shares

    def as_int(self):
        return self._secret

    def as_charset(self, charset):
        return int_to_charset(self._secret, charset)

    def as_hex(self):
        return self.as_charset(string.hexdigits[0:16])

    def as_b58(self):
        return self.as_charset(B58_CHARS)

    def as_nato(self):
        return self.as_charset(NATO_CHARS)

    def as_printable_ascii(self):
        return self.as_charset(string.printable)
