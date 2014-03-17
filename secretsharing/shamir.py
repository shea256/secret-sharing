# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import string
from characters.charset import charset_to_int, int_to_charset
from characters.hex import hex_to_int, int_to_hex, is_hex
from characters.b58 import b58_to_int, int_to_b58, is_b58, B58_CHARS

from .utils import get_large_enough_prime, random_polynomial, \
    get_polynomial_points, modular_lagrange_interpolation

def share_to_point(share, share_enc='hex'):
    '''
    share should be in the format:
      `01-d051080de7...` for hex
      `2-FIXMEFIXME...` for b58
    '''
    assert share_enc in ('hex', 'b58'), share_enc
    if isinstance(share, str) and share.count('-') == 1:
        x,y = share.split('-')
        if share_enc == 'hex':
            if is_hex(x) and is_hex(y):
                return (hex_to_int(x), hex_to_int(y))
        elif share_enc == 'b58':
            if is_b58(x) and is_b58(y):
                return (b58_to_int(x), b58_to_int(y))
    raise ValueError('Share format is invalid.')

def point_to_share(point, share_enc='enc'):
    '''
    point should be in the format (1, 4938573982723...)
    '''
    assert share_enc in ('hex', 'b58'), share_enc
    if isinstance(point, tuple) and len(point) == 2:
        if isinstance(point[0], (int, long)) and isinstance(point[1], (int, long)):
            x,y = point
            if x > 255:
                raise ValueError('The largest x coordinate for a share is 255.')
            if share_enc == 'hex':
                hex_x, hex_y = int_to_hex(x).zfill(2), int_to_hex(y)
                return hex_x + '-' + hex_y
            elif share_enc == 'b58':
                # TODO: add zfill to support greater #s of shares than 58
                b58_x, b58_y = int_to_b58(x), int_to_b58(y)
                return b58_x + '-' + b58_y
        else:
            print "ah!"
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
            raise ValueError("Secret contains characters that aren't in the charset.")
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
        assert share_enc in ('hex', 'b58'), share_enc
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

        The threshold is the total number of shares required to recover the secret.
        '''
        assert share_enc in ('hex', 'b58'), share_enc
        if threshold < 2:
            raise ValueError("Threshold must be >= 2.")
        if threshold > num_shares:
            raise ValueError("Threshold must be < the total number of shares.")
        if share_enc == 'hex':
            assert threshold <= len(B58_CHARS), threshold
        prime = get_large_enough_prime([self._secret, num_shares])
        if not prime:
            raise ValueError("Error! Secret is too long for share calculation!")
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

    def as_printable_ascii(self):
        return self.as_charset(string.printable)

