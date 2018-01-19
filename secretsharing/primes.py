# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""


def mersenne_primes(pmax=35):
    """ Returns mersenne primes up to the given exponent number:
        3, 7, 31, 127, 8191, 131071, 524287, 2147483647L, 2305843009213693951L,
        618970019642690137449562111L, 162259276829213363391578010288127L,
        170141183460469231731687303715884105727L,
        68647976601306097149...12574028291115057151L, (157 digits)
        53113799281676709868...70835393219031728127L, (183 digits)
        10407932194664399081...20710555703168729087L, (386 digits)
    """
    exponents = [
        2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279,  2203, 2281,
        3217, 4253, 4423, 9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243,
        110503, 132049, 216091, 756839, 859433, 1257787, 1398269, 2976221, 3021377,
        6972593, 13466917, 20996011, 24036583, 25964951, 30402457, 32582657, 37156667,
        42643801, 43112609, 57885161, 74207281
    ]
    return [2**exp - 1 for exp in exponents[:pmax]]

SP_257BIT = 2**256 + 297
SP_321BIT = 2**320 + 27
SP_385BIT = 2**384 + 231
STANDARD_PRIMES = sorted(mersenne_primes() + [SP_257BIT, SP_321BIT, SP_385BIT])


def get_large_enough_prime(batch, primes=STANDARD_PRIMES):
    """ Returns a prime number that is greater all the numbers in the batch.
    """
    # find a prime that is greater than all the numbers in the batch
    for prime in primes:
        numbers_greater_than_prime = sum(1 for i in batch if i > prime)
        if not numbers_greater_than_prime:
            return prime
    return None
