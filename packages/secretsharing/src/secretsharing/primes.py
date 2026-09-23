"""Primes of the legacy v0 format and a primality check used only to validate user-supplied primes."""

import secrets

_MERSENNE_EXPONENTS = (2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279)
STANDARD_PRIMES: list[int] = sorted(
    [2**e - 1 for e in _MERSENNE_EXPONENTS] + [2**256 + 297, 2**320 + 27, 2**384 + 231]
)
_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
_DETERMINISTIC_BOUND = 3_317_044_064_679_887_385_961_981  # bases 2..37 are exact below this


def is_probable_prime(n: int) -> bool:
    """Miller–Rabin: deterministic below 3.3e24, sixty-four random bases above."""
    if type(n) is not int or n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    bases = _SMALL_PRIMES if n < _DETERMINISTIC_BOUND else [secrets.randbelow(n - 3) + 2 for _ in range(64)]
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True
