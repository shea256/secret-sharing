SecretSharing
=============

Tools for sharing secrets (like Bitcoin private keys), using shamir's secret sharing scheme

## Sample Usage

#### Splitting up a hex secret into shares

    >>> from secretsharing import SecretSharer
    >>> secret = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
    >>> sharer = SecretSharer()
    >>> shares = sharer.split_secret(secret, 3, 5)
    ['1-2253a55f531283ea44e6616fb6edae5ad78edbbb8c10225e38c6f474fa76df64', '2-7175dcede9247604dd3ed59cc7f95c975f6d1432dc8ed26d2a5b3a5d4b058b28', '3-b22271cb80ff73b5886334e3bfd939987330e875d28304b0ae6c78f4c68f9cad', '4-e45963f81aa37cfc46537f449e8d455e12da58846decb928c4fab03b6d1513f3', '5-81ab373b61091d9170fb4bf64157fe83e69645eaecbefd56e05e0313e95efd1']

#### Recovering a hex secret from hex shares

    >>> sharer.recover_secret(shares[0:3])
    'c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a'

#### Splitting up a text secret into hex shares

    >>> secret = "correct horse battery staple"
    >>> sharer = PlaintextToHexSecretSharer()
    >>> shares = sharer.split_secret(secret, 3, 5)

#### Splitting up a Bitcoin private key into reliably transcribable shares

    >>> secret = "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS"
    >>> sharer = BitcoinSecretSharer()
    >>> shares = sharer.split_secret(secret, 3, 5)
