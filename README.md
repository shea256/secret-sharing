Secret Sharing
=============

A system for sharing secrets using Shamir's Secret Sharing Scheme.

## Sample Usage

#### Creating secrets from ascii strings

    >>> from secretsharing.shamir import Secret
    >>> secret = Secret.from_printable_ascii("Hello, world!")
    >>> secret.as_printable_ascii()
    'Hello, world!'
    >>> secret.as_int()
    43142121247394322427211362L

#### Creating secrets from hex values

    >>> private_key = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
    >>> secret = Secret.from_hex(private_key)

#### Creating secrets from integers

    >>> secret = Secret(43142121247394322427211362L)

#### Spliting secrets into shares

    >>> shares = secret.split(3, 5)
    >>> print shares
    ['01-762cfaba2802c2191e486f', '02-1762f2ca77fbd06de2565c4', '03-123b648dc47453748d24662', '04-17ec24f587e9b535924ea48', '05-8753401c25bf5b0f1d5177']

#### Recovering secrets from shares

  	>>> recovered_shares = ['02-1762f2ca77fbd06de2565c4', '04-17ec24f587e9b535924ea48', '05-8753401c25bf5b0f1d5177']
    >>> recovered_secret = Secret.from_shares(recovered_shares)
    >>> recovered_secret.as_printable_ascii()
    'Hello, world!'

#### Shares too long? Use Bitcoin inspired base58 encoding instead of hex

    >>> secret = Secret.from_printable_ascii("Hello, world!")
    >>> b58_shares = secret.split(3, 5, share_enc='b58')
    >>> print b58_shares
    ['2-dqqXbFouiv6aztG', '3-2NuD3PS2me78j8mo', '4-C4WafUspLBCcd8H', '5-2TFUFR7fYkFUiFcn', '6-nYMwed5TwCnZEaE']

#### Recovering secrets from base58 shares

    >>> recovered_shares = ['2-dqqXbFouiv6aztG', '3-2NuD3PS2me78j8mo','4-C4WafUspLBCcd8H']
    >>> recovered_secret = Secret.from_shares(recovered_shares, share_enc='b58')
    >>> print recovered_secret.as_printable_ascii()
    'Hello, world!'

You can also use integers or (a modification of) [the NATO phonetic alphabet](http://en.wikipedia.org/wiki/NATO_phonetic_alphabet] with `share_enc='int'` or `share_enc='nato'`.
