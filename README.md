secretsharing
=============

A system for sharing secrets using Shamir's Secret Sharing Scheme.

## Sample Usage

#### Creating secrets from strings

    >>> from secretsharing.shamir import Secret
    >>> secret = Secret.from_printable_ascii("Hello, world!")
    >>> secret.as_printable_ascii()
    'Hello, world!'
    >>> secret.as_int()
    43142121247394322427211362L

#### Creating secrets from integers

	>>> secret = Secret(43142121247394322427211362L)

#### Spliting secrets into shares

    >>> shares = secret.split(3, 5)
    >>> for s in shares:
    ... 	print s:
    ...
    01-762cfaba2802c2191e486f
	02-1762f2ca77fbd06de2565c4
	03-123b648dc47453748d24662
	04-17ec24f587e9b535924ea48
	05-8753401c25bf5b0f1d5177

#### Recovering secrets from shares

	>>> recovered_shares = ['02-1762f2ca77fbd06de2565c4', '04-17ec24f587e9b535924ea48', '05-8753401c25bf5b0f1d5177']
    >>> recovered_secret = Secret.from_shares(recovered_shares)
    >>> recovered_secret.as_printable_ascii()
    'Hello, world!'

