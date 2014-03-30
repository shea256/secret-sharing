# -*- coding: utf-8 -*-
# Copied/inspired by 2014-03-30 from characters repo:
# https://raw.githubusercontent.com/onenameio/characters/

import string

# Integer


def int_to_charset(val, charset):
    """ Turn a non-negative integer into a string.
    """
    if not val >= 0:
        raise ValueError('"val" must be a non-negative integer.')
    if val == 0:
        return charset[0]
    output = ""
    while val > 0:
        val, digit = divmod(val, len(charset))
        output += charset[digit]
    # reverse the characters in the output and return
    return output[::-1]


def charset_to_int(s, charset):
    """ Turn a string into a non-negative integer.
    """
    output = 0
    for char in s:
        output = output * len(charset) + charset.index(char)
    return output


def change_charset(s, original_charset, target_charset):
    """ Convert a string from one charset to another.
    """
    if not isinstance(s, str):
        raise ValueError('"s" must be a string.')

    intermediate_integer = charset_to_int(s, original_charset)
    output_string = int_to_charset(intermediate_integer, target_charset)
    return output_string


# Hexadecimal

def hex_to_int(s):
    return charset_to_int(s, string.hexdigits[0:16])


def int_to_hex(val):
    return int_to_charset(val, string.hexdigits[0:16])


def is_hex(s):
    try:
        int(s, 16)
    except ValueError:
        return False
    else:
        return True

# Base 58

# https://en.bitcoin.it/wiki/Base58Check_encoding
B58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58_to_int(s):
    return charset_to_int(s, B58_CHARS)


def int_to_b58(val):
    return int_to_charset(val, B58_CHARS)


def is_b58(s):
    for char in s:
        if char not in B58_CHARS:
            return False
    return True

# Integer

def is_int(s):
    # http://stackoverflow.com/a/1267145/1754586
    try:
        int(s)
        return True
    except ValueError:
        return False

# Nato phonetic alphabet
# http://en.wikipedia.org/wiki/NATO_phonetic_alphabet
# 0 and l removed (kind of like b58)
NATO_CHARS = '123456789abcdefghijkmnopqrstuvwxyz'

def nato_to_int(s):
    return charset_to_int(s, NATO_CHARS)

def int_to_nato(val):
    return int_to_charset(val, NATO_CHARS)

def is_nato(s):
    for char in s:
        if char not in NATO_CHARS:
            return False
    return True
