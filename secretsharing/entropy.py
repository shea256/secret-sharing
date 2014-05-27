# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import os
from math import ceil

def dev_random_entropy(numbytes):
    return open("/dev/random", "rb").read(numbytes)

def dev_urandom_entropy(numbytes):
    return open("/dev/urandom", "rb").read(numbytes)

def get_entropy(numbytes):
    if os.name == 'nt':
        return os.urandom(numbytes)
    else:
        return dev_random_entropy(numbytes)

def randint(min_value, max_value):
    """ Chooses a random integer between min_value and max_value, inclusive.
        Range of values: [min_value, max_value]
    """
    if not (isinstance(min_value, int) and isinstance(min_value, int)):
        raise ValueError('min and max must be integers')
    # Bounds are inclusive, so add 1 to the spread between the min and max
    value_range = (max_value - min_value) + 1
    # The bytes of entropy required depends on the bit length of the value range
    numbytes_of_entropy = int(ceil(value_range.bit_length()/8.0)) + 1
    # The entropy value range is the # of possible values of the entropy sample
    entropy_value_range = 2**(numbytes_of_entropy*8)
    # Any number greater than a multiple of the value range will be rejected
    acceptable_sample_range = entropy_value_range - (entropy_value_range % value_range)
    # Rejection sampling: Keep picking random #s until one falls in the range
    while True:
        byte_from_entropy = get_entropy(numbytes_of_entropy)
        int_from_entropy = int(byte_from_entropy.encode('hex'), 16)
        if int_from_entropy <= acceptable_sample_range:
            break
    # Take the sampled int and extract an int that's within the provided bounds
    rand_int = min_value + (int_from_entropy % value_range)
    return rand_int