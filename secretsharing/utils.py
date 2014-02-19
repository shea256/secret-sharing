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

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(k, prime):
    k = k % prime
    if k < 0:
        r = egcd(prime, -k)[2]
    else:
        r = egcd(prime, k)[2]
    return (prime + r) % prime

def get_smallest_257bit_prime():
    return (2**256 + 297)

def get_mersenne_primes():
    """ Returns all the mersenne primes with less than 500 digits.
        All primes:
        3, 7, 31, 127, 8191, 131071, 524287, 2147483647L, 2305843009213693951L,
        618970019642690137449562111L, 162259276829213363391578010288127L,
        170141183460469231731687303715884105727L,
        68647976601306097149...12574028291115057151L, (157 digits)
        53113799281676709868...70835393219031728127L, (183 digits)
        10407932194664399081...20710555703168729087L, (386 digits)
    """
    mersenne_prime_exponents = [
        2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279
    ]
    primes = []
    for exp in mersenne_prime_exponents:
        prime = long(1)
        for i in range(exp):
            prime *= 2
        prime -= 1
        primes.append(prime)
    return primes

def get_large_enough_prime(batch):
    """ Returns a prime number that is greater all the numbers in the batch.
    """
    # build a list of primes
    primes = get_mersenne_primes() + [get_smallest_257bit_prime()]
    primes.sort()
    # find a prime that is greater than all the numbers in the batch
    for prime in primes:
        numbers_greater_than_prime = [i for i in batch if i > prime]
        if len(numbers_greater_than_prime) == 0:
            return prime
    return None

def random_polynomial(degree, intercept, upper_bound):
    """ Generates a random polynomial with positive coefficients.
    """
    if degree < 0:
        raise ValueError('Degree must be a non-negative number.')
    coefficients = [intercept]
    for i in range(degree):
        random_coeff = randint(0, upper_bound-1)
        coefficients.append(random_coeff)
    return coefficients

def get_polynomial_points(coefficients, num_points, prime):
    """ Calculates the first n polynomial points.
        [ (1, f(1)), (2, f(2)), ... (n, f(n)) ]
    """
    points = []
    for x in range(1, num_points+1):
        # start with x=1 and calculate the value of y
        y = coefficients[0]
        # calculate each term and add it to y, using modular math
        for i in range(1, len(coefficients)):
            exponentiation = (long(x)**i) % prime
            term = (coefficients[i] * exponentiation) % prime
            y = (y + term) % prime
        # add the point to the list of points
        points.append((x, y))
    return points

def modular_lagrange_interpolation(x, points, prime):
	# break the points up into lists of x and y values
    x_values, y_values = zip(*points)
    # initialize f(x) and begin the calculation: f(x) = SUM( y_i * l_i(x) )
    f_x = long(0)
    for i in range(len(points)):
    	# evaluate the lagrange basis polynomial l_i(x)
        numerator, denominator = 1, 1
        for j in range(len(points)):
        	# don't compute a polynomial fraction if i equals j
            if i == j: continue
            # compute a fraction and update the existing numerator + denominator
            numerator = (numerator * (x - x_values[j])) % prime
            denominator = (denominator * (x_values[i] - x_values[j])) % prime
        # get the polynomial from the numerator + mod inverse of the denominator
        lagrange_polynomial = numerator * mod_inverse(denominator, prime)
        # multiply the current y and the evaluated polynomial and add it to f(x)
        f_x = (prime + f_x + (y_values[i] * lagrange_polynomial)) % prime
    return f_x

