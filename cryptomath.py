# Cryptomath Module
import secrets


def gcd(a, b):
    # Returns the GCD of positive integers a and b using the Euclidean Algorithm.
    if a > b:
        x, y = a, b
    else:
        y, x = a, b

    while y != 0:
        temp = x % y
        x = y
        y = temp
    return x


def extended_gcd(a, b):  # used to find mod inverse
    # Returns integers u, v such that au + bv = gcd(a, b).
    x, y = a, b
    u1, v1 = 1, 0
    u2, v2 = 0, 1
    while y != 0:
        r = x % y
        q = (x - r) // y
        u, v = u1 - q * u2, v1 - q * v2
        x = y
        y = r
        u1, v1 = u2, v2
        u2, v2 = u, v
    return (u1, v1)


def find_mod_inverse(a, m):
    # Returns the inverse of a modulo m, if it exists.
    if gcd(a, m) != 1:
        return None
    u, _ = extended_gcd(a, m)
    return u % m


def rabin_miller(n):
    # Applies the probabilistic Rabin-Miller test for primality.
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    d, s = decompose(n - 1)
    for _ in range(50):
        a = secrets.randbelow(n - 2) + 2
        if not is_composite(a, d, n, s):
            continue
        return False
    return True


def decompose(n):
    # Decomposes (n - 1) into d * 2^s with d odd.
    d = n
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    return d, s


def is_composite(a, d, n, s):
    # Checks if n is composite using a single base a.
    if gcd(a, n) != 1:
        return True
    b = pow(a, d, n)
    if b in {1, n - 1}:
        return False
    for _ in range(s - 1):
        b = pow(b, 2, n)
        if b == n - 1:
            return False
    return True


def is_small_prime(n, small_primes):
    # See if n is a small prime.
    return n in small_primes


def is_divisible_by_small_prime(n, small_primes):
    # See if n is divisible by a small prime.
    for p in small_primes:
        if n % p == 0:
            return True
    return any(n % p == 0 for p in small_primes)


def apply_fermat_test(n, bases):
    # Apply Fermat test for compositeness.
    for base in bases:
        if pow(base, n - 1, n) != 1:
            return False
    return all(pow(base, n - 1, n) == 1 for base in bases)


def is_prime(n):
    # Determines whether a positive integer n is composite or probably prime.
    if n < 2:
        return False
    small_primes = get_small_primes()
    if is_small_prime(n, small_primes):
        return True
    if is_divisible_by_small_prime(n, small_primes):
        return False
    if not apply_fermat_test(n, [2, 3, 5, 7, 11]):
        return False
    return rabin_miller(n)


def get_small_primes():
    # Returns a list of small prime numbers.
    return [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
            59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
            127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
            191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
            257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
            331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
            401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
            467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
            563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
            631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
            709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
            797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
            877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
            967, 971, 977, 983, 991, 997]


def find_prime(bits=1024, tries=10000):
    # Find a prime with the given number of bits.
    x = 2 ** (bits - 1)
    y = 2 * x
    for _ in range(tries):
        n = secrets.randbelow(y - x) + x  # Generate a random number in the range [x, y)
        if n % 2 == 0:
            n += 1
        if is_prime(n):
            return n
    return None