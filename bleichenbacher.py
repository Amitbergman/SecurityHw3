"""
Chosen-ciphertext attack on PKCS #1 v1.5
http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
"""
from oracles import PKCS1_v1_5_Oracle
from os import urandom
from Crypto.PublicKey import RSA


def egcd(a, b):
    """
    Use Euclid's algorithm to find gcd of a and b
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    """
    Compute modular inverse of a over m
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def divceil(a, b):
    """
    Accurate division with ceil, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: ceil(a / b)
    """
    q, r = divmod(a, b)
    if r:
        return q + 1
    return q


def divfloor(a, b):
    """
    Accurate division with floor, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: floor(a / b)
    """
    q, r = divmod(a, b)
    return q


def merge_intervals(intervals):
    """
    Given a list of intervals, merge them into equivalent non-overlapping intervals
    :param intervals: list of tuples (a, b), where a <= b
    :return: list of tuples (a, b), where a <= b and a_{i+1} > b_i
    """
    intervals.sort(key=lambda x: x[0])

    merged = []
    curr = intervals[0]
    high = intervals[0][1]

    for interval in intervals:
        if interval[0] > high:
            merged.append(curr)
            curr = interval
            high = interval[1]
        else:
            high = max(high, interval[1])
            curr = (curr[0], high)
    merged.append(curr)
    return merged


def blinding(k, key, c, oracle):
    """
    Step 1 of the attack
    :param k: length of block in bytes
    :param key: RSA key
    :param c: integer smaller than n
    :param oracle: oracle that checks ciphertext conformity
    :return: integers s_0, c_0 s.t. s_0 represents a conforming encryption and c_0 = (c * (s_0) ** e) mod n
    """
    if oracle.query(c.to_bytes(k, byteorder='big')):
        return 1, c
    ind = 1
    while True:
        ind +=1
        if (ind % 15000 ==0):
            print(ind)
        s_0 = urandom(k)
        s_0 = int.from_bytes(s_0, byteorder='big') % key.n
        s_0_power_e = pow (s_0,key.e, key.n)
        to_send_to_oracle = (s_0_power_e * c) %key.n
        to_send_to_oracle_as_bytes_arary = to_send_to_oracle.to_bytes(k, byteorder='big')
        if (oracle.query(to_send_to_oracle_as_bytes_arary) == True):
            print(to_send_to_oracle_as_bytes_arary)
            print(to_send_to_oracle,  "is the number")
            return s_0, to_send_to_oracle

def find_min_conforming(key, c_0, min_s, oracle, k):
    """
    Step 2.a and 2.b of the attack
    :param key: RSA key
    :param c_0: integer that represents a conforming ciphertext
    :param min_s: minimal s to run over
    :param oracle: oracle that checks ciphertext conformity
    :return: smallest s >= min_s s.t. (c_0 * (s ** e)) mod n represents a conforming ciphertext
    """
    current = min_s
    ind = 0
    while True:
        ind+=1
        if (ind % 15000 ==0):
            print("ind in find min is ", ind)
        power = pow(current, key.e, key.n)
        to_send_to_oracle = (c_0 * power)%key.n
        to_send_to_oracle_as_bytes_arary = to_send_to_oracle.to_bytes(k, byteorder='big')
        if (oracle.query(to_send_to_oracle_as_bytes_arary) == True):
            return current
        current +=1


def search_single_interval(B, prev_s, a, b, c_0, key, k):
    """
    Step 2.c of the attack
    :param B: 2 ** (8 * (k - 2))
    :param prev_s: s value of previous round
    :param a: minimum of interval
    :param b: maximum of interval
    :param c_0: integer that represents a conforming ciphertext
    :return: s s.t. (c_0 * (s ** e)) mod n represents a conforming ciphertext
    """
    minimal_r_i =  2 * divfloor(b * prev_s - 2  * B, key.n)
    current_r = minimal_r_i -1
    
    while (True):
        if (current_r %15000 ==0):
            print("index in search single is ", current_r)
        current_r +=1
        s_minimal = divceil(2 * B + current_r * key.n, b)
        s_maximal = divfloor(3 * B + current_r * key.n, a)
        for s_value in range(s_minimal, s_maximal):
            power = pow(s_value, key.e, key.n)
            to_send_to_oracle = (c_0 * power)%key.n
            to_send_to_oracle_as_bytes_arary = to_send_to_oracle.to_bytes(k, byteorder='big')
            if (oracle.query(to_send_to_oracle_as_bytes_arary) == True):
                return s_value

def narrow_m(key, m_prev, s, B):
    """
    Step 3 of the attack
    :param key: RSA key
    :param m_prev: previous range
    :param s: s value of the current round
    :param B: 2 ** (8 * (k - 2))
    :return: New narrowed-down intervals
    """
    intervals = []
    for a, b in m_prev:
        min_r = divceil(a * s - 3 * B + 1, key.n)
        max_r = divfloor(b * s - 2 * B, key.n)
        for r in range(min_r, max_r + 1):
            start = max(a, divceil(2 * B + r * key.n, s))
            end = min(b, divfloor(3 * B  - 1 + r *key.n, s))
            if (start > end):
                print("problem - not working interval")
            else:
                intervals.append((start, end))

    return merge_intervals(intervals)


def bleichenbacher_attack(k, key, c, oracle, verbose=False):
    """
    Given an RSA public key and an oracle for conformity of PKCS #1 encryptions, along with a value c, calculate m = (c ** d) mod n
    :param k: length of ciphertext in bytes
    :param key: RSA public key
    :param c: input parameter
    :param oracle: oracle that checks ciphertext conformity
    :return: m s.t. m = (c ** d) mod n
    """
    B = 2 ** (8 * (k - 2))

    c = int.from_bytes(c, byteorder='big')
    s_0, c_0 = blinding(k, key, c, oracle)

    if verbose:
        print("Blinding complete")

    m = [(2 * B, 3 * B - 1)]
    i = 1
    while True:
        if verbose:
            print("Round ", i)
        if i == 1:
            s = find_min_conforming(key, c_0, divceil(key.n, 3 * B), oracle, k)
        elif len(m) > 1:
            s = find_min_conforming(key, c_0, s + 1, oracle, k)
        else:
            a = m[0][0]
            b = m[0][1]
            s = search_single_interval(B, s, a, b, c_0, key, k)

        m = narrow_m(key, m, s, B)
        print("length of m is ", len(m), "the size is", m[0][1] - m[0][0])
        if len(m) == 1 and m[0][0] == m[0][1]:
            a = m[0][0]
            result = modinv(s, key.n) * a
            break
        i += 1

    # Test the result
    if pow(result, key.e, key.n) == c:
        return result.to_bytes(k, byteorder='big')
    else:
        return None


if __name__ == "__main__":
    n_length = 1024

    key = RSA.generate(n_length)
    pub_key = key.public_key()
    k = int(n_length / 8)

    oracle = PKCS1_v1_5_Oracle(key)

    c = b'\x00' + (k - 1) * bytes([1])
    result = bleichenbacher_attack(k, pub_key, c, oracle, True)
    print(result)
