"""
Chosen-ciphertext attack on PKCS #1 v1.5
https://www.iacr.org/archive/crypto2001/21390229.pdf
"""
from oracles import PKCS1_OAEP_Oracle
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import math

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

def tryWithOracle(number, key, c, oracle, k): #smaller returns true
    to_send_to_oracle = (pow(number, key.e, key.n) * c)%key.n
    return oracle.query(to_send_to_oracle.to_bytes(k, byteorder='big'))

def find_f1(k, key, c, oracle):
    """
    Step 1 of the attack
    :param k: length of block in bytes
    :param key: RSA key
    :param c: integer representing the parameter of the attack
    :param oracle: oracle that checks whether a decryption is smaller than B
    :return: f1 such that B/2 <= f1 * m / 2 < B
    """
    f1 = 2
    while (True):
        oracle_result = tryWithOracle(f1, key, c, oracle, k)
        if(oracle_result == True):
            f1 = f1*2
        else:
            return f1

def find_f2(k, key, c, f1, oracle):
    """
    Step 2 of the attack
    :param k: length of block in bytes
    :param key: RSA key
    :param c: integer representing the parameter of the attack
    :param f1: multiple from the previous step
    :param oracle: oracle that checks whether a decryption is smaller than B
    :return: f2 such that n <= f2 * m < n + B
    """
    B = 2 ** (8 * (k - 1))
    f2 = int(divfloor(key.n + B, B) * (f1 / 2))
    while (True):
        oracle_result = tryWithOracle(f2, key, c, oracle, k)
        if (oracle_result == False): # More than B
            f2 = int(f2 + f1 / 2)
        else:
            return f2


def find_m(k, key, c, f2, oracle, verbose=False):
    """
    Step 3 of the attack
    :param k: length of block in bytes
    :param key: RSA key
    :param c: integer representing the parameter of the attack
    :param f2: multiple from the previous step
    :param oracle: oracle that checks whether a decryption is smaller than B
    :return: m such that (m ** e) mod n = c
    """
    B = 2 ** (8 * (k - 1))
    m_min = divceil(key.n, f2)
    original_min = m_min
    m_max = divfloor(key.n + B, f2)
    original_max = m_max
    count = 0
    while m_max != m_min:
        if verbose:
            print("Round", count)
        count = count + 1
        f_temp = divfloor(2 * B , m_max - m_min)
        i = divfloor(f_temp * m_min, key.n)
        f3 = divceil(i * key.n, m_min)
        oracle_result = tryWithOracle(f3, key, c, oracle, k)
        if (oracle_result == False): #bigger than B
            m_min = divceil(i * key.n + B, f3)
        else:
            m_max = divfloor(i * key.n + B, f3)
    return m_min


def manger_attack(k, key, c, oracle, verbose=False):
    """
    Given an RSA public key and an oracle for whether a decryption is lesser than B, along with a conforming ciphertext
        c, calculate m = (c ** d) mod n
    :param k: length of ciphertext in bytes
    :param key: RSA public key
    :param c: input parameter
    :param oracle: oracle that checks whether a decryption is smaller than B
    :return: m such that m = (c ** d) mod n
    """
    c = int.from_bytes(c, byteorder='big')

    f1 = find_f1(k, key, c, oracle)
    if verbose:
        print("f1 =", f1)

    f2 = find_f2(k, key, c, f1, oracle)
    if verbose:
        print("f2 =", f2)

    m = find_m(k, key, c, f2, oracle, False)

    # Test the result - if implemented properly the attack should always succeed
    if pow(m, key.e, key.n) == c:
        return m.to_bytes(k, byteorder='big')
    else:
        return None


if __name__ == "__main__":
    n_length = 1024

    key = RSA.generate(n_length)
    pub_key = key.public_key()
    k = int(n_length / 8)

    oracle = PKCS1_OAEP_Oracle(k, key)

    cipher = PKCS1_OAEP.new(key)
    message = b'secret message'
    c = cipher.encrypt(message)

    result = manger_attack(k, pub_key, c, oracle, False)
    print(result)
    
