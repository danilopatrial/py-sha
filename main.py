from __future__ import annotations

from typing    import Self, Protocol, Callable, NewType, Iterator, overload, runtime_checkable, AnyStr
from types     import MethodType
from warnings  import warn
from functools import wraps

import math, decimal


@runtime_checkable
class ReadableBuffer(Protocol):
    def __len__(self) -> int: ...
    def __getitem__(self, index: int) -> int: ...
    def __iter__(self): ...
    def extend(self, __x: bytes) -> None: ...


class HashMismatchError(BaseException): ...


def _nprimes(x: int) -> Iterator[int]:
    '''Returns the first n prime numbers'''
    def is_prime(n: int) -> bool:
        if n < 2: return False
        if n == 2: return True
        if n % 2 == 0: return False
        for i in range(3, int(math.isqrt(n)) + 1, 2):
            if n % i == 0: return False
        return True 

    found, candidate = 0, 2

    while found < x:
        if is_prime(candidate):
            yield candidate
            found += 1
        candidate += 1


def _cbrt_frac(x: int, mod: int) -> int:
    '''Returns the fractional part of math.cbrt(x)'''
    cbrt = decimal.Decimal(x) ** (decimal.Decimal(1) / decimal.Decimal(3))
    return int((cbrt - math.floor(cbrt)) * mod)



class HASH(object):

    def __init__(self, ds: int, bs: int, name: str, ihv: list) -> None:
        self._buffer:  bytearray = bytearray()
        self._counter: int = 0

        self.digest_size: int  = ds
        self.block_size:  int  = bs
        self.name:        str  = name
        self._H:          list = ihv # Initial Hash Values

    # Operations on words
    def _ROTR(self, x: int, n: int) -> int: return (x >> n) | (x << (self.digest_size - n))
    def _ROTL(self, x: int, n: int) -> int: return (x << n) | (x >> (self.digest_size - n))

    # Base functions
    @staticmethod
    def _parity(x: int, y: int, z: int) -> int: return x ^ y ^ z
    @staticmethod
    def _ch(x: int, y: int, z: int) -> int: return (x & y) | (~x & z)
    @staticmethod
    def _maj(x: int, y: int, z: int) -> int: return (x & y) | (x & z) | (y & z)

    @staticmethod
    def _sigma0(x: int) -> int: raise NotImplementedError
    @staticmethod
    def _sigma1(x: int) -> int: raise NotImplementedError
    @staticmethod
    def _uSigma0(x: int) -> int: raise NotImplementedError
    @staticmethod
    def _uSigma1(x: int) -> int: raise NotImplementedError


    @property
    def K(self) -> list:
        '''Constants'''

        if not hasattr(self, '_K'):
            k_map: dict = {
                'sha1':   [int(math.sqrt(p) * (2**32)) & 0xFFFFFFFF for p in (2, 3, 5, 10)],
                'sha224': [_cbrt_frac(i, mod=2**32) for i in _nprimes(64)],
                'sha384': [_cbrt_frac(i, mod=2**64) for i in _nprimes(80)]
            }
            k_map['sha256'] = k_map['sha224']
            k_map['sha512'] = k_map['sha512-224'] = k_map['sha512-256'] = k_map['sha384']

            object.__setattr__(self, '_K', k_map[self.name])

        return self._K


    @staticmethod
    def _pad(message: bytearray, message_len: int, block_size: int) -> bytearray:
        message.append(0x80)
        length_field_size = 128 if block_size == 1024 else 64
        while ((len(message) * 8) % block_size) != (block_size - length_field_size):
            message.append(0x00)
        message += message_len.to_bytes(length_field_size // 8, 'big')
        return message


    def copy(self) -> Self:
        clone = self.__class__.__new__(self.__class__)
        clone.__dict__.update({
            '_buffer': self._buffer[:],
            '_counter': self._counter,
            'digest_size': self.digest_size,
            'block_size': self.block_size,
            'name': self.name,
            '_H': self._H[:],
        })
        return clone

    def digest(self) -> bytes:
        raise NotImplementedError

    def hexdigest(self) -> str:
        return self.digest().hex()

    def update(self, obj: ReadableBuffer, /) -> None:
        self._buffer.extend(obj)
        self._counter += len(obj)


'''
NOTE: The `usedforsecurity` parameter in OpenSSL functions is primarily advisory.
In most cases, it has no effect. However, for insecure algorithms like MD5 and SHA-1,
setting `usedforsecurity=True` may raise a warning in security-sensitive environments.
'''

def openssl_sha1(string: ReadableBuffer = b'', *, usedforsecurity: bool = True) -> HASH:
    '''Returns a sha1 hash object; optionally initialized with a string'''

    if not isinstance(string, (bytes, bytearray)):
        raise TypeError('Strings must be encoded before hashing')

    if usedforsecurity:
        warn('SHA-1 is not considered secure for cryptographic purposes.', category=UserWarning)

    def __digest(cls: HASH) -> bytes:
        message: bytearray = cls._pad(cls._buffer[:], cls._counter * 8, cls.block_size)
        blocks: list[bytearray] = [message[i:i + 64] for i in range(0, len(message), 64)]

        for block in blocks:
            W: list[int] = []

            for t in range(80):
                if t <= 15:
                    W.append(int.from_bytes(block[t * 4:(t + 1) * 4], 'big'))
                else:
                    val = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]
                    W.append(cls._ROTL(val, 1) & 0xFFFFFFFF)

            a, b, c, d, e = cls._H

            for t in range(80):
                if t <= 19:
                    f, k = cls._ch(b, c, d), 0x5A827999
                elif t <= 39:
                    f, k = cls._parity(b, c, d), 0x6ED9EBA1
                elif t <= 59:
                    f, k = cls._maj(b, c, d), 0x8F1BBCDC
                else:
                    f, k = cls._parity(b, c, d), 0xCA62C1D6

                temp = (cls._ROTL(a, 5) + f + e + k + W[t]) & 0xFFFFFFFF
                a, b, c, d, e = temp, a, cls._ROTL(b, 30), c, d

            cls._H = [(x + y) & 0xFFFFFFFF for x, y in zip(cls._H, [a, b, c, d, e])]

        return b''.join(h.to_bytes(4, 'big') for h in cls._H)

    # Initial Hash Values
    ihv: list = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

    hash_obj: HASH = HASH(ds=32, bs=512, name='sha1', ihv=ihv)
    hash_obj.digest = MethodType(__digest, hash_obj)

    if string: hash_obj.update(string)

    return hash_obj


def openssl_sha224(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH:
    '''Returns a sha224 hash object; optionally initialized with a string'''

    if not isinstance(string, (bytes, bytearray)):
        raise TypeError('Strings must be encoded before hashing')

    def __digest(cls: HASH) -> bytes:
        message: bytearray = cls._pad(cls._buffer[:], cls._counter * 8, cls.block_size)
        blocks: list[bytearray] = [message[i:i + 64] for i in range(0, len(message), 64)]

        for block in blocks:
            W: list[int] = []

            for t in range(64):
                if t <= 15:
                    W.append(int.from_bytes(block[t*4:(t*4)+4], 'big'))
                else:
                    s1 = cls._ROTR(W[t-2], 17) ^ cls._ROTR(W[t-2], 19) ^ W[t-2] >> 10
                    s0 = cls._ROTR(W[t-15], 7) ^ cls._ROTR(W[t-15], 18) ^ W[t-15] >> 3
                    W.append((s1 + W[t-7] + s0 + W[t-16]) & 0xFFFFFFFF)

            a, b, c, d, e, f, g, h = cls._H

            for t in range(64):
                s1 = cls._ROTR(e, 6) ^ cls._ROTR(e, 11) ^ cls._ROTR(e, 25)
                s0 = cls._ROTR(a, 2) ^ cls._ROTR(a, 13) ^ cls._ROTR(a, 22)
                t1 = (h + s1 + cls._ch(e, f, g) + cls.K[t] + W[t]) & 0xFFFFFFFF
                t2 = (s0 + cls._maj(a, b, c)) & 0xFFFFFFFF

                h, g, f = g, f, e
                e = (d + t1) & 0xFFFFFFFF
                d, c, b = c, b, a
                a = (t1 + t2) & 0xFFFFFFFF

            cls._H = [(x + y) & 0xFFFFFFFF for x, y in zip(cls._H, [a, b, c, d, e, f, g, h])]

        cls._H.pop()
        return b''.join(h.to_bytes(4, 'big') for h in cls._H)

    # Initial Hash Values
    ihv: list = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ]

    hash_obj: HASH = HASH(ds=32, bs=512, name='sha224', ihv=ihv)
    hash_obj.digest = MethodType(__digest, hash_obj)

    if string: hash_obj.update(string)

    return hash_obj


def openssl_sha256(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH:
    '''Returns a sha256 hash object; optionally initialized with a string'''

    if not isinstance(string, (bytes, bytearray)):
        raise TypeError('Strings must be encoded before hashing')

    def __digest(cls: HASH) -> bytes:
        message: bytearray = cls._pad(cls._buffer[:], cls._counter * 8, cls.block_size)
        blocks: list[bytearray] = [message[i:i + 64] for i in range(0, len(message), 64)]

        for block in blocks:
            W: list[int] = []

            for t in range(64):
                if t <= 15:
                    W.append(int.from_bytes(block[t*4:(t*4)+4], 'big'))
                else:
                    s1 = cls._ROTR(W[t-2], 17) ^ cls._ROTR(W[t-2], 19) ^ W[t-2] >> 10
                    s0 = cls._ROTR(W[t-15], 7) ^ cls._ROTR(W[t-15], 18) ^ W[t-15] >> 3
                    W.append((s1 + W[t-7] + s0 + W[t-16]) & 0xFFFFFFFF)

            a, b, c, d, e, f, g, h = cls._H

            for t in range(64):
                s1 = cls._ROTR(e, 6) ^ cls._ROTR(e, 11) ^ cls._ROTR(e, 25)
                s0 = cls._ROTR(a, 2) ^ cls._ROTR(a, 13) ^ cls._ROTR(a, 22)
                t1 = (h + s1 + cls._ch(e, f, g) + cls.K[t] + W[t]) & 0xFFFFFFFF
                t2 = (s0 + cls._maj(a, b, c)) & 0xFFFFFFFF

                h, g, f = g, f, e
                e = (d + t1) & 0xFFFFFFFF
                d, c, b = c, b, a
                a = (t1 + t2) & 0xFFFFFFFF

            cls._H = [(x + y) & 0xFFFFFFFF for x, y in zip(cls._H, [a, b, c, d, e, f, g, h])]

        return b''.join(h.to_bytes(4, 'big') for h in cls._H)

    # Initial Hash Values
    ihv: list = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ]

    hash_obj: HASH = HASH(ds=32, bs=512, name='sha256', ihv=ihv)
    hash_obj.digest = MethodType(__digest, hash_obj)

    if string: hash_obj.update(string)

    return hash_obj



if __name__ == '__main__':

    import hashlib

    def _get_sum(_hash) -> str:
        with open('sha/nist.fips.180-4.pdf', 'rb') as file:
            for chunk in iter(lambda: file.read(8196), b''):  _hash.update(chunk)
        return _hash.hexdigest()

    assert _get_sum(openssl_sha1())   == _get_sum(hashlib.sha1())
    assert _get_sum(openssl_sha256()) == _get_sum(hashlib.sha256())
    assert _get_sum(openssl_sha224()) == _get_sum(hashlib.sha224())