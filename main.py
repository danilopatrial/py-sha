from __future__ import annotations


'''
A naive Python implementation of the hashlib library.

NOTE: Several algorithms  reuse the same  underlying digest  routine—for example,  
SHA-224 relies  on the SHA-256  compression  function.  In the code that follows,  
these shared methods are re-implemented even though they already exist elsewhere.  
This  deliberate duplication keeps each  algorithm self-contained for educational  
clarity.  If you'd rather work with a tidier,  de-duplicated codebase,  check out  
the `better-digest` branch.
```
'''


from typing import (
    Self, 
    Protocol, 
    Iterator, 
    overload, 
    runtime_checkable, 
    type_check_only, 
    AnyStr
    )

from types import MethodType
from warnings import warn

import math, decimal


@runtime_checkable
class ReadableBuffer(Protocol):
    def __len__(self) -> int: ...
    def __getitem__(self, index: int) -> int: ...
    def __iter__(self): ...
    def extend(self, __x: bytes) -> None: ...


@type_check_only
class _HashObject(Protocol):
    @property
    def digest_size(self) -> int: ...
    @property
    def block_size(self) -> int: ...
    @property
    def name(self) -> str: ...
    def copy(self) -> Self: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def update(self, obj: ReadableBuffer, /) -> None: ...


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

    def __init__(self, ds: int, bs: int, w: int, name: str, ihv: list) -> None:
        self._buffer:  bytearray = bytearray()
        self._counter: int = 0

        self.digest_size: int  = ds    # Digest bytes-length
        self.block_size:  int  = bs    # Block size
        self.name:        str  = name  # Algorithm name
        self._w:          int  = w     # word bit-length
        self._H:          list = ihv   # Initial Hash Values

    # Operations on words
    def _ROTR(self, x: int, n: int) -> int: return (x >> n) | (x << (self._w - n))
    def _ROTL(self, x: int, n: int) -> int: return (x << n) | (x >> (self._w - n))

    # Base functions
    @staticmethod
    def _parity(x: int, y: int, z: int) -> int: return x ^ y ^ z
    @staticmethod
    def _ch(x: int, y: int, z: int) -> int: return (x & y) | (~x & z)
    @staticmethod
    def _maj(x: int, y: int, z: int) -> int: return (x & y) | (x & z) | (y & z)

    @property
    def _mod(self) -> int:
        return 0xFFFFFFFF if self._w == 32 else 0xFFFFFFFFFFFFFFFF

    @property
    def K(self) -> list:
        '''Constants'''

        if not hasattr(self, '_K'):
            k_map: dict = {
                'sha1':   [int(math.sqrt(p) * (2**32)) & self._mod for p in (2, 3, 5, 10)],
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
In most cases,  it has no effect.  However,  for insecure algorithms like MD5 and  
SHA-1,  setting `usedforsecurity=True`  may raise a warning in security-sensitive  
environments.
'''

def sha1(string: ReadableBuffer = b'', *, usedforsecurity: bool = True) -> HASH:
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
                    W.append(cls._ROTL(val, 1) & cls._mod)

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

                temp = (cls._ROTL(a, 5) + f + e + k + W[t]) & cls._mod
                a, b, c, d, e = temp, a, cls._ROTL(b, 30), c, d

            cls._H = [(x + y) & cls._mod for x, y in zip(cls._H, [a, b, c, d, e])]

        return b''.join(h.to_bytes(4, 'big') for h in cls._H)[:cls.digest_size]

    # Initial Hash Values
    ihv: list = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

    hash_obj: HASH = HASH(ds=20, bs=512, w=32, name='sha1', ihv=ihv)
    hash_obj.digest = MethodType(__digest, hash_obj)

    if string: hash_obj.update(string)

    return hash_obj


def sha224(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH:
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
                    W.append((s1 + W[t-7] + s0 + W[t-16]) & cls._mod)

            a, b, c, d, e, f, g, h = cls._H

            for t in range(64):
                s1 = cls._ROTR(e, 6) ^ cls._ROTR(e, 11) ^ cls._ROTR(e, 25)
                s0 = cls._ROTR(a, 2) ^ cls._ROTR(a, 13) ^ cls._ROTR(a, 22)
                t1 = (h + s1 + cls._ch(e, f, g) + cls.K[t] + W[t]) & cls._mod
                t2 = (s0 + cls._maj(a, b, c)) & cls._mod

                h, g, f = g, f, e
                e = (d + t1) & cls._mod
                d, c, b = c, b, a
                a = (t1 + t2) & cls._mod

            cls._H = [(x + y) & cls._mod for x, y in zip(cls._H, [a, b, c, d, e, f, g, h])]

        return b''.join(h.to_bytes(4, 'big') for h in cls._H)[:cls.digest_size]

    # Initial Hash Values
    ihv: list = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ]

    hash_obj: HASH = HASH(ds=28, bs=512, w=32, name='sha224', ihv=ihv)
    hash_obj.digest = MethodType(__digest, hash_obj)

    if string: hash_obj.update(string)

    return hash_obj


def sha256(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH:
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
                    W.append((s1 + W[t-7] + s0 + W[t-16]) & cls._mod)

            a, b, c, d, e, f, g, h = cls._H

            for t in range(64):
                s1 = cls._ROTR(e, 6) ^ cls._ROTR(e, 11) ^ cls._ROTR(e, 25)
                s0 = cls._ROTR(a, 2) ^ cls._ROTR(a, 13) ^ cls._ROTR(a, 22)
                t1 = (h + s1 + cls._ch(e, f, g) + cls.K[t] + W[t]) & cls._mod
                t2 = (s0 + cls._maj(a, b, c)) & cls._mod

                h, g, f = g, f, e
                e = (d + t1) & cls._mod
                d, c, b = c, b, a
                a = (t1 + t2) & cls._mod

            cls._H = [(x + y) & cls._mod for x, y in zip(cls._H, [a, b, c, d, e, f, g, h])]

        return b''.join(h.to_bytes(4, 'big') for h in cls._H)[:cls.digest_size]

    # Initial Hash Values
    ihv: list = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ]

    hash_obj: HASH = HASH(ds=32, bs=512, w=32, name='sha256', ihv=ihv)
    hash_obj.digest = MethodType(__digest, hash_obj)

    if string: hash_obj.update(string)

    return hash_obj


def sha384(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH:
    '''Returns a sha384 hash object; optionally initialized with a string'''

    if not isinstance(string, (bytes, bytearray)):
        raise TypeError('Strings must be encoded before hashing')

    def __digest(cls: HASH) -> bytes:
        message: bytearray = cls._pad(cls._buffer[:], cls._counter * 8, cls.block_size)
        blocks: list[bytearray] = [message[i:i + 128] for i in range(0, len(message), 128)]

        for block in blocks:
            W: list = []

            for t in range(80):
                if t <= 15:
                    W.append(int.from_bytes(block[t*8:(t*8)+8], 'big'))
                else:
                    s1 = cls._ROTR(W[t-2], 19) ^ cls._ROTR(W[t-2], 61) ^ W[t-2] >> 6
                    s0 = cls._ROTR(W[t-15], 1) ^ cls._ROTR(W[t-15], 8) ^ W[t-15] >> 7

                    W.append((s1 + W[t-7] + s0 + W[t-16]) & cls._mod)

            a, b, c, d, e, f, g, h = cls._H

            for t in range(80):
                s1 = cls._ROTR(e, 14) ^ cls._ROTR(e, 18) ^ cls._ROTR(e, 41)
                s0 = cls._ROTR(a, 28) ^ cls._ROTR(a, 34) ^ cls._ROTR(a, 39)
                t1 = (h + s1 + cls._ch(e, f, g) + cls.K[t] + W[t]) & cls._mod
                t2 = (s0 + cls._maj(a, b, c)) & cls._mod

                h, g, f = g, f, e
                e = (d + t1) & cls._mod
                d, c, b = c, b, a
                a = (t1 + t2) & cls._mod

            cls._H = [(x + y) & cls._mod for x, y in zip(cls._H, [a, b, c, d, e, f, g, h])]

        return b''.join(h.to_bytes(8, 'big') for h in cls._H)[:cls.digest_size]

    ihv: list = [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
    ]

    hash_obj: HASH = HASH(ds=48, bs=1024, w=64, name='sha384', ihv=ihv)
    hash_obj.digest = MethodType(__digest, hash_obj)

    if string: hash_obj.update(string)

    return hash_obj


def sha512(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH:
    '''Returns a sha512 hash object; optionally initialized with a string'''

    if not isinstance(string, (bytes, bytearray)):
        raise TypeError('Strings must be encoded before hashing')

    def __digest(cls: HASH) -> bytes:
        message: bytearray = cls._pad(cls._buffer[:], cls._counter * 8, cls.block_size)
        blocks: list[bytearray] = [message[i:i + 128] for i in range(0, len(message), 128)]

        for block in blocks:
            W: list = []

            for t in range(80):
                if t <= 15:
                    W.append(int.from_bytes(block[t*8:(t*8)+8], 'big'))
                else:
                    s1 = cls._ROTR(W[t-2], 19) ^ cls._ROTR(W[t-2], 61) ^ W[t-2] >> 6
                    s0 = cls._ROTR(W[t-15], 1) ^ cls._ROTR(W[t-15], 8) ^ W[t-15] >> 7

                    W.append((s1 + W[t-7] + s0 + W[t-16]) & cls._mod)

            a, b, c, d, e, f, g, h = cls._H

            for t in range(80):
                s1 = cls._ROTR(e, 14) ^ cls._ROTR(e, 18) ^ cls._ROTR(e, 41)
                s0 = cls._ROTR(a, 28) ^ cls._ROTR(a, 34) ^ cls._ROTR(a, 39)
                t1 = (h + s1 + cls._ch(e, f, g) + cls.K[t] + W[t]) & cls._mod
                t2 = (s0 + cls._maj(a, b, c)) & cls._mod

                h, g, f = g, f, e
                e = (d + t1) & cls._mod
                d, c, b = c, b, a
                a = (t1 + t2) & cls._mod

            cls._H = [(x + y) & cls._mod for x, y in zip(cls._H, [a, b, c, d, e, f, g, h])]

        return b''.join(h.to_bytes(8, 'big') for h in cls._H)[:cls.digest_size]

    # Initial Hash Values
    ihv: list = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]

    hash_obj: HASH = HASH(ds=64, bs=1024, w=64, name='sha512', ihv=ihv)
    hash_obj.digest = MethodType(__digest, hash_obj)

    if string: hash_obj.update(string)

    return hash_obj


def sha512_224(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH:
    '''Returns a sha512-224 hash object; optionally initialized with a string'''

    if not isinstance(string, (bytes, bytearray)):
        raise TypeError('Strings must be encoded before hashing')

    def __digest(cls: HASH) -> bytes:
        message: bytearray = cls._pad(cls._buffer[:], cls._counter * 8, cls.block_size)
        blocks: list[bytearray] = [message[i:i + 128] for i in range(0, len(message), 128)]

        for block in blocks:
            W: list = []

            for t in range(80):
                if t <= 15:
                    W.append(int.from_bytes(block[t*8:(t*8)+8], 'big'))
                else:
                    s1 = cls._ROTR(W[t-2], 19) ^ cls._ROTR(W[t-2], 61) ^ W[t-2] >> 6
                    s0 = cls._ROTR(W[t-15], 1) ^ cls._ROTR(W[t-15], 8) ^ W[t-15] >> 7

                    W.append((s1 + W[t-7] + s0 + W[t-16]) & cls._mod)

            a, b, c, d, e, f, g, h = cls._H

            for t in range(80):
                s1 = cls._ROTR(e, 14) ^ cls._ROTR(e, 18) ^ cls._ROTR(e, 41)
                s0 = cls._ROTR(a, 28) ^ cls._ROTR(a, 34) ^ cls._ROTR(a, 39)
                t1 = (h + s1 + cls._ch(e, f, g) + cls.K[t] + W[t]) & cls._mod
                t2 = (s0 + cls._maj(a, b, c)) & cls._mod

                h, g, f = g, f, e
                e = (d + t1) & cls._mod
                d, c, b = c, b, a
                a = (t1 + t2) & cls._mod

            cls._H = [(x + y) & cls._mod for x, y in zip(cls._H, [a, b, c, d, e, f, g, h])]

        return b''.join(h.to_bytes(8, 'big') for h in cls._H)[:cls.digest_size]

    # Initial Hash Values
    ihv: list = [
        0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
        0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
    ]

    hash_obj: HASH = HASH(ds=28, bs=1024, w=64, name='sha512-224', ihv=ihv)
    hash_obj.digest = MethodType(__digest, hash_obj)

    if string: hash_obj.update(string)

    return hash_obj


def sha512_256(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH:
    '''Returns a sha512-256 hash object; optionally initialized with a string'''

    if not isinstance(string, (bytes, bytearray)):
        raise TypeError('Strings must be encoded before hashing')

    def __digest(cls: HASH) -> bytes:
        message: bytearray = cls._pad(cls._buffer[:], cls._counter * 8, cls.block_size)
        blocks: list[bytearray] = [message[i:i + 128] for i in range(0, len(message), 128)]

        for block in blocks:
            W: list = []

            for t in range(80):
                if t <= 15:
                    W.append(int.from_bytes(block[t*8:(t*8)+8], 'big'))
                else:
                    s1 = cls._ROTR(W[t-2], 19) ^ cls._ROTR(W[t-2], 61) ^ W[t-2] >> 6
                    s0 = cls._ROTR(W[t-15], 1) ^ cls._ROTR(W[t-15], 8) ^ W[t-15] >> 7

                    W.append((s1 + W[t-7] + s0 + W[t-16]) & cls._mod)

            a, b, c, d, e, f, g, h = cls._H

            for t in range(80):
                s1 = cls._ROTR(e, 14) ^ cls._ROTR(e, 18) ^ cls._ROTR(e, 41)
                s0 = cls._ROTR(a, 28) ^ cls._ROTR(a, 34) ^ cls._ROTR(a, 39)
                t1 = (h + s1 + cls._ch(e, f, g) + cls.K[t] + W[t]) & cls._mod
                t2 = (s0 + cls._maj(a, b, c)) & cls._mod

                h, g, f = g, f, e
                e = (d + t1) & cls._mod
                d, c, b = c, b, a
                a = (t1 + t2) & cls._mod

            cls._H = [(x + y) & cls._mod for x, y in zip(cls._H, [a, b, c, d, e, f, g, h])]

        return b''.join(h.to_bytes(8, 'big') for h in cls._H)[:cls.digest_size]

    # Initial Hash Values
    ihv: list = [
        0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
        0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
    ]

    hash_obj: HASH = HASH(ds=32, bs=1024, w=64, name='sha512-256', ihv=ihv)
    hash_obj.digest = MethodType(__digest, hash_obj)

    if string: hash_obj.update(string)

    return hash_obj


def sha3_224(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH: ...
def sha3_256(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH: ...
def sha3_384(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH: ...
def sha3_512(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH: ...
def shake_128(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH: ...
def shake_256(string: ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH: ...
def hmac_digest(key: bytes | bytearray, msg: ReadableBuffer, digest: str) -> bytes: ...
def pbkdf2_hmac(
    hash_name: str, password: ReadableBuffer, salt: ReadableBuffer, iterations: int, dklen: int | None = None
) -> bytes: ...
def scrypt(
    password: ReadableBuffer, *, salt: ReadableBuffer, n: int, r: int, p: int, maxmem: int = 0, dklen: int = 64
) -> bytes: ...


__all__: list = [var for var in globals().keys() if not var.startswith('_')]


if __name__ == '__main__':

    import hashlib

    def _get_sum(_hash) -> str:
        with open('nist.fips.180-4.pdf', 'rb') as file:
            for chunk in iter(lambda: file.read(8196), b''):  _hash.update(chunk)
        return _hash.hexdigest()

    assert _get_sum(sha1()) == _get_sum(hashlib.sha1())
    assert _get_sum(sha256()) == _get_sum(hashlib.sha256())
    assert _get_sum(sha224()) == _get_sum(hashlib.sha224())
    assert _get_sum(sha512()) == _get_sum(hashlib.sha512())
    assert _get_sum(sha384()) == _get_sum(hashlib.sha384())
    assert _get_sum(sha512_224()) == _get_sum(hashlib.new('sha512-224'))
    assert _get_sum(sha512_256()) == _get_sum(hashlib.new('sha512-256'))