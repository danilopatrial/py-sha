from __future__ import annotations

from typing   import Self, Protocol, Any, NewType, Iterator, overload, runtime_checkable, AnyStr
from warnings import warn

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

    '''
    All not implemented methods must be implemented by the subclass
    '''

    def __init__(self, ds: int, bs: int, name: str, _h: list) -> None:
        self._buffer:  bytearray = bytearray()
        self._counter: int = 0

        self.digest_size: int  = ds
        self.block_size:  int  = bs
        self.name:        str  = name
        self._H:          list = _h # Initial Hash Values

    @property
    def __class__(self) -> HASH: return HASH

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


class SHA1(HASH):
    def __init__(self) -> None:
        super().__init__(
            ds=32, bs=512, name='sha1',
            _h=[
                0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
            ])

    def digest(self) -> bytes:
        message: bytearray = self._pad(self._buffer[:], self._counter * 8, self.block_size)
        blocks: list[bytearray] = [message[i:i + 64] for i in range(0, len(message), 64)]

        for block in blocks:
            W: list[int] = []

            for t in range(80):
                if t <= 15:
                    W.append(int.from_bytes(block[t * 4:(t + 1) * 4], 'big'))
                else:
                    val = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]
                    W.append(self._ROTL(val, 1) & 0xFFFFFFFF)

            a, b, c, d, e = self._H

            for t in range(80):
                if t <= 19:
                    f, k = self._ch(b, c, d), 0x5A827999
                elif t <= 39:
                    f, k = self._parity(b, c, d), 0x6ED9EBA1
                elif t <= 59:
                    f, k = self._maj(b, c, d), 0x8F1BBCDC
                else:
                    f, k = self._parity(b, c, d), 0xCA62C1D6

                temp = (self._ROTL(a, 5) + f + e + k + W[t]) & 0xFFFFFFFF
                a, b, c, d, e = temp, a, self._ROTL(b, 30), c, d

            self._H = [(x + y) & 0xFFFFFFFF for x, y in zip(self._H, [a, b, c, d, e])]

        return b''.join(h.to_bytes(4, 'big') for h in self._H)



'''
NOTE: The `usedforsecurity` parameter in OpenSSL functions is primarily advisory.
In most cases, it has no effect. However, for insecure algorithms like MD5 and SHA-1,
setting `usedforsecurity=True` may raise a warning in security-sensitive environments.
'''

def openssl_sha1(string: ReadableBuffer = b'', *, usedforsecurity: bool = True) -> HASH:

    if usedforsecurity:
        warn('SHA-1 is not considered secure for cryptographic purposes.', category=UserWarning)

    obj: SHA1 = SHA1()
    if string: obj.update(string)
    return obj


