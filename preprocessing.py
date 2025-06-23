
import hashlib

from typing import Self, overload, AnyStr, runtime_checkable, Protocol

from warnings import warn

from constants import *

from functions import (
    shr, sigma0, sigma1, uSigma0, uSigma1, maj, ch, parity, rotl, rotr
)


@runtime_checkable
class ReadableBuffer(Protocol):
    def __len__(self) -> int: ...
    def __getitem__(self, index: int) -> int: ...
    def __iter__(self): ...
    def extend(self, __x: bytes) -> None: ...


def pad(message: bytearray, message_len: int, block_size: int) -> bytearray:
    message.append(0x80)
    length_field_size: int = 128 if block_size == 1024 else 64
    while ((len(message) * 8) % block_size) != (block_size - length_field_size):
        message.append(0x00)
    message += message_len.to_bytes(length_field_size // 8, 'big')
    return message


class HASH(object):
    def __init__(self, digest_size: int, block_size: int, name: str, hash_values: list) -> None:
        self._buffer: bytearray = bytearray()
        self._counter: int = 0

        self.digest_size: int = digest_size
        self.block_size:  int = block_size
        self.name: str = name

        self._H: list = hash_values

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
        '''Must be implemented by subclass'''
        raise NotImplementedError

    def hexdigest(self) -> str:
        return self.digest().hex()

    def update(self, obj: ReadableBuffer, /) -> None:
        self._buffer.extend(obj)
        self._counter += len(obj)


class sha256(HASH):
    def __init__(self) -> None:
        super().__init__(
            digest_size=32, block_size=512, name='sha256',
            hash_values=[
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ])

    def digest(self) -> bytes:
        message = pad(self._buffer[:], self._counter * 8, self.block_size)
        blocks = [message[i:i + 64] for i in range(0, len(message), 64)]
        H = self._H[:]
        for block in blocks:
            W: list = []
            for t in range(64):
                if t < 16:
                    W.append(int.from_bytes(block[t*4:(t+1)*4], 'big'))
                else:
                    s0 = rotr(W[t-15], 7) ^ rotr(W[t-15], 18) ^ (W[t-15] >> 3)
                    s1 = rotr(W[t-2], 17) ^ rotr(W[t-2], 19) ^ (W[t-2] >> 10)
                    W.append((W[t-16] + s0 + W[t-7] + s1) % 2**32)

        a, b, c, d, e, f, g, h = H

        for t in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + K256[t] + W[t]) % 2**32
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) % 2**32
            h, g, f, e, d, c, b, a = (
                g, f, e, (d + temp1) % 2**32, c, b, a, (temp1 + temp2) % 2**32
            )

        H = [(x + y) % 2**32 for x, y in zip(H, [a, b, c, d, e, f, g, h])]

        return b''.join(h.to_bytes(4, 'big') for h in H)


@overload
def compare_digest(a: ReadableBuffer, b: ReadableBuffer, /) -> bool: ...
@overload
def compare_digest(a: AnyStr, b: AnyStr, /) -> bool: ...



'''
NOTE: The `usedforsecurity` parameter in OpenSSL functions is primarily advisory.
In most cases, it has no effect. However, for insecure algorithms like MD5 and SHA-1,
setting `usedforsecurity=True` may raise a warning in security-sensitive environments.
'''

def new(string: ReadableBuffer = b'', *, usedforsecurity: bool = True) -> HASH: ...

def openssl_md5(string: ReadableBuffer = b'', *, usedforsecurity: bool = True) -> HASH:
    if usedforsecurity:
        warn('MD5 is not considered secure for cryptographic purposes.', category=UserWarning)

def openssl_sha1(string: ReadableBuffer = b'', *, usedforsecurity: bool = True) -> HASH:
    if usedforsecurity:
        warn('SHA-1 is not considered secure for cryptographic purposes.', category=UserWarning)

def openssl_sha224(string: ReadableBuffer = b'', *, usedforsecurity: bool = True) -> HASH: ...

def openssl_sha256(string: ReadableBuffer = b'', *, usedforsecurity: bool = True) -> HASH:

    obj: sha256 = sha256()
    if string: obj.update(string)
    return obj


def openssl_sha384(string: ReadableBuffer = b'', *, usedforsecurity: bool = True) -> HASH: ...
def openssl_sha512(string: ReadableBuffer = b'', *, usedforsecurity: bool = True) -> HASH: ...
