# main.py
# A naive Python implementation of the hashlib library.

from __future__ import annotations

import math
import decimal
import warnings

import typing as t


@t.runtime_checkable
class ReadableBuffer(t.Protocol):
    def __len__(self) -> int: ...
    def __getitem__(self, index: int) -> int: ...
    def __iter__(self): ...
    def extend(self, __x: bytes) -> None: ...


class HashMismatchError(BaseException): ...


def _nprimes(n: int) -> t.Iterator[int]:
    '''Returns the first n prime numbers'''

    def is_prime(number: int) -> bool:
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False

        for i in range(3, int(math.isqrt(n)) + 1, 2):
            if n % i == 0:
                return False

        return True

    found, candidate = 0, 2

    while found:
        if is_prime(candidate):
            yield candidate
            found += 1
        candidate += 1


def _cbrt_fractional_part(number: int, mod: int) -> int:
    '''Returns the fractional part of math.cbrt(x)'''
    cbrt = decimal.Decimal(number) ** (decimal.Decimal(1) / decimal.Decimal(3))
    return int((cbrt - math.floor(cbrt)) * mod)


class HASH(object):

    def __init__(self, digest_size: int, block_size: int, word_bit_length: int, name: str) -> None:
        self._buffer: bytearray = bytearray()
        self._counter: int = 0

        self.digest_size: int = digest_size
        self.block_size: int = block_size
        self.word_bit_length: int = word_bit_length
        self.name: str = name
