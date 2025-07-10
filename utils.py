# utils.py
# Useful constants and definition

from __future__ import annotations

import typing as t
import decimal
import math

@t.runtime_checkable
class ReadableBuffer(t.Protocol):
    def __len__(self) -> int: ...
    def __getitem__(self, index: int) -> int: ...
    def __iter__(self): ...
    def extend(self, __x: bytes) -> None: ...


class HashMismatchError(BaseException): ...


def nprimes(n: int) -> list[int]:
    """Returns the first n prime numbers"""
    primes: list = []

    def is_prime(number: int) -> bool:
        if number < 2: return False
        if number == 2: return True
        if number % 2 == 0: return False

        for i in range(3, int(math.isqrt(number)) + 1, 2):
            if number % i == 0: return False
        return True

    found, candidate = 0, 2

    while found < n:
        if is_prime(candidate):
            primes.append(candidate); found += 1
        candidate += 1

    return primes


def cbrt_fractional_part(number: int) -> int:
    """Returns the fractional part of math.cbrt(x)"""
    cbrt = decimal.Decimal(number) ** (decimal.Decimal(1) / decimal.Decimal(3))
    print(math.floor(cbrt))
    return cbrt - math.floor(cbrt)


def compute_constants(fn: t.Callable, bits: int, primes: t.Iterable) -> list:
    """Return a list of `⌊frac(fn(p))·2ᵇⁱᵗˢ⌋` for each prime in *primes*."""
    return [int((fn(prime)) * (2**bits)) for prime in primes]


# Initial Hash Values
# See definition in NIST FIPS 180-4, Section 5.3.
sha1_initial_hash_values: tuple = (
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
    )
sha224_initial_hash_values: tuple = (
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
    )
sha256_initial_hash_values: tuple = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)
sha384_initial_hash_values: tuple = (
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
)
sha512_initial_hash_values: tuple = (
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
)
sha512_224_initial_hash_values: tuple = (
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
)
sha512_256_initial_hash_values: tuple = (
    0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
    0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
)