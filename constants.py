import math, decimal
from typing import Iterator

def _nprimes(x: int) -> Iterator[int]:

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


K1:   list = [int(math.sqrt(p) * (2**32)) & 0xFFFFFFFF for p in (2, 3, 5, 10)]

K224: list = [_cbrt_frac(i, mod=2**32) for i in _nprimes(64)]

K256: list = K224

K384: list = [_cbrt_frac(i, mod=2**64) for i in _nprimes(80)]

K512 = K512_224 = K512_256 = K384
