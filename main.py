# main.py
# A naive Python implementation of the secure hash standard (NIST FIPS 180-4).

from __future__ import annotations

import warnings
import math
import typing as t
import copy
import decimal

if t.TYPE_CHECKING:
    import _typeshed as _t

from functools import partial, wraps

# Initial Hash Values
# See definition in NIST FIPS 180-4, Section 5.3.
SHA1_INITIAL_HASH_VALUES: tuple = (
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
)
SHA224_INITIAL_HASH_VALUES: tuple = (
    0xC1059ED8,
    0x367CD507,
    0x3070DD17,
    0xF70E5939,
    0xFFC00B31,
    0x68581511,
    0x64F98FA7,
    0xBEFA4FA4,
)
SHA256_INITIAL_HASH_VALUES: tuple = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
SHA384_INITIAL_HASH_VALUES: tuple = (
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
)
SHA512_INITIAL_HASH_VALUES: tuple = (
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)
SHA512_224_INITIAL_HASH_VALUES: tuple = (
    0x8C3D37C819544DA2,
    0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82,
    0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8,
    0x77E36F7304C48942,
    0x3F9D85A86A1D36C8,
    0x1112E6AD91D692A1,
)
SHA512_256_INITIAL_HASH_VALUES: tuple = (
    0x22312194FC2BF72C,
    0x9F555FA3C84C64C2,
    0x2393B86B6F53B151,
    0x963877195940EABD,
    0x96283EE2A88EFFE3,
    0xBE5E1E2553863992,
    0x2B0199FC2C85B8AA,
    0x0EB72DDC81C52CA2,
)


class HashMismatchError(BaseException): ...


def _nprimes(n: int) -> list[int]:
    """Returns the first n prime numbers"""
    primes: list = []

    def is_prime(number: int) -> bool:
        if number < 2:
            return False
        if number == 2:
            return True
        if number % 2 == 0:
            return False

        for i in range(3, int(math.isqrt(number)) + 1, 2):
            if number % i == 0:
                return False
        return True

    found, candidate = 0, 2

    while found < n:
        if is_prime(candidate):
            primes.append(candidate)
            found += 1
        candidate += 1

    return primes


def _cbrt_fractional_part(number: int) -> int:
    """Returns the fractional part of math.cbrt(x)"""
    cbrt = decimal.Decimal(number) ** (decimal.Decimal(1) / decimal.Decimal(3))
    return cbrt - math.floor(cbrt)


def _compute_constants(fn: t.Callable, bits: int, primes: t.Iterable) -> list:
    """Return a list of `⌊frac(fn(p))·2ᵇⁱᵗˢ⌋` for each prime in *primes*."""
    return [int((fn(prime)) * (2**bits)) for prime in primes]


class HASH(object):

    __slots__: tuple = (
        "_buffer",
        "_counter",
        "digest_size",
        "block_size",
        "word_bit_length",
        "name",
        "_K",
        "usedforsecurity",
    )

    def __new__(cls, **kwds) -> HASH:
        if kwds.get("name", None).lower() == "sha1" and kwds.get(
            "usedforsecurity", False
        ):
            warnings.warn(
                "SHA-1 is not considered secure for cryptographic purposes.",
                UserWarning,
            )
        return super().__new__(cls)

    @t.overload
    def __init__(
        self,
        *,
        digest_size: int,
        block_size: int,
        word_bit_length: int,
        name: str,
        **kwds,
    ) -> None: ...
    def __init__(self, **kwds: t.Union[int, str, bool]) -> None:

        self._buffer: bytearray = bytearray()
        self._counter: int = 0

        for key, value in kwds.items():
            object.__setattr__(self, key, value)

    # Operations on words, see definition in NIST FIPS 180-4, Section 3.2
    def _ROTR(self, x: int, n: int) -> int:
        return ((x >> n) | (x << (self.word_bit_length - n))) & self.mod

    def _ROTL(self, x: int, n: int) -> int:
        return ((x << n) | (x >> (self.word_bit_length - n))) & self.mod

    # Base functions, see definition in NIST FIPS 180-4, Section 4
    @staticmethod
    def _parity(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    @staticmethod
    def _ch(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    @staticmethod
    def _maj(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    @property
    def mod(self) -> int:
        return 0xFFFFFFFF if self.word_bit_length == 32 else 0xFFFFFFFFFFFFFFFF

    @property
    def K(self) -> list:
        """See definition in NIST FIPS 180-4, Section 4.2"""
        if hasattr(self, "_K") and object.__getattribute__(self, "_K"):
            return self._K

        cbrt_frac32 = partial(
            _compute_constants, lambda p: _cbrt_fractional_part(p), 32
        )
        cbrt_frac64 = partial(
            _compute_constants, lambda p: _cbrt_fractional_part(p), 64
        )

        P64: list = _nprimes(64)
        P80: list = _nprimes(80)

        const_map = {
            "sha224": cbrt_frac32(P64),  # NIST FIPS 180-4, Section 4.2.2
            "sha256": cbrt_frac32(P64),
            "sha384": cbrt_frac64(P80),  # NIST FIPS 180-4, Section 4.2.3
        }

        # All three 512-bit variants share the same table
        const_map.update(
            {key: const_map["sha384"] for key in ("sha512", "sha512_224", "sha512_256")}
        )

        self._K = const_map[self.name.lower()]
        return self._K

    @staticmethod
    def pad(message: bytearray, message_len: int, block_size: int) -> bytearray:
        """The purpose of this padding is to ensure that the padded
        message is a multiple of 512 or 1024 bits, depending on the
        algorithm. See definition in NIST FIPS 180-4, Section 5.1"""

        message.append(0x80)
        length_field_size: int = (
            128 if block_size == 1024 else 64 if block_size == 512 else None
        )
        while ((len(message) * 8) % block_size) != (block_size - length_field_size):
            message.append(0x00)
        message += message_len.to_bytes(length_field_size // 8, "big")
        return message

    def copy(self) -> HASH:
        return copy.deepcopy(self)

    def __sha1_digest(self) -> bytes:
        message: bytearray = self.pad(
            self._buffer[:], self._counter * 8, self.block_size
        )
        blocks: list[bytearray] = [
            message[i : i + 64] for i in range(0, len(message), 64)
        ]
        H: tuple = SHA1_INITIAL_HASH_VALUES

        for block in blocks:
            W: list = []

            for t in range(80):
                if t <= 15:
                    W.append(int.from_bytes(block[t * 4 : (t + 1) * 4], "big"))
                else:
                    val = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]
                    W.append(self._ROTL(val, 1) & self.mod)

            a, b, c, d, e = H

            for t in range(80):
                if t <= 19:
                    f, k = self._ch(b, c, d), 0x5A827999
                elif t <= 39:
                    f, k = self._parity(b, c, d), 0x6ED9EBA1
                elif t <= 59:
                    f, k = self._maj(b, c, d), 0x8F1BBCDC
                else:
                    f, k = self._parity(b, c, d), 0xCA62C1D6

                temp = (self._ROTL(a, 5) + f + e + k + W[t]) & self.mod
                a, b, c, d, e = temp, a, self._ROTL(b, 30), c, d

            H: list = [(x + y) & self.mod for x, y in zip(H, [a, b, c, d, e])]

        return b"".join(h.to_bytes(4, "big") for h in H)[: self.digest_size]

    def __sha224_digest(self, initial_hash_values: tuple[int]) -> bytes:
        message: bytearray = self.pad(
            self._buffer[:], self._counter * 8, self.block_size
        )
        blocks: list[bytearray] = [
            message[i : i + 64] for i in range(0, len(message), 64)
        ]
        H: tuple = initial_hash_values

        for block in blocks:
            W: list[int] = []

            for t in range(64):
                if t <= 15:
                    W.append(int.from_bytes(block[t * 4 : (t * 4) + 4], "big"))
                else:
                    s1 = (
                        self._ROTR(W[t - 2], 17)
                        ^ self._ROTR(W[t - 2], 19)
                        ^ W[t - 2] >> 10
                    )
                    s0 = (
                        self._ROTR(W[t - 15], 7)
                        ^ self._ROTR(W[t - 15], 18)
                        ^ W[t - 15] >> 3
                    )
                    W.append((s1 + W[t - 7] + s0 + W[t - 16]) & self.mod)

            a, b, c, d, e, f, g, h = H

            for t in range(64):
                s1 = self._ROTR(e, 6) ^ self._ROTR(e, 11) ^ self._ROTR(e, 25)
                s0 = self._ROTR(a, 2) ^ self._ROTR(a, 13) ^ self._ROTR(a, 22)
                t1 = (h + s1 + self._ch(e, f, g) + self.K[t] + W[t]) & self.mod
                t2 = (s0 + self._maj(a, b, c)) & self.mod

                h, g, f = g, f, e
                e = (d + t1) & self.mod
                d, c, b = c, b, a
                a = (t1 + t2) & self.mod

            H = [(x + y) & self.mod for x, y in zip(H, [a, b, c, d, e, f, g, h])]

        return b"".join(h.to_bytes(4, "big") for h in H)[: self.digest_size]

    def __sha384_digest(self, initial_hash_values: tuple[int]) -> bytes:
        message: bytearray = self.pad(
            self._buffer[:], self._counter * 8, self.block_size
        )
        blocks: list[bytearray] = [
            message[i : i + 128] for i in range(0, len(message), 128)
        ]
        H: tuple = initial_hash_values

        for block in blocks:
            W: list = []

            for t in range(80):
                if t <= 15:
                    W.append(int.from_bytes(block[t * 8 : (t * 8) + 8], "big"))
                else:
                    s1 = (
                        self._ROTR(W[t - 2], 19)
                        ^ self._ROTR(W[t - 2], 61)
                        ^ W[t - 2] >> 6
                    )
                    s0 = (
                        self._ROTR(W[t - 15], 1)
                        ^ self._ROTR(W[t - 15], 8)
                        ^ W[t - 15] >> 7
                    )

                    W.append((s1 + W[t - 7] + s0 + W[t - 16]) & self.mod)

            a, b, c, d, e, f, g, h = H

            for t in range(80):
                s1 = self._ROTR(e, 14) ^ self._ROTR(e, 18) ^ self._ROTR(e, 41)
                s0 = self._ROTR(a, 28) ^ self._ROTR(a, 34) ^ self._ROTR(a, 39)
                t1 = (h + s1 + self._ch(e, f, g) + self.K[t] + W[t]) & self.mod
                t2 = (s0 + self._maj(a, b, c)) & self.mod

                h, g, f = g, f, e
                e = (d + t1) & self.mod
                d, c, b = c, b, a
                a = (t1 + t2) & self.mod

            H = [(x + y) & self.mod for x, y in zip(H, [a, b, c, d, e, f, g, h])]

        return b"".join(h.to_bytes(8, "big") for h in H)[: self.digest_size]

    def digest(self) -> bytes:
        algo = self.name.lower()

        # Map algorithm → (method, *extra_args)
        dispatch: dict[str, tuple[t.Callable, tuple]] = {
            "sha1": (self.__sha1_digest, ()),
            "sha224": (self.__sha224_digest, (SHA224_INITIAL_HASH_VALUES,)),
            "sha256": (self.__sha224_digest, (SHA256_INITIAL_HASH_VALUES,)),
            "sha384": (self.__sha384_digest, (SHA384_INITIAL_HASH_VALUES,)),
            "sha512": (self.__sha384_digest, (SHA512_INITIAL_HASH_VALUES,)),
            "sha512_224": (self.__sha384_digest, (SHA512_224_INITIAL_HASH_VALUES,)),
            "sha512_256": (self.__sha384_digest, (SHA512_256_INITIAL_HASH_VALUES,)),
        }

        try:
            func, extra = dispatch[algo]
        except KeyError:  # unknown/unsupported algorithm
            raise ValueError(f"Unsupported algorithm: {self.name!r}") from None

        return func(*extra)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def update(self, obj: _t.ReadableBuffer, /) -> None:
        self._buffer.extend(obj)
        self._counter += len(obj)


"""
NOTE: The `usedforsecurity` parameter in the following functions is primarily advisory.  
In most cases, it has no effect.  However,  for insecure algorithms like SHA-1, setting  
`usedforsecurity=True` may raise a warning in security-sensitive environments.
"""


def _shadef(
    digest_size: int, block_size: int, word_bit_length: int
) -> t.Callable[[t.Callable[..., HASH]], t.Callable[..., HASH]]:

    def decorator(func: t.Callable[..., HASH]) -> t.Callable[..., HASH]:

        @wraps(func)
        def wrapper(string: bytes = b"", *, usedforsecurity: bool = True) -> HASH:

            if not isinstance(string, (bytes, bytearray)):
                raise TypeError("Strings must be encoded before hashing")

            h = HASH(
                digest_size=digest_size,
                block_size=block_size,
                word_bit_length=word_bit_length,
                name=func.__name__,
                usedforsecurity=usedforsecurity,
            )

            if string:
                h.update(string)
            return h

        wrapper.digest_size = digest_size
        wrapper.block_size = block_size
        wrapper.name = func.__name__
        return wrapper

    return decorator


@_shadef(digest_size=20, block_size=512, word_bit_length=32)
def sha1(string: _t.ReadableBuffer = b"", *, usedforsecurity: bool = True) -> HASH: ...


@_shadef(digest_size=28, block_size=512, word_bit_length=32)
def sha224(
    string: _t.ReadableBuffer = b"", *, usedforsecurity: bool = True
) -> HASH: ...


@_shadef(digest_size=32, block_size=512, word_bit_length=32)
def sha256(
    string: _t.ReadableBuffer = b"", *, usedforsecurity: bool = True
) -> HASH: ...


@_shadef(digest_size=48, block_size=1024, word_bit_length=64)
def sha384(
    string: _t.ReadableBuffer = b"", *, usedforsecurity: bool = True
) -> HASH: ...


@_shadef(digest_size=64, block_size=1024, word_bit_length=64)
def sha512(
    string: _t.ReadableBuffer = b"", *, usedforsecurity: bool = True
) -> HASH: ...


@_shadef(digest_size=28, block_size=1024, word_bit_length=64)
def sha512_224(
    string: _t.ReadableBuffer = b"", *, usedforsecurity: bool = True
) -> HASH: ...


@_shadef(digest_size=32, block_size=1024, word_bit_length=64)
def sha512_256(
    string: _t.ReadableBuffer = b"", *, usedforsecurity: bool = True
) -> HASH: ...


__all__: list = [var for var in globals().keys() if not var.startswith("_")]
