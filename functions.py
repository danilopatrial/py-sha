
from __future__ import annotations

from typing_extensions import deprecated

def rotr(x: int, n: int, w: int) -> int:
    '''Rotate Right (circular right shift) operation'''
    return (x << n) | (x >> (w - n))

def rotl(x: int, n: int, w: int) -> int:
    '''Rotate Left (circular right shift) operation'''
    return (x << n) | (x >> (w - n))


def shr(x: int, n: int) -> int:
    '''Right Shift operation'''
    return x >> n


def choice(x: int, y: int, z: int) -> int:
    '''Choice
    _
    SHA-1 -> 0 <= t <= 19'''
    return (x & y) ^ (~x & z)

def parity(x: int, y: int, z: int) -> int:
    '''Parity
    _
    SHA-1 -> 20 <= t <= 39 and 60 <= t <= 79'''
    return x ^ y ^ z

def majority(x: int, y: int, z: int) -> int:
    '''Majority
    _
    SHA-1 -> 40 <= t <= 59'''
    return (x & y) ^ (x & z) ^ (y & z)


@deprecated('Use `rotr(x, __s1) ^ rotr(x, __s2) ^ rotr(x, __s3)` instead - better readability')
def uSigma0(x: int, __s1: int, __s2: int, __s3: int) -> int:
    return rotr(x, __s1) ^ rotr(x, __s2) ^ rotr(x, __s3)

@deprecated('Use `rotr(x, __s1) ^ rotr(x, __s2) ^ rotr(x, __s3)` instead - better readability')
def uSigma1(x: int, __s1: int, __s2: int, __s3: int) -> int:
    return rotr(x, __s1) ^ rotr(x, __s2) ^ rotr(x, __s3)

@deprecated('Use `rotr(x, __s1) ^ rotr(x, __s2) ^ shr(x, __s3)` instead - better readability')
def sigma0(x: int, __s1: int, __s2: int, __s3: int) -> int:
    return rotr(x, __s1) ^ rotr(x, __s2) ^ shr(x, __s3)

@deprecated('Use `rotr(x, __s1) ^ rotr(x, __s2) ^ shr(x, __s3)` instead - better readability')
def sigma1(x: int, __s1: int, __s2: int, __s3: int) -> int:
    return rotr(x, __s1) ^ rotr(x, __s2) ^ shr(x, __s3)



__all__: list = [var for var in globals().keys() if not var.startswith('_')]