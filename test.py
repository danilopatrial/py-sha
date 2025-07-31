# test.py
# Unit test

import unittest
import hashlib

from main import (
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    sha512_224,
    sha512_256,
)

class SecureHashStandardTest(unittest.TestCase):
    def setUp(self):
        self.test_vectors = [
            b"",
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            b"1234567890" * 8,
        ]

    def test_sha1(self):
        for msg in self.test_vectors:
            expected = hashlib.sha1(msg).hexdigest()
            result = sha1(msg).hexdigest()
            self.assertEqual(result, expected, f"Failed for message: {msg}")

    def test_sha224(self):
        for msg in self.test_vectors:
            expected = hashlib.sha224(msg).hexdigest()
            result = sha224(msg).hexdigest()
            self.assertEqual(result, expected, f"Failed for message: {msg}")

    def test_sha256(self):
        for msg in self.test_vectors:
            expected = hashlib.sha256(msg).hexdigest()
            result = sha256(msg).hexdigest()
            self.assertEqual(result, expected, f"Failed for message: {msg}")

    def test_sha384(self):
        for msg in self.test_vectors:
            expected = hashlib.sha384(msg).hexdigest()
            result = sha384(msg).hexdigest()
            self.assertEqual(result, expected, f"Failed for message: {msg}")

    def test_sha512(self):
        for msg in self.test_vectors:
            expected = hashlib.sha512(msg).hexdigest()
            result = sha512(msg).hexdigest()
            self.assertEqual(result, expected, f"Failed for message: {msg}")

    def test_sha512_224(self):
        for msg in self.test_vectors:
            expected = hashlib.new("sha512_224", msg).hexdigest()
            result = sha512_224(msg).hexdigest()
            self.assertEqual(result, expected, f"Failed for message: {msg}")

    def test_sha512_256(self):
        for msg in self.test_vectors:
            expected = hashlib.new("sha512_256", msg).hexdigest()
            result = sha512_256(msg).hexdigest()
            self.assertEqual(result, expected, f"Failed for message: {msg}")


if __name__ == "__main__":
    unittest.main()
