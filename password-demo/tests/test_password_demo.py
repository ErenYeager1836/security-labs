"""
Unit tests for password-demo hashing, verification, salting, and benchmarks.
"""

import unittest
from unittest.mock import patch

from password_demo.benchmark import benchmark_algorithm, run_full_benchmark
from password_demo.cli import main
from password_demo.hasher import PasswordHasher
from password_demo.salting import run_salting_demonstration


class TestPasswordHasher(unittest.TestCase):
    def test_md5_hashing_and_verification(self):
        pw = "TestPassword123!"
        h, elapsed = PasswordHasher.hash_md5(pw)
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 32)
        self.assertGreaterEqual(elapsed, 0.0)

        # Correct password verification
        self.assertTrue(PasswordHasher.verify_md5(pw, h))
        # Wrong password fails
        self.assertFalse(PasswordHasher.verify_md5("WrongPassword!", h))

    def test_bcrypt_hashing_and_verification(self):
        pw = "SuperSecretBcryptPassword"
        # Use low cost factor (4) for fast unit test execution
        h, elapsed = PasswordHasher.hash_bcrypt(pw, cost=4)
        self.assertTrue(h.startswith("$2b$04$"))
        self.assertGreater(elapsed, 0.0)

        self.assertTrue(PasswordHasher.verify_bcrypt(pw, h))
        self.assertFalse(PasswordHasher.verify_bcrypt("WrongBcrypt", h))

    def test_argon2_hashing_and_verification(self):
        pw = "Argon2RobustPassphrase"
        # Low parameters for unit testing
        h, elapsed = PasswordHasher.hash_argon2(pw, time_cost=1, memory_cost_kib=1024, parallelism=1)
        self.assertTrue(h.startswith("$argon2id$"))
        self.assertGreater(elapsed, 0.0)

        self.assertTrue(PasswordHasher.verify_argon2(pw, h))
        self.assertFalse(PasswordHasher.verify_argon2("WrongArgon2", h))


class TestSalting(unittest.TestCase):
    def test_salting_uniqueness_and_rainbow_table_mitigation(self):
        res = run_salting_demonstration("IdenticalPasswordForEachUser")

        # Unsalted: all hashes must be identical
        self.assertTrue(res["all_unsalted_hashes_identical"])
        unsalted_hashes = [r["hash"] for r in res["unsalted"]]
        self.assertEqual(len(set(unsalted_hashes)), 1)

        # Salted: all hashes must be unique
        self.assertTrue(res["all_salted_hashes_unique"])
        salted_hashes = [r["hash"] for r in res["salted"]]
        self.assertEqual(len(set(salted_hashes)), 3)


class TestBenchmark(unittest.TestCase):
    def test_benchmark_algorithm(self):
        res = benchmark_algorithm("MD5-Test", lambda pw: PasswordHasher.hash_md5(pw), iterations=5)
        self.assertEqual(res["algorithm"], "MD5-Test")
        self.assertEqual(res["iterations"], 5)
        self.assertGreater(res["hashes_per_second"], 0.0)

    @patch("sys.stdout")
    def test_cli_execution(self, mock_stdout):
        exit_code = main(["--salting"])
        self.assertEqual(exit_code, 0)

        exit_code_json = main(["--salting", "--json"])
        self.assertEqual(exit_code_json, 0)


if __name__ == "__main__":
    unittest.main()
