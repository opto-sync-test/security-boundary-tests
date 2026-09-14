import unittest

from deep_tests.security_model import BoundaryViolation, normalize_relative_path, validate_outbound_url


class OptoSyncDomainSecurityTests(unittest.TestCase):
    def test_sync_database_paths_reject_encoded_parent_escape(self) -> None:
        for value in ("sqlite/%2e%2e/secrets.db", "indexeddb/%252e%252e/token", "%2E%2E/opto-sync.db"):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)

    def test_sync_gateway_urls_reject_authority_confusion(self) -> None:
        allowed = {"sync.example.test"}
        for value in (
            "//sync.example.test/push",
            "https://sync.example.test@attacker.invalid/push",
            "https://attacker.invalid/sync.example.test/push",
        ):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)


if __name__ == "__main__":
    unittest.main()
