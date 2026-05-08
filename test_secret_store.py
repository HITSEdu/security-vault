import tempfile
import time
import unittest
from pathlib import Path

from secret_store import SecretStore


CHILD_KEYS = ["share-1", "share-2", "share-3"]


class SecretStoreTestCase(unittest.TestCase):
    def test_store_requires_unseal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = str(Path(tmp_dir) / "vault.json")
            store = SecretStore(path)
            with self.assertRaises(ValueError):
                store.put_secret("db_password", "123")

    def test_put_get_and_seal_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = str(Path(tmp_dir) / "vault.json")
            store = SecretStore(path)
            store.unseal(CHILD_KEYS)
            store.put_secret("db_password", "123")
            self.assertEqual(store.get_secret("db_password"), "123")

            store.seal()
            with self.assertRaises(ValueError):
                store.get_secret("db_password")

            store.unseal(CHILD_KEYS)
            self.assertEqual(store.get_secret("db_password"), "123")

    def test_wrap_and_unwrap_with_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = str(Path(tmp_dir) / "vault.json")
            store = SecretStore(path)
            store.unseal(CHILD_KEYS)
            store.put_secret("api_key", "value-001")

            token = store.wrap_secret("api_key", ttl_seconds=1)
            unwrapped = store.unwrap_secret(token)
            self.assertEqual(unwrapped["value"], "value-001")

            time.sleep(2)
            with self.assertRaises(ValueError):
                store.unwrap_secret(token)


if __name__ == "__main__":
    unittest.main()
