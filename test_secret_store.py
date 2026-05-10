import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from secret_store import SecretStore


CHILD_KEYS = ["share-1", "share-2", "share-3"]


class SecretStoreTestCase(unittest.TestCase):
    def test_store_requires_unseal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = str(Path(tmp_dir) / "vault.db")
            store = SecretStore(path)
            with self.assertRaises(ValueError):
                store.put_secret("db_password", "123")

    def test_put_get_and_seal_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = str(Path(tmp_dir) / "vault.db")
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
            path = str(Path(tmp_dir) / "vault.db")
            store = SecretStore(path)
            store.unseal(CHILD_KEYS)
            store.put_secret("api_key", "value-001")

            token = store.wrap_secret("api_key", ttl_seconds=1)
            unwrapped = store.unwrap_secret(token)
            self.assertEqual(unwrapped["value"], "value-001")

            time.sleep(2)
            with self.assertRaises(ValueError):
                store.unwrap_secret(token)

    def test_storage_is_sqlite_and_persists_between_instances(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "vault.db"
            first_store = SecretStore(str(path))
            first_store.unseal(CHILD_KEYS)
            first_store.put_secret("service_token", "abc-123")
            first_store.seal()

            second_store = SecretStore(str(path))
            second_store.unseal(CHILD_KEYS)
            self.assertEqual(second_store.get_secret("service_token"), "abc-123")

            with sqlite3.connect(path) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }

            self.assertIn("meta", tables)
            self.assertIn("secrets", tables)


if __name__ == "__main__":
    unittest.main()
