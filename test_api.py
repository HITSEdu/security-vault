import os
import sys
import tempfile
import unittest
from importlib import import_module, reload
from pathlib import Path

from fastapi.testclient import TestClient

CHILD_KEYS = ["share-1", "share-2", "share-3"]


class VaultApiRBACTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        os.environ["SECRET_STORAGE_PATH"] = str(Path(self.tmp_dir.name) / "vault.db")
        os.environ["SECRET_API_KEYS"] = (
            '{"admin-token":"admin","writer-token":"writer","reader-token":"reader"}'
        )
        if "main" in sys.modules:
            self.main = reload(sys.modules["main"])
        else:
            self.main = import_module("main")
        self.client = TestClient(self.main.app)
        self.headers = {
            "admin": {"X-API-Key": "admin-token"},
            "writer": {"X-API-Key": "writer-token"},
            "reader": {"X-API-Key": "reader-token"},
        }

    def tearDown(self) -> None:
        self.client.close()
        self.tmp_dir.cleanup()
        os.environ.pop("SECRET_STORAGE_PATH", None)
        os.environ.pop("SECRET_API_KEYS", None)

    def test_role_matrix(self) -> None:
        unseal_response = self.client.post(
            "/v1/unseal",
            headers=self.headers["admin"],
            json={"child_keys": CHILD_KEYS},
        )
        self.assertEqual(unseal_response.status_code, 200)

        writer_put = self.client.put(
            "/v1/secrets/db_password",
            headers=self.headers["writer"],
            json={"value": "secret-01"},
        )
        self.assertEqual(writer_put.status_code, 200)

        reader_get = self.client.get("/v1/secrets/db_password", headers=self.headers["reader"])
        self.assertEqual(reader_get.status_code, 200)
        self.assertEqual(reader_get.json()["value"], "secret-01")

        forbidden_put = self.client.put(
            "/v1/secrets/db_password",
            headers=self.headers["reader"],
            json={"value": "should-fail"},
        )
        self.assertEqual(forbidden_put.status_code, 403)

        forbidden_status = self.client.get("/v1/status", headers=self.headers["writer"])
        self.assertEqual(forbidden_status.status_code, 403)

    def test_whoami_returns_role(self) -> None:
        response = self.client.get("/v1/whoami", headers=self.headers["writer"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"role": "writer"})


if __name__ == "__main__":
    unittest.main()
