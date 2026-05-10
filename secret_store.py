import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from secret_crypto import b64decode, b64encode, decrypt, derive_master_key, encrypt, sign_token, verify_token


class SecretStore:
    def __init__(self, storage_path: str) -> None:
        self.storage_path = Path(storage_path)
        self.master_key: Optional[bytes] = None
        self._lock = threading.RLock()
        self._initialize_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.storage_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_db(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    name TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            connection.commit()

        defaults = {
            "status": "sealed",
            "created_at": str(int(time.time())),
            "algorithm": "xor-stream+hmac-sha256",
            "kdf": "iterated-hmac-sha256",
        }
        with self._lock:
            for key, value in defaults.items():
                self._set_meta_if_missing(key, value)
            self._set_meta("status", "sealed")

    def _set_meta_if_missing(self, key: str, value: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)",
                (key, value),
            )
            connection.commit()

    def _set_meta(self, key: str, value: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO meta(key, value) VALUES(?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )
            connection.commit()

    def _get_meta(self) -> Dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute("SELECT key, value FROM meta").fetchall()
        return {str(row["key"]): str(row["value"]) for row in rows}

    def seal(self) -> None:
        with self._lock:
            self.master_key = None
            self._set_meta("status", "sealed")

    def unseal(self, child_keys: List[str]) -> None:
        with self._lock:
            self.master_key = derive_master_key(child_keys)
            self._set_meta("status", "unsealed")
            self._set_meta("last_unsealed_at", str(int(time.time())))

    def is_sealed(self) -> bool:
        return self.master_key is None

    def _ensure_unsealed(self) -> bytes:
        if self.master_key is None:
            raise ValueError("store is sealed")
        return self.master_key

    def put_secret(self, name: str, value: str) -> None:
        with self._lock:
            master_key = self._ensure_unsealed()
            record_name = name.strip()
            if not record_name:
                raise ValueError("secret name must be non-empty")

            plaintext = value.encode("utf-8")
            aad = record_name.encode("utf-8")
            nonce, ciphertext, tag = encrypt(master_key, plaintext, aad=aad)

            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO secrets(name, nonce, ciphertext, tag, updated_at)
                    VALUES(?, ?, ?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        nonce = excluded.nonce,
                        ciphertext = excluded.ciphertext,
                        tag = excluded.tag,
                        updated_at = excluded.updated_at
                    """,
                    (
                        record_name,
                        b64encode(nonce),
                        b64encode(ciphertext),
                        b64encode(tag),
                        int(time.time()),
                    ),
                )
                connection.commit()

    def get_secret(self, name: str) -> str:
        with self._lock:
            master_key = self._ensure_unsealed()
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT nonce, ciphertext, tag FROM secrets WHERE name = ?",
                    (name,),
                ).fetchone()

            if row is None:
                raise KeyError(name)

            plaintext = decrypt(
                master_key,
                b64decode(str(row["nonce"])),
                b64decode(str(row["ciphertext"])),
                b64decode(str(row["tag"])),
                aad=name.encode("utf-8"),
            )
            return plaintext.decode("utf-8")

    def list_secrets(self) -> List[str]:
        with self._lock:
            with self._connect() as connection:
                rows = connection.execute("SELECT name FROM secrets ORDER BY name ASC").fetchall()
            return [str(row["name"]) for row in rows]

    def wrap_secret(self, name: str, ttl_seconds: int) -> str:
        with self._lock:
            master_key = self._ensure_unsealed()
            if ttl_seconds <= 0:
                raise ValueError("ttl_seconds must be positive")
            if name not in self.list_secrets():
                raise KeyError(name)

            now = int(time.time())
            payload = {
                "secret_name": name,
                "exp": now + ttl_seconds,
                "issued_at": now,
            }
            raw_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            signature = sign_token(master_key, raw_payload)
            token = {"payload": payload, "signature": signature}
            return b64encode(json.dumps(token, sort_keys=True, separators=(",", ":")).encode("utf-8"))

    def unwrap_secret(self, token: str) -> Dict[str, Any]:
        with self._lock:
            master_key = self._ensure_unsealed()
            token_data = json.loads(b64decode(token).decode("utf-8"))
            payload = token_data["payload"]
            raw_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if not verify_token(master_key, raw_payload, token_data["signature"]):
                raise ValueError("invalid token signature")
            if int(time.time()) > int(payload["exp"]):
                raise ValueError("token expired")

            secret_name = payload["secret_name"]
            return {
                "secret_name": secret_name,
                "value": self.get_secret(secret_name),
                "expires_at": int(payload["exp"]),
            }

    def status(self) -> Dict[str, Any]:
        with self._lock:
            meta = self._get_meta()
            normalized_meta: Dict[str, Any] = {}
            for key, value in meta.items():
                if value.isdigit():
                    normalized_meta[key] = int(value)
                else:
                    normalized_meta[key] = value

            return {
                "sealed": self.is_sealed(),
                "secret_count": len(self.list_secrets()),
                "meta": normalized_meta,
            }
