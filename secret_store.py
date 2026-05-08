import json
import time
from pathlib import Path
from typing import Any, Dict, List

from secret_crypto import b64decode, b64encode, decrypt, derive_master_key, encrypt, sign_token, verify_token


class SecretStore:
    def __init__(self, storage_path: str) -> None:
        self.storage_path = Path(storage_path)
        self.master_key = None
        self._load_or_init()

    def _load_or_init(self) -> None:
        if self.storage_path.exists():
            self._storage = json.loads(self.storage_path.read_text(encoding="utf-8"))
            return

        self._storage = {
            "meta": {
                "status": "sealed",
                "created_at": int(time.time()),
                "algorithm": "xor-stream+hmac-sha256",
                "kdf": "iterated-hmac-sha256",
            },
            "secrets": {},
        }
        self._persist()

    def _persist(self) -> None:
        self.storage_path.write_text(json.dumps(self._storage, ensure_ascii=False, indent=2), encoding="utf-8")

    def seal(self) -> None:
        self.master_key = None
        self._storage["meta"]["status"] = "sealed"
        self._persist()

    def unseal(self, child_keys: List[str]) -> None:
        self.master_key = derive_master_key(child_keys)
        self._storage["meta"]["status"] = "unsealed"
        self._storage["meta"]["last_unsealed_at"] = int(time.time())
        self._persist()

    def is_sealed(self) -> bool:
        return self.master_key is None

    def _ensure_unsealed(self) -> bytes:
        if self.master_key is None:
            raise ValueError("store is sealed")
        return self.master_key

    def put_secret(self, name: str, value: str) -> None:
        master_key = self._ensure_unsealed()
        record_name = name.strip()
        if not record_name:
            raise ValueError("secret name must be non-empty")

        plaintext = value.encode("utf-8")
        aad = record_name.encode("utf-8")
        nonce, ciphertext, tag = encrypt(master_key, plaintext, aad=aad)
        self._storage["secrets"][record_name] = {
            "nonce": b64encode(nonce),
            "ciphertext": b64encode(ciphertext),
            "tag": b64encode(tag),
            "updated_at": int(time.time()),
        }
        self._persist()

    def get_secret(self, name: str) -> str:
        master_key = self._ensure_unsealed()
        if name not in self._storage["secrets"]:
            raise KeyError(name)
        record = self._storage["secrets"][name]
        plaintext = decrypt(
            master_key,
            b64decode(record["nonce"]),
            b64decode(record["ciphertext"]),
            b64decode(record["tag"]),
            aad=name.encode("utf-8"),
        )
        return plaintext.decode("utf-8")

    def list_secrets(self) -> List[str]:
        return sorted(self._storage["secrets"].keys())

    def wrap_secret(self, name: str, ttl_seconds: int) -> str:
        master_key = self._ensure_unsealed()
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if name not in self._storage["secrets"]:
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
