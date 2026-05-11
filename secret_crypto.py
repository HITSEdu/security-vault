import base64
import hashlib
import hmac
import secrets
from typing import Tuple


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def derive_master_key(child_keys: list[str]) -> bytes:
    if len(child_keys) < 2:
        raise ValueError("at least two child keys are required")
    normalized = [key.strip().encode("utf-8") for key in child_keys]
    if any(not item for item in normalized):
        raise ValueError("child keys must be non-empty")

    digest = hashlib.sha256(b"vault-master-v1").digest()
    for child_key in normalized:
        digest = hmac.new(digest, child_key, hashlib.sha256).digest()
    return digest


def derive_master_key_verifier(master_key: bytes) -> str:
    verifier = hmac.new(master_key, b"vault-unseal-verifier-v1", hashlib.sha256).digest()
    return b64encode(verifier)


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    blocks = []
    counter = 0
    while sum(len(block) for block in blocks) < length:
        counter_bytes = counter.to_bytes(4, "big")
        blocks.append(hashlib.sha256(key + nonce + counter_bytes).digest())
        counter += 1
    return b"".join(blocks)[:length]


def encrypt(master_key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
    nonce = secrets.token_bytes(16)
    stream = _keystream(master_key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hmac.new(master_key, aad + nonce + ciphertext, hashlib.sha256).digest()
    return nonce, ciphertext, tag


def decrypt(master_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    expected = hmac.new(master_key, aad + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("secret integrity check failed")
    stream = _keystream(master_key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream))


def sign_token(signing_key: bytes, payload: bytes) -> str:
    signature = hmac.new(signing_key, payload, hashlib.sha256).digest()
    return b64encode(signature)


def verify_token(signing_key: bytes, payload: bytes, signature: str) -> bool:
    expected = hmac.new(signing_key, payload, hashlib.sha256).digest()
    return hmac.compare_digest(expected, b64decode(signature))
