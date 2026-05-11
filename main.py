import json
import os
import hashlib
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Callable, Dict, List

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from secret_store import SecretStore


DEFAULT_STORAGE_PATH = os.getenv("SECRET_STORAGE_PATH", "./data/secrets.db")
DEFAULT_API_TOKEN = os.getenv("SECRET_API_TOKEN", "change-me-admin")


def hash_api_key(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


DEFAULT_API_KEYS = json.dumps({hash_api_key(DEFAULT_API_TOKEN): "admin"})


class UnsealRequest(BaseModel):
    child_keys: List[str] = Field(min_length=2)


class PutSecretRequest(BaseModel):
    value: str


class WrapSecretRequest(BaseModel):
    ttl_seconds: int = Field(gt=0)


class TokenRequest(BaseModel):
    token: str


@dataclass(frozen=True)
class AuthContext:
    token: str
    role: str


def load_api_keys() -> Dict[str, str]:
    raw_config = os.getenv("SECRET_API_KEYS", DEFAULT_API_KEYS)
    try:
        parsed = json.loads(raw_config)
    except json.JSONDecodeError as exc:
        raise RuntimeError("SECRET_API_KEYS must be a valid JSON object") from exc

    if not isinstance(parsed, dict) or not parsed:
        raise RuntimeError("SECRET_API_KEYS must be a non-empty JSON object")

    allowed_roles = {"admin", "writer", "reader"}
    api_keys: Dict[str, str] = {}
    for token_hash, role in parsed.items():
        if not isinstance(token_hash, str) or not token_hash.strip():
            raise RuntimeError("SECRET_API_KEYS contains an empty API key hash")
        if not token_hash.startswith("sha256:"):
            raise RuntimeError("SECRET_API_KEYS keys must use sha256:<hex> format")
        digest = token_hash.removeprefix("sha256:")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise RuntimeError("SECRET_API_KEYS contains an invalid sha256 hash")
        if role not in allowed_roles:
            raise RuntimeError("SECRET_API_KEYS contains an unsupported role")
        api_keys[token_hash] = role
    return api_keys


def require_role(api_keys: Dict[str, str], allowed_roles: set[str]) -> Callable[[str], AuthContext]:
    def dependency(x_api_key: str = Header(..., alias="X-API-Key")) -> AuthContext:
        role = api_keys.get(hash_api_key(x_api_key))
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid api key",
            )
        if role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role '{role}' cannot access this endpoint",
            )
        return AuthContext(token=x_api_key, role=role)

    return dependency


def _raise_http_error(exc: Exception) -> None:
    if isinstance(exc, KeyError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc).strip("'")) from exc
    if isinstance(exc, ValueError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    raise exc


def create_app() -> FastAPI:
    store = SecretStore(os.getenv("SECRET_STORAGE_PATH", DEFAULT_STORAGE_PATH))
    api_keys = load_api_keys()

    require_admin = require_role(api_keys, {"admin"})
    require_writer = require_role(api_keys, {"admin", "writer"})
    require_reader = require_role(api_keys, {"admin", "writer", "reader"})

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        store.seal()

    app = FastAPI(
        title="Security Vault API",
        version="1.1.0",
        description="HTTP API for encrypted secret storage with SQLite backend and RBAC.",
        lifespan=lifespan,
    )
    app.state.store = store
    app.state.api_keys = dict(api_keys)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/v1/status")
    def get_status(_: AuthContext = Depends(require_admin)) -> dict:
        return store.status()

    @app.post("/v1/init")
    def initialize_store(payload: UnsealRequest, _: AuthContext = Depends(require_admin)) -> dict:
        try:
            store.initialize(payload.child_keys)
            return {"status": "initialized"}
        except Exception as exc:
            _raise_http_error(exc)

    @app.get("/v1/whoami")
    def whoami(context: AuthContext = Depends(require_reader)) -> dict:
        return {"role": context.role}

    @app.post("/v1/unseal")
    def unseal_store(payload: UnsealRequest, _: AuthContext = Depends(require_admin)) -> dict:
        try:
            store.unseal(payload.child_keys)
            return {"status": "unsealed"}
        except Exception as exc:
            _raise_http_error(exc)

    @app.post("/v1/seal")
    def seal_store(_: AuthContext = Depends(require_admin)) -> dict:
        store.seal()
        return {"status": "sealed"}

    @app.get("/v1/secrets")
    def list_secrets(_: AuthContext = Depends(require_reader)) -> dict:
        return {"secrets": store.list_secrets()}

    @app.put("/v1/secrets/{name}")
    def put_secret(name: str, payload: PutSecretRequest, _: AuthContext = Depends(require_writer)) -> dict:
        try:
            store.put_secret(name, payload.value)
            return {"status": "stored", "secret_name": name}
        except Exception as exc:
            _raise_http_error(exc)

    @app.get("/v1/secrets/{name}")
    def get_secret(name: str, _: AuthContext = Depends(require_reader)) -> dict:
        try:
            return {"secret_name": name, "value": store.get_secret(name)}
        except Exception as exc:
            _raise_http_error(exc)

    @app.post("/v1/secrets/{name}/wrap")
    def wrap_secret(name: str, payload: WrapSecretRequest, _: AuthContext = Depends(require_writer)) -> dict:
        try:
            token = store.wrap_secret(name, payload.ttl_seconds)
            return {"secret_name": name, "token": token}
        except Exception as exc:
            _raise_http_error(exc)

    @app.post("/v1/unwrap")
    def unwrap_secret(payload: TokenRequest) -> dict:
        try:
            return store.unwrap_secret(payload.token)
        except Exception as exc:
            _raise_http_error(exc)

    return app


app = create_app()
