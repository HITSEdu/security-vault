from pathlib import Path

from secret_store import SecretStore


STORAGE_PATH = "secrets-db.json"
CHILD_KEYS = ["bank-fragment-A", "bank-fragment-B", "bank-fragment-C"]


def main() -> None:
    storage = Path(STORAGE_PATH)
    if storage.exists():
        storage.unlink()

    store = SecretStore(STORAGE_PATH)
    store.unseal(CHILD_KEYS)
    store.put_secret("db_password", "s3cr3t-pass")
    store.put_secret("partner_api_key", "partner-token-001")

    print("Секреты в хранилище:", ", ".join(store.list_secrets()))
    print("db_password:", store.get_secret("db_password"))

    token = store.wrap_secret("partner_api_key", ttl_seconds=30)
    print("Wrap token:", token)
    unwrapped = store.unwrap_secret(token)
    print("Unwrapped secret:", unwrapped["secret_name"], "=", unwrapped["value"])

    store.seal()
    print("Хранилище снова sealed.")


if __name__ == "__main__":
    main()
