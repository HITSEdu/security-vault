# Security Vault API

Проект переделан из локального скрипта в HTTP API сервис, который можно поднять на сервере или в Docker.

Секреты не читаются приложением напрямую из кода. Доступ к ним идет через API, а сами значения хранятся в зашифрованном виде в SQLite-базе внутри тома контейнера.

## Что есть

- HTTP API на `FastAPI`
- `main.py` как entrypoint сервера
- SQLite storage для секретов и служебных метаданных
- `seal / unseal` через мастер-ключ из нескольких дочерних ключей
- `wrap / unwrap` токенов с TTL
- RBAC по API-ключам с ролями `admin`, `writer`, `reader`
- Dockerfile и `docker-compose.yml`

## Структура

- `main.py` - HTTP API и RBAC
- `secret_store.py` - логика хранилища на SQLite
- `secret_crypto.py` - KDF, шифрование и подпись токенов
- `test_secret_store.py` - unit-тесты storage
- `test_api.py` - тесты RBAC и API
- `Dockerfile` - сборка контейнера
- `docker-compose.yml` - локальный запуск сервиса

## Как это работает

### 1. Хранение

Секреты сохраняются в SQLite, но не в открытом виде. Для каждого секрета в таблице `secrets` хранятся:

- `name`
- `nonce`
- `ciphertext`
- `tag`
- `updated_at`

В таблице `meta` лежат служебные поля вроде `status`, `created_at`, `last_unsealed_at`.

Само значение секрета на диск в открытом виде не пишется.

### 2. Init / Unseal

Сервис после старта находится в состоянии `sealed`, но до первой инициализации он еще и `not initialized`.

Сначала администратор один раз вызывает `POST /v1/init` и передает набор дочерних ключей:

```json
{
  "child_keys": ["share-1", "share-2", "share-3"]
}
```

Из них вычисляется мастер-ключ, а в `meta` сохраняется только verifier этого ключа. Сам набор `child_keys`
сервис не хранит.

После `POST /v1/seal` мастер-ключ удаляется из памяти. Чтобы снова открыть vault, нужно вызвать
`POST /v1/unseal` с тем же набором `child_keys`. Сервис заново вычислит мастер-ключ и сравнит его verifier
с сохраненным значением.

Если vault не был инициализирован, `unseal` вернет ошибку `vault is not initialized`.
Если передан другой набор `child_keys`, `unseal` вернет `invalid child keys`.

### 3. Шифрование

Сейчас используется учебная схема:

- мастер-ключ вычисляется через последовательный `HMAC-SHA256`
- для каждого секрета генерируется случайный `nonce`
- plaintext шифруется XOR-потоком на базе `SHA-256`
- целостность защищается через `HMAC-SHA256`

Для production это лучше заменить на готовую AEAD-схему, например `AES-GCM` или `ChaCha20-Poly1305`.

### 4. Wrap / unwrap

`POST /v1/secrets/{name}/wrap` выдает токен со сроком жизни. Эндпоинт доступен `admin` и `writer`.

Токен содержит:

- имя секрета
- время выдачи
- `exp`

Токен подписывается мастер-ключом. `POST /v1/unwrap` не требует API-ключа: он проверяет подпись и TTL, затем возвращает секрет только по самому токену.

### 5. RBAC

Доступ задается через переменную окружения `SECRET_API_KEYS` в виде JSON-объекта, где ключом является `sha256`-хэш API-токена, а значением - роль:

```json
{
  "sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a": "admin",
  "sha256:3590c0a59f72ce02700194a05f228a725c1f135a6dcb3ded9b2d86ab6a6f52cb": "writer",
  "sha256:ba5005a40cf5212e4ac0190104cc127edab013294bb71279a975b27a80982d45": "reader"
}
```

Сам клиент по-прежнему отправляет обычный токен в `X-API-Key`. Сервис на своей стороне считает `sha256` и ищет совпадение в `SECRET_API_KEYS`.

Посчитать хэш токена можно так:

```bash
python3 - <<'PY'
import hashlib
token = "admin-token"
print("sha256:" + hashlib.sha256(token.encode()).hexdigest())
PY
```

Матрица прав:

- `admin` - `status`, `init`, `unseal`, `seal`, чтение, запись, `wrap`
- `writer` - чтение, запись, `wrap`
- `reader` - чтение, список секретов, `whoami`
- `unwrap` - доступен без API-ключа, если есть валидный wrap-токен

Есть обратная совместимость: если `SECRET_API_KEYS` не задан, используется старый `SECRET_API_TOKEN` как `admin`.

## Локальный запуск

Сервис может стартовать и без `.env`. В этом случае используются значения по умолчанию:

- `SECRET_STORAGE_PATH=./data/secrets.db`
- `SECRET_API_TOKEN=change-me-admin`

Но для RBAC лучше использовать `.env` на основе `.env.example`.

### Вариант 1. Быстрый запуск без `.env`

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Тогда для запросов используй ключ:

```bash
X-API-Key: change-me-admin
```

### Вариант 2. Запуск с `.env`

```bash
cp .env.example .env
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
set -a
. ./.env
set +a
uvicorn main:app --reload
```

### Минимальный `.env`

```env
SECRET_STORAGE_PATH=./data/secrets.db
SECRET_API_KEYS='{"sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a":"admin","sha256:3590c0a59f72ce02700194a05f228a725c1f135a6dcb3ded9b2d86ab6a6f52cb":"writer","sha256:ba5005a40cf5212e4ac0190104cc127edab013294bb71279a975b27a80982d45":"reader"}'
```

### Старый режим с одним ключом

```env
SECRET_STORAGE_PATH=./data/secrets.db
SECRET_API_TOKEN=change-me-admin
```

### Базовый локальный запуск

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

## Docker

```bash
docker compose up --build
```

По умолчанию сервис поднимается на `http://localhost:8000`.

Переменные окружения:

- `SECRET_STORAGE_PATH` - путь к SQLite-файлу
- `SECRET_API_KEYS` - JSON-объект вида `sha256:<hex> -> role`
- `SECRET_API_TOKEN` - legacy fallback для одного `admin` ключа

## Как проверить, что все работает

Ниже полный ручной сценарий проверки для RBAC-режима из `.env.example`.

### 1. Проверить, что сервис поднялся

```bash
curl http://localhost:8000/health
```

Ожидаемый ответ:

```json
{"status":"ok"}
```

### 2. Проверить, что ключи и роли читаются

```bash
curl http://localhost:8000/v1/whoami \
  -H "X-API-Key: admin-token"
```

```bash
curl http://localhost:8000/v1/whoami \
  -H "X-API-Key: writer-token"
```

```bash
curl http://localhost:8000/v1/whoami \
  -H "X-API-Key: reader-token"
```

Ожидаемо вернутся роли `admin`, `writer`, `reader`.

### 3. Проверить, что до unseal секреты недоступны

```bash
curl -X PUT http://localhost:8000/v1/secrets/db_password \
  -H "Content-Type: application/json" \
  -H "X-API-Key: writer-token" \
  -d '{"value":"super-secret-password"}'
```

Ожидаемо будет ошибка `store is sealed`.

### 4. Инициализировать vault

```bash
curl -X POST http://localhost:8000/v1/init \
  -H "Content-Type: application/json" \
  -H "X-API-Key: admin-token" \
  -d '{"child_keys":["share-1","share-2","share-3"]}'
```

Ожидаемый ответ:

```json
{"status":"initialized"}
```

### 5. Сделать unseal

Сначала можно явно запечатать vault:

```bash
curl -X POST http://localhost:8000/v1/seal \
  -H "X-API-Key: admin-token"
```

Затем открыть его снова:

```bash
curl -X POST http://localhost:8000/v1/unseal \
  -H "Content-Type: application/json" \
  -H "X-API-Key: admin-token" \
  -d '{"child_keys":["share-1","share-2","share-3"]}'
```

Ожидаемый ответ:

```json
{"status":"unsealed"}
```

### 6. Записать секрет

```bash
curl -X PUT http://localhost:8000/v1/secrets/db_password \
  -H "Content-Type: application/json" \
  -H "X-API-Key: writer-token" \
  -d '{"value":"super-secret-password"}'
```

### 7. Прочитать секрет

```bash
curl http://localhost:8000/v1/secrets/db_password \
  -H "X-API-Key: reader-token"
```

### 8. Проверить список секретов

```bash
curl http://localhost:8000/v1/secrets \
  -H "X-API-Key: reader-token"
```

### 9. Проверить wrap / unwrap

Создать токен:

```bash
curl -X POST http://localhost:8000/v1/secrets/db_password/wrap \
  -H "Content-Type: application/json" \
  -H "X-API-Key: writer-token" \
  -d '{"ttl_seconds":60}'
```

Из ответа возьми `token`, затем:

```bash
curl -X POST http://localhost:8000/v1/unwrap \
  -H "Content-Type: application/json" \
  -d '{"token":"PASTE_TOKEN_HERE"}'
```

### 10. Проверить RBAC-ограничения

`reader` не должен уметь писать:

```bash
curl -X PUT http://localhost:8000/v1/secrets/forbidden \
  -H "Content-Type: application/json" \
  -H "X-API-Key: reader-token" \
  -d '{"value":"123"}'
```

Ожидаемый HTTP статус: `403`.

`writer` не должен видеть `/v1/status`:

```bash
curl http://localhost:8000/v1/status \
  -H "X-API-Key: writer-token"
```

Ожидаемый HTTP статус: `403`.

`admin` должен видеть `/v1/status`:

```bash
curl http://localhost:8000/v1/status \
  -H "X-API-Key: admin-token"
```

### 11. Проверить seal

```bash
curl -X POST http://localhost:8000/v1/seal \
  -H "X-API-Key: admin-token"
```

После этого чтение секрета снова должно падать с ошибкой `store is sealed`.

## Примеры API

### Проверка сервиса

```bash
curl http://localhost:8000/health
```

### Проверить роль ключа

```bash
curl http://localhost:8000/v1/whoami \
  -H "X-API-Key: reader-token"
```

### Unseal

```bash
curl -X POST http://localhost:8000/v1/unseal \
  -H "Content-Type: application/json" \
  -H "X-API-Key: admin-token" \
  -d '{"child_keys":["share-1","share-2","share-3"]}'
```

### Сохранить секрет

```bash
curl -X PUT http://localhost:8000/v1/secrets/db_password \
  -H "Content-Type: application/json" \
  -H "X-API-Key: writer-token" \
  -d '{"value":"super-secret-password"}'
```

### Получить секрет

```bash
curl http://localhost:8000/v1/secrets/db_password \
  -H "X-API-Key: reader-token"
```

### Создать временный токен

```bash
curl -X POST http://localhost:8000/v1/secrets/db_password/wrap \
  -H "Content-Type: application/json" \
  -H "X-API-Key: writer-token" \
  -d '{"ttl_seconds":60}'
```

### Развернуть токен

```bash
curl -X POST http://localhost:8000/v1/unwrap \
  -H "Content-Type: application/json" \
  -H "X-API-Key: reader-token" \
  -d '{"token":"PASTE_TOKEN_HERE"}'
```

## Тесты

```bash
python3 -m unittest -v test_secret_store.py test_api.py
```

Для ручной end-to-end проверки запущенного сервиса:

```bash
chmod +x check_endpoints.sh
./check_endpoints.sh
```

Если токены или адрес отличаются, можно переопределить их через env:

```bash
BASE_URL=http://localhost:8000 \
ADMIN_TOKEN=admin-token \
WRITER_TOKEN=writer-token \
READER_TOKEN=reader-token \
./check_endpoints.sh
```

## Ограничения

Это уже серверный вариант, но не production-grade vault:

- RBAC пока только по статическим API-ключам из env, без пользователей и групп
- нет аудита запросов
- нет ротации ключей
- криптография учебная, а не промышленная

Следующий шаг к более серьезной системе: аудит, ротация ключей, нормальные identities и библиотечная AEAD-криптография.
