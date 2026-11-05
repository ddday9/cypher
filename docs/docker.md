# Сервер в Docker

Схема:

```
интернет ──:80──►  nginx   (редирект на https; проверка Let's Encrypt → cypher)
         ──:443─►  cypher  ── клиент с ключом ──► туннель
                      └──── все остальные ──► nginx:8080 (сайт из ./site)
```

Снаружи сервер выглядит как обычный сайт на nginx: на 80 — редирект на
https, на 443 — ваш сайт с настоящим сертификатом.

**Сертификат.** cypher сам получает его в Let's Encrypt (сам является
ACME-клиентом, certbot не нужен) и сам продлевает за 30 дней до истечения.
Новый сертификат начинает использоваться сразу, без перезапуска. Проверка
домена идёт через порт 80 (HTTP-01, через nginx) или 443 (TLS-ALPN-01).

## 1. Подготовка

* A-запись домена указывает на IP сервера.
* Открыты входящие TCP-порты **80** и **443**, на них ничего больше не слушает.
* Установлен Docker с плагином compose:

```bash
curl -fsSL https://get.docker.com | sh
```

## 2. Запуск

Скачайте папку `deploy/docker` из релиза или из репозитория:

```bash
mkdir -p ~/cypher && cd ~/cypher && curl -sSL https://github.com/ddday9/cypher/releases/latest/download/cypher-linux-amd64.tar.gz | tar xz --strip-components=3 --wildcards '*/deploy/docker'
```

(если ссылка `latest` не сработала, возьмите архив конкретной версии со
страницы Releases). Затем:

```bash
echo "CYPHER_DOMAIN=example.com" > .env
```

```bash
docker compose up -d
```

```bash
docker compose logs -f cypher
```

В логе при первом запуске будет ссылка `cypher://…` — вставьте её в
cypher-gui (**Серверы → Добавить**). Когда появится строка
`certificate ready … expires=… renews_after=…`, сервер готов.

## 3. Сайт-прикрытие

Папка `site/` отдаётся nginx'ом всем, у кого нет ключа: браузерам,
поисковикам и проверкам цензора. Замените `site/index.html` на свой
правдоподобный сайт. Перезапуск не нужен.

## 4. Пользователи

Без ограничений по трафику и времени: пользователь либо есть, либо отозван.
Изменения применяются работающим сервером за несколько секунд, без
перезапуска; отозванный пользователь отключается сразу.

```bash
docker compose exec cypher cypher user add phone
```

```bash
docker compose exec cypher cypher user list
```

```bash
docker compose exec cypher cypher user link phone
```

```bash
docker compose exec cypher cypher user revoke phone
```

`add` и `link` печатают ссылку `cypher://…` для клиента.

## 5. Обновление

```bash
docker compose pull && docker compose up -d
```

## Переменные

Используются только при первом запуске, когда конфига ещё нет. Дальше
настройки берутся из `/etc/cypher/server.json` в томе `cypher_cypher-data`.

| Переменная | По умолчанию | Что это |
|---|---|---|
| `CYPHER_DOMAIN` | — | домен сервера (обязательно) |
| `CYPHER_EMAIL` | — | email для уведомлений Let's Encrypt |
| `CYPHER_PUBLIC_PORT` | `443` | порт, который попадёт в ссылку |
| `CYPHER_LISTEN` | `:8443` | порт cypher внутри контейнера |
| `CYPHER_ACME_HTTP` | `:8081` (в compose) | куда nginx пересылает проверки HTTP-01 |
| `CYPHER_FALLBACK_PROXY` | `http://nginx:8080` (в compose) | куда отправлять всех без ключа |
| `CYPHER_ACME_DIRECTORY` | Let's Encrypt | другой ACME-сервер (например staging) |

## Безопасность контейнеров

cypher работает от непривилегированного пользователя в образе
`distroless/static` (без shell), файловая система только для чтения, все
capabilities сброшены, `no-new-privileges`. nginx — официальный образ с
файловой системой только для чтения.

## Без Docker

`sudo ./deploy/install-server.sh --domain example.com` ставит то же самое
как службы systemd: cypher и nginx из пакетов дистрибутива (см. [setup.md](setup.md)).
