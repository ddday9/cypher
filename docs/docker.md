# Сервер в Docker

Всё, что нужно на сервере, — Docker и домен. Сертификат Let's Encrypt сервер
получает и продлевает сам прямо на порту 443 (проверка TLS-ALPN-01), поэтому
nginx, certbot и порт 80 не нужны.

## 1. Подготовка

* A-запись домена указывает на IP сервера.
* Открыт входящий TCP-порт **443**; на нём ничего больше не слушает.
* Установлен Docker с плагином compose:

```bash
curl -fsSL https://get.docker.com | sh
```

## 2. Запуск

Скачайте папку `deploy/docker` из релиза (архив `cypher-…-linux-amd64.tar.gz`)
или из репозитория и в ней выполните:

```bash
echo "CYPHER_DOMAIN=example.com" > .env
```

```bash
docker compose up -d
```

```bash
docker compose logs cypher
```

В логе при первом запуске будет ссылка `cypher://…` — вставьте её в
cypher-gui (**Серверы → Добавить**). Через несколько секунд в логе появится
`certificate ready` — сервер готов.

Если образ `ghcr.io/ddday9/cypher` приватный, сначала войдите в реестр
(токен GitHub с правом `read:packages`):

```bash
docker login ghcr.io -u ВАШ_ЛОГИН
```

Либо соберите образ на сервере из исходников (нужен весь репозиторий):

```bash
docker compose up -d --build
```

## 3. Сайт-прикрытие

Всё, что лежит в `deploy/docker/site/`, видят те, у кого нет ключа:
браузеры, поисковики и проверки цензора. Положите туда правдоподобный
статический сайт с `index.html`. Пока папка пуста, показывается простая
заглушка. Перезапуск не нужен.

## 4. Пользователи

Добавить пользователя (выведет его ссылку):

```bash
docker compose exec cypher cypher adduser -name phone
```

```bash
docker compose restart cypher
```

Показать ссылки всех пользователей:

```bash
docker compose exec cypher cypher links
```

Удалить пользователя — удалите его из `users` в конфиге и перезапустите.
Конфиг лежит в томе `cypher_cypher-data` (`/etc/cypher/server.json` внутри
контейнера).

## 5. Обновление

```bash
docker compose pull && docker compose up -d
```

## Переменные

| Переменная | По умолчанию | Что это |
|---|---|---|
| `CYPHER_DOMAIN` | — | домен сервера (обязательно при первом запуске) |
| `CYPHER_EMAIL` | — | email для уведомлений Let's Encrypt |
| `CYPHER_PUBLIC_PORT` | `443` | порт, который попадёт в ссылку |
| `CYPHER_LISTEN` | `:8443` | порт внутри контейнера |
| `CYPHER_LOG` | `info` | уровень логов при создании конфига |
| `CYPHER_ACME_DIRECTORY` | Let's Encrypt | другой ACME-сервер (например staging) |

Переменные используются только при первом запуске, когда конфига ещё нет.
Дальше настройки берутся из `/etc/cypher/server.json` в томе.

## Безопасность контейнера

Процесс работает от непривилегированного пользователя, файловая система
образа только для чтения, все capabilities сброшены, `no-new-privileges`.
Образ построен на `distroless/static`: в нём нет shell и пакетного менеджера.

## Без Docker

По-прежнему можно поставить сервер как службу systemd:
`sudo ./deploy/install-server.sh --domain example.com` (см. [setup.md](setup.md)).
