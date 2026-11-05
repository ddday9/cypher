# Быстрая настройка

Только команды по порядку. Подробности каждого шага — в
[server.md](server.md) и [client.md](client.md).

Схема:

```
nevio (Windows) ──► ретранслятор в РФ ──► выход за границей ──► интернет
                          └─► российские сайты напрямую
```

Без ретранслятора — [вариант Б](#вариант-б-без-ретранслятора) в конце.

## Что понадобится

* **2 ВМ с Linux** и публичным IPv4: одна за границей (выход), одна в
  России (ретранслятор).
* **2 домена или поддомена**, например `exit.example.com` и
  `ru.example.com`. В DNS — A-запись каждого на IP своей ВМ.
* Компьютер с **Windows 10/11**.

Ниже вместо `exit.example.com` и `ru.example.com` подставляйте свои домены.

---

## Вариант А: выход + ретранслятор + nevio

### Шаг 1. Выход (ВМ за границей)

Подключитесь к ВМ по SSH и выполните команды по очереди.

1. Проверьте, что домен указывает на эту ВМ (должен вывести её IP):

```bash
getent hosts exit.example.com
```

2. Установите Docker:

```bash
curl -fsSL https://get.docker.com | sh
```

3. Откройте порты 80 и 443 (если включён `ufw`; у облачного провайдера
   их может понадобиться открыть ещё и в панели управления):

```bash
sudo ufw allow 80,443/tcp
```

4. Скачайте файлы сервера:

```bash
mkdir -p ~/cypher && cd ~/cypher && curl -sSL https://github.com/ddday9/cypher/releases/latest/download/cypher-linux-amd64.tar.gz | tar xz --strip-components=3 --wildcards '*/deploy/docker'
```

   (на ARM-сервере замените `amd64` на `arm64`).

5. Укажите домен:

```bash
printf 'CYPHER_DOMAIN=exit.example.com\nCYPHER_EMAIL=you@example.com\n' > .env
```

6. Запустите:

```bash
docker compose up -d
```

7. Дождитесь сертификата — в логе появится `certificate ready` (обычно
   до минуты), затем нажмите Ctrl+C:

```bash
docker compose logs -f cypher
```

8. Создайте пользователя для ретранслятора:

```bash
docker compose exec cypher cypher user add relay
```

   Скопируйте напечатанную ссылку `cypher://…` — это **ССЫЛКА_RELAY**.

9. Создайте пользователя для себя (для сквозного шифрования):

```bash
docker compose exec cypher cypher user add phone
```

   Скопируйте ссылку — это **ССЫЛКА_PHONE_ВЫХОД**.

### Шаг 2. Ретранслятор (ВМ в России)

Подключитесь ко второй ВМ по SSH.

1. Проверьте домен, установите Docker, откройте порты и скачайте файлы —
   те же команды, что в шаге 1, пункты 1–4, но с `ru.example.com`:

```bash
getent hosts ru.example.com
```

```bash
curl -fsSL https://get.docker.com | sh
```

```bash
sudo ufw allow 80,443/tcp
```

```bash
mkdir -p ~/cypher && cd ~/cypher && curl -sSL https://github.com/ddday9/cypher/releases/latest/download/cypher-linux-amd64.tar.gz | tar xz --strip-components=3 --wildcards '*/deploy/docker'
```

2. Создайте `.env`: домен ретранслятора и **ССЫЛКА_RELAY** из шага 1.8.
   Ссылку оставьте в одинарных кавычках:

```bash
printf "CYPHER_DOMAIN=ru.example.com\nCYPHER_UPSTREAM='%s'\n" 'ССЫЛКА_RELAY' > .env
```

3. Запустите:

```bash
docker compose up -d
```

4. Проверьте лог, затем Ctrl+C. Должны появиться строки
   `relay mode: traffic routed to "exit" goes to the upstream server`,
   `server routing rules applied rules=4 default=exit` (после скачивания
   баз, до минуты) и `certificate ready`:

```bash
docker compose logs -f cypher
```

5. Создайте себе ссылку со сквозным шифрованием до выхода, подставив
   **ССЫЛКА_PHONE_ВЫХОД** из шага 1.9:

```bash
docker compose exec cypher cypher user add phone -exit 'ССЫЛКА_PHONE_ВЫХОД'
```

   Напечатается ссылка `cypher://…@ru.example.com:443?ek=…&epk=…` — это
   **ССЫЛКА_ДЛЯ_NEVIO**.

### Шаг 3. nevio (Windows)

1. Скачайте `nevio-windows-amd64.exe` со страницы
   [Releases](https://github.com/ddday9/cypher/releases/latest), положите в
   отдельную папку (например `%LOCALAPPDATA%\nevio`) и запустите.
2. **Серверы** → вставьте **ССЫЛКА_ДЛЯ_NEVIO** → **Добавить**. Сервер
   будет помечен «через ретранслятор, сквозное шифрование».
3. **Главная** → большая кнопка. Первое подключение дольше: скачиваются
   базы geosite/geoip (~100 МБ).
4. Проверка: [ifconfig.me](https://ifconfig.me) показывает IP **выхода**;
   [2ip.ru](https://2ip.ru) — ваш обычный IP (российские сайты по
   умолчанию идут напрямую).

Готово. Весь трафик системы, включая игры: на главной переключите режим на
**Весь трафик (TUN)** (nevio попросит права администратора).

---

## Вариант Б: без ретранслятора

1. Выполните [шаг 1](#шаг-1-выход-вм-за-границей), пункты 1–7.
2. Создайте пользователя:

```bash
docker compose exec cypher cypher user add phone
```

3. Ссылку из вывода вставьте в nevio — [шаг 3](#шаг-3-nevio-windows).

---

## Дальше

| Задача | Где |
|---|---|
| Ещё один пользователь / устройство | шаг 1.9 и 2.5 с другим именем, или только `cypher user add NAME` на ретрансляторе (без сквозного шифрования) — [server.md, 8.4](server.md#84-пользователи-ретранслятора-два-режима) |
| Отозвать пользователя | `docker compose exec cypher cypher user revoke NAME` — [server.md, 9](server.md#9-пользователи) |
| Свой сайт-прикрытие | замените файлы в `~/cypher/site/` — [server.md, 14.1](server.md#141-свой-сайт-прикрытие) |
| Изменить, что идёт напрямую с ретранслятора | [server.md, 8.3](server.md#83-правила-ретранслятора) |
| Игры и программы напрямую | nevio → Настройки → Приложения — [client.md, 3.3](client.md#33-настройки--маршрутизация) |
| Обновить сервер | `cd ~/cypher && docker compose pull && docker compose up -d` |
| Что-то не работает | [server.md, 15](server.md#15-диагностика), [client.md, 13](client.md#13-диагностика) |
