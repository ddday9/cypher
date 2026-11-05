# Установка: сервер на Linux, клиент на Windows

## Что понадобится

* Linux-ВМ с публичным IP, на которой свободен порт 443.
* Домен (подойдёт любой дешёвый) с A-записью на IP ВМ.
* Go 1.26+ для сборки (более старый Go сам скачает нужную версию) (или готовые бинарники из `make linux windows`).

## 1. Сборка

На любой машине с Go:

```bash
make linux windows
```

Получатся `bin/cypher-linux-amd64` и `bin/cypher-windows-amd64.exe`.

## 2. Сервер (Linux)

### Сертификат

```bash
sudo apt install certbot
```

```bash
sudo certbot certonly --standalone -d example.com
```

Сертификат ляжет в `/etc/letsencrypt/live/example.com/`. Сервер сам
перечитывает его после продления, перезапуск не нужен.

### Пользователь и файлы

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin cypher
```

```bash
sudo install -m 755 bin/cypher-linux-amd64 /usr/local/bin/cypher
```

```bash
sudo mkdir -p /etc/cypher /var/www/site
```

Дайте пользователю `cypher` читать сертификат:

```bash
sudo chgrp -R cypher /etc/letsencrypt/live /etc/letsencrypt/archive && sudo chmod -R g+rX /etc/letsencrypt/live /etc/letsencrypt/archive
```

### Ключ и конфиг

```bash
cypher genkey
```

Скопируйте `examples/server.json` в `/etc/cypher/server.json`, впишите домен
в пути к сертификату и ключ из `genkey` в `users`.

### Сайт-прикрытие

Положите в `/var/www/site` любой правдоподобный статический сайт
(`index.html` и пара страниц). Его увидит любой, кто зайдёт на ваш домен
браузером, — и цензор, который проверяет сервер. Без `fallback.dir` сервер
показывает простую заглушку.

### Запуск

```bash
sudo cp deploy/cypher.service /etc/systemd/system/
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now cypher
```

```bash
journalctl -u cypher -f
```

Проверка: откройте `https://example.com` в браузере — должен открыться ваш сайт.

## 3. Клиент (Windows)

1. Создайте папку, например `C:\cypher`, положите туда
   `cypher-windows-amd64.exe` (можно переименовать в `cypher.exe`).
2. Скачайте `geosite.dat` и `geoip.dat` — те же, что для Xray, например из
   [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat/releases)
   или [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat/releases),
   и положите рядом.
3. Скопируйте `examples/client.json` в `C:\cypher\client.json`, впишите
   `server` (`example.com:443`) и тот же `key`, что на сервере.
4. Проверьте конфиг и запустите:

```bash
cypher.exe check -c client.json
```

```bash
cypher.exe run -c client.json
```

5. Включите прокси в Windows: **Параметры → Сеть и Интернет → Прокси-сервер →
   Использовать прокси-сервер**, адрес `127.0.0.1`, порт `10809` (HTTP).
   Либо укажите SOCKS5 `127.0.0.1:10808` в настройках браузера или программы.

Пока работает режим локального прокси: через него идут программы, которые
используют системный прокси (браузеры и большинство приложений). Режим TUN
для всего трафика системы — следующий этап.

## Маршрутизация

Синтаксис совместим с Xray:

| Поле | Значения |
|---|---|
| `domain` | `geosite:google`, `geosite:google@cn` (атрибут), `domain:example.com` (домен и поддомены), `full:www.example.com`, `keyword:goog`, `regexp:^ads\d+\.`, строка без префикса = keyword |
| `ip` | `geoip:ru`, `geoip:private`, `geoip:!ru` (всё, кроме), `10.0.0.0/8`, `1.2.3.4` |
| `port` | `443`, `"1000-2000"`, `"80,443,8000-9000"` |
| `network` | `tcp`, `udp`, `tcp,udp` |
| `inboundTag` | `["socks"]` |

Внутри поля условия объединяются через ИЛИ, поля между собой — через И.
Правила проверяются по порядку; первое совпавшее определяет `outbound`. Если
ничего не совпало — `routing.default` (или первый outbound).

`domainStrategy`:
* `AsIs` (по умолчанию) — IP-правила применяются только к соединениям по IP.
* `IPIfNonMatch` — если домен не совпал ни с одним правилом, клиент резолвит
  его и проверяет IP-правила (например, `geoip:ru`). **Внимание:** это
  локальный DNS-запрос к провайдеру, он раскрывает домен.

## Обновление правил без перезапуска

Клиент каждые 3 секунды проверяет `geosite.dat`, `geoip.dat` и свой конфиг.
Если файл изменился (и не меняется ещё одну проверку, то есть уже докачан),
правила маршрутизации пересобираются и подменяются на лету. Открытые
соединения не рвутся.

* Если новый файл битый или правило ссылается на несуществующий outbound,
  в лог пишется ошибка, и продолжают действовать старые правила.
* На лету меняется только секция `routing`. Изменения `inbounds` и
  `outbounds` требуют перезапуска.
