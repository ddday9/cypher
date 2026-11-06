# CLAUDE.md — контекст проекта cypher

Этот файл — для Claude (и для человека, который продолжит работу с ним).
Здесь то, чего нет в коде: решения владельца проекта, устройство, как
собирать и проверять, на какие грабли уже наступили и что осталось сделать.
Пользовательская документация — в `docs/` (ссылки ниже).

## Что это

**cypher** — собственный протокол обхода DPI (ориентир — ТСПУ в России) и
всё вокруг него, на Go, без форка Xray:

* сервер (выход за границей) и **ретранслятор** (сервер в РФ перед
  выходом) — `cmd/cypher`, Docker-образ `ghcr.io/ddday9/cypher`;
* консольный клиент — тот же `cmd/cypher`;
* **nevio** — графический клиент для Windows (`cmd/nevio`) и **Android**
  (`android/` + `mobile/`), общий веб-интерфейс в `internal/gui/web`.

Снаружи — обычный HTTPS (TLS 1.3, настоящий сертификат Let's Encrypt,
ClientHello браузера через uTLS); без ключа сервер отдаёт сайт-прикрытие.
Маршрутизация в стиле Xray с теми же `geosite.dat`/`geoip.dat`.

## Общение с владельцем

* Владелец — ddday9 (GitHub). **Отвечать по-русски.** Документация — по-русски;
  код, комментарии, коммиты — по-английски.
* Владелец тестирует сам: сервер в Docker на Linux-ВМ (`cypher.ragg.space`),
  клиент nevio на Windows. Android на реальном телефоне ещё не проверялся.
* Проверять заявления о совместимости и работе на реальных бинарниках, а не
  «должно работать». Если что-то не проверено (нет устройства, нет Windows),
  говорить прямо.

## Решения, которые уже приняты (не пересматривать без владельца)

* Своя реализация, **не форк Xray**. Синтаксис правил совместим с Xray.
* **Обратная совместимость в обе стороны обязательна**: новые клиенты со
  старыми серверами и старые клиенты с новыми (начиная с v0.1.0). Любое
  изменение протокола — через согласование (флаги/возможности), с
  проверкой матрицы версий (`tools/compat/`).
* **Режим без домена не нужен** (только свой домен + настоящий сертификат;
  `--self-signed` — лишь для проверки).
* Отпечаток TLS **по умолчанию Firefox**; остальные (chrome, safari, edge,
  ios, android, random) — выбором. `random` выбирается один раз по ключу и
  серверу и не меняется (смена отпечатка во время ограничений продлевает
  блок).
* Сервер — **в Docker** (nginx на 80 и сайт-прикрытие, cypher на 443), свой
  ACME/Let's Encrypt с автопродлением и подхватом без перезапуска.
  systemd-установка (`deploy/install-server.sh`) тоже поддерживается.
* Пользователи — **без лимитов трафика/времени**: есть или отозван.
  Добавление/отзыв без перезапуска.
* Базы geosite/geoip **по умолчанию — runetfreedom**, автообновление
  встроенным таймером (без cron), применение на лету.
* Ретранслятор: маршрутизация geosite/geoip на нём; два режима — A
  (ретранслятор расшифровывает) и B (сквозное шифрование Noise NK до
  выхода), плюс `hd=1` (скрыть адреса).
* Android: максимальная скрытность VPN от других приложений (см.
  `docs/android.md` — честно о пределах без root).
* **Ключей подписи и секретов в репозитории нет** (репозиторий публичный).
  Попытка закоммитить публичный keystore была заблокирована проверкой
  безопасности — это правильно.

## Карта репозитория

| Путь | Что там |
|---|---|
| `cmd/cypher` | CLI: `run`, `check`, `serve` (создаёт конфиг из `CYPHER_*`), `user add/list/link/revoke`, `link`, `genkey` |
| `cmd/nevio` | nevio для Windows: окно WebView2 + трей, `wintun.dll` встраивается (`make gui`) |
| `mobile/` | Go-API для Android (`gomobile bind`): `Start`, `Call` (API в процессе), `Asset`, `Connect`, `Disconnect` |
| `android/` | Kotlin-приложение: WebView + мост JS, `NevioVpnService`, `KeepAliveService`, маскировка значка |
| `internal/protocol` | протокол: auth (HMAC), расширение v2, записи с паддингом, сессия «против заморозки», keepalive, **e2e (Noise NK)**, запросы |
| `internal/client` | outbound'ы: `cypher` (пул, ротация, темп хендшейков, watchdog, anti-freeze, e2e), `direct`, `block` |
| `internal/server` | сервер: TLS, fallback-сайт, ACME, пользователи, маршрутизация (`direct/block/exit`), ретранслятор (`relay.go`), UDP |
| `internal/router` | маршрутизатор Xray-подобный, чтение geosite/geoip (protowire, без сгенерированного кода) |
| `internal/inbound` | socks (с паролем RFC 1929), http, tun |
| `internal/tun` | TUN: wintun (Windows), netlink (Linux), TUN из fd (Android); gVisor-стек |
| `internal/netx` | привязка сокетов к физическому интерфейсу (TUN), реестр своих портов (защита от петель) |
| `internal/gui` | бэкенд nevio (общий Windows/Android): профили, подписки, пресеты, API, `mobile.go` |
| `internal/app` | сборка клиента/сервера из конфига, перечитывание конфига и баз, **интеграционные тесты** |
| `internal/geo`, `links`, `procinfo`, `sniff`, `sysproxy`, `engine`, `config` | см. комментарии пакетов |
| `deploy/` | `docker/` (compose, nginx.conf, сайт), `install-server.sh`, `cypher.service`, `test-client.sh` |
| `tools/compat/` | проверки на реальных бинарниках разных версий (см. README там) |
| `docs/` | `quickstart.md`, `server.md`, `client.md`, `android.md`, `relay.md`, `protocol.md`, `comparison.md`, `docker.md`, `setup.md`, `nevio.md` |

## Протокол — главное (подробно: `docs/protocol.md`)

* Внутри TLS клиент шлёт заголовок аутентификации (nonce, время ±120 с,
  HMAC; первый байт nonce не A–Z, чтобы HTTP сразу ушёл на сайт).
* Записи `dataLen|padLen|data|pad`; первые записи каждого потока нарезаются
  и паддятся (против классификации вложенного TLS). smux v2 поверх.
* **v2** согласуется расширением в паддинге аутентификации (`CY2\x01`):
  флаги клиента `V2`, `Segmented`, `Attach`, `QuietIdle`; возможности
  сервера в HELLO: `Ping`, `Segmented`, `Relay`, `QuietIdle`, `E2E`.
  Служебные записи — бит `0x8000` в `padLen`.
* Keepalive — свой, случайные 10–40 с и только при открытых потоках
  (`QuietIdle`); старым версиям — всегда (у них таймаут 60 с).
* Пул клиента: не больше одного хендшейка одновременно, ≥1 с между ними,
  ≤3 в минуту, пауза после неудач 2 с → 2 мин (против «сибирской» схемы ТСПУ
  2026). `singleConnection` — строго одно соединение.
* Anti-freeze: сессия поверх коротких соединений (бюджет 8 КБ), `auto`
  включается после второй заморозки за 10 минут.
* Ретранслятор: запрос с флагом `0x80` + Noise-кадр; `CmdE2E`(4),
  `StatusE2E`(6). Ссылки выхода содержат `epk` (публичный ключ) —
  **`epk` без `ek` не включает e2e** (была ошибка v0.4.0).

## Сборка и проверки

```bash
make test                      # go test -race ./...
go vet ./... && GOOS=windows go vet ./...
GOOS=windows go build -o /dev/null ./cmd/nevio
make linux windows             # CLI
make gui                       # nevio.exe (качает и проверяет wintun.dll)
make android                   # nevio-android.apk: нужны ANDROID_HOME, ANDROID_NDK_HOME (NDK r27), gomobile
```

Android-окружение (как ставилось в облачной сессии): cmdline-tools в
`/opt/android-sdk`, `sdkmanager "platforms;android-35" "build-tools;35.0.0"
"ndk;27.2.12479018"`, `go install golang.org/x/mobile/cmd/gomobile@<версия
из go.mod> && gomobile init`, JDK 17+.

**Обязательно перед коммитом:** `gofmt -l`, vet для linux и windows, тесты.
Тест `TestTUNFromFD` требует root (реальный TUN), `TestWindowsTUN*` — Windows
с правами администратора и `CYPHER_TUN_TEST=1` (их гоняет CI).

**Проверка совместимости** при любом изменении протокола или сетевого
поведения — `tools/compat/` (сборка старых тегов, матрица новый↔старый,
простой >60 с, заморозка, ретранслятор). Перед этим `git fetch --tags`.

### CI (`.github/workflows/ci.yml`)

* `test` — vet, тесты, сборка nevio для Windows;
* `windows-tun` — **настоящий адаптер wintun** на windows-latest: TUN с
  маршрутами и прямой выход по правилу процесса (TCP, TLS, UDP к 1.1.1.1);
* `android` — AAR + APK + lint.

### Релизы

* **Пуш тегов из облачной сессии Claude запрещён прокси.** Релиз —
  `workflow_dispatch` для `release.yml` с входом `version` (например
  `v0.4.4`); workflow сам создаёт тег на текущем коммите.
* Ассеты: `cypher-linux-{amd64,arm64}.tar.gz`, `cypher-windows-amd64.zip`,
  `nevio-windows-amd64.exe`, `nevio-android.apk`, `SHA256SUMS`; образ GHCR
  multi-arch. После релиза — скачать ассеты, проверить суммы и версию.
* Android-подпись: секреты `NEVIO_KEYSTORE_B64`, `NEVIO_KEYSTORE_PASSWORD`,
  `NEVIO_KEY_ALIAS`, `NEVIO_KEY_PASSWORD` (`android/signing/README.md`).
  **Пока их нет** — APK подписан временным ключом, обновление поверх не
  ставится (каждый релиз — другой ключ).

### Git

* Единственная ветка — `claude/eloquent-ride-svvkti` (она же основная).
  PR не использовались. Коммиты — понятные, с объяснением «почему» в теле.

## Грабли, на которые уже наступили

* `go test | tail` прячет код возврата — всегда `set -o pipefail`.
* `yes | sdkmanager` под `pipefail` падает от SIGPIPE → `{ yes || true; } |`.
* Heredoc с `EOF` внутри вставляемого текста — брать уникальные метки.
* Фоновые `python3 -m http.server` в подоболочке не убиваются `kill` —
  запускать через `exec`.
* Kotlin-демон пишет логи в `android/.kotlin/` — не коммитить (в .gitignore).
* **Windows TUN:** `SetRoutesForFamily` сначала удаляет все маршруты адаптера
  и падает `Element not found` → добавлять маршруты без очистки, повторять
  при `ERROR_NOT_FOUND` (как wireguard-windows).
* **Windows TUN:** двухстековый UDP-сокет игнорирует `IP_UNICAST_IF` для IPv4
  → прямой UDP возвращался в TUN и зацикливался (Dota без сети). Теперь
  сокет под семейство адреса + реестр своих портов (`netx.IsOwnPort`)
  отбрасывает петли. **Не отбрасывать трафик «по имени своего процесса»**:
  nevio сам законно ходит через TUN (базы, подписки).
* TUN: сниффнутый домен — только для маршрута; прямое соединение идёт на
  исходный IP (иначе лишний DNS через VPN и CDN не в той стране).
* Клиент, которому нужны возможности сервера до первого запроса, должен
  отправить заголовок аутентификации сразу (пустой записью), иначе
  взаимное ожидание 3 с.
* `server.New` создаёт `e2e.key` рядом с конфигом; в тестах передавать
  `E2EKeyFile` во временную папку.
* Android: `ComponentName`-алиасы — в namespace `net.nevio.app`, даже если
  `applicationId` переопределён; `addDisallowedApplication` на
  несуществующий пакет кидает исключение — пропускать.
* Эмулятор Android в облачной сессии не запускается (нет KVM).

## Открытые задачи

1. **Тест Android на эмуляторе в CI** (начат и отложен владельцем): job с
   `reactivecircus/android-emulator-runner` (KVM на ubuntu-latest), сервер
   cypher на раннере (эмулятор видит хост как `10.0.2.2`, сертификат с
   IP SAN `10.0.2.2` от тестового CA; CA в процесс приложения через
   `SSL_CERT_FILE` в своём `AndroidJUnitRunner.onCreate` до загрузки Go),
   `appops set net.nevio.app ACTIVATE_VPN allow` вместо окна согласия.
   Инструментальный тест через `Mobile.call`: импорт ссылки, режим VPN,
   трафик `adb shell` (`toybox nc`) идёт через туннель, своё приложение не
   видит `TRANSPORT_VPN`, UI показывает «Подключено» (UiAutomator), режим
   прокси — SOCKS5 с паролем. Версии androidx.test: runner 1.6.2,
   ext:junit 1.2.1, uiautomator 2.3.0.
2. **Лимит устройств на пользователя** (`maxDevices`) — предложено, ждёт
   решения владельца: отказывать новому или выбивать старое (рекомендовано
   второе + лог + счётчик сессий в `cypher user list`).
3. Транспорт через CDN (HTTP/2, WebSocket) и автопереключение серверов.
4. Форма трафика против классификаторов вложенного TLS.
5. nevio для iOS (нужны Mac, аккаунт Apple, Network Extension; App Store в
   РФ удаляет VPN).
6. Секреты подписи Android — за владельцем.
7. Решения владельца: лицензия (её нет), видимость репозитория (публичный).
8. Не выяснено: «странный порядок иконок» в nevio на Windows — владелец не
   уточнил, о чём речь.

## Версии

Последний релиз — **v0.4.3** (Windows: TUN-маршруты, петля прямого UDP,
подсказки geosite/geoip в редакторе правил). История — в
[Releases](https://github.com/ddday9/cypher/releases) и `git log`.
