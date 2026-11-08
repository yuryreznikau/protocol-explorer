# Protocol Explorer — прикладной уровень / Application Layer Edition

[Русский](#русский) · [English](#english)

Онлайн / Live: **https://yuryreznikau.github.io/protocol-explorer/**

---

## Русский

Интерактивный визуальный тренажёр по сетевым протоколам: пакеты движутся по схеме сети, а каждый можно открыть и разобрать по байтам, как в Wireshark.

### Авторство

- Оригинальный проект и визуальный движок: **Dilum Sanjaya** — [protocol-explorer-alpha.vercel.app](https://protocol-explorer-alpha.vercel.app/).
- Расширенная версия, от которой сделан этот форк: [AliShafiee2003/protocol-explorer](https://github.com/AliShafiee2003/protocol-explorer).

### Что изменено в форке

- **Только прикладной уровень (L7).** Уроки TCP, UDP, IP, ICMP и TLS удалены. Остались HTTP, HTTP/2, HTTP/3, DNS, DHCP, SMTP, POP3, IMAP, FTP, WebSocket, MQTT, SSE, Chunked, gRPC, а в группе «Безопасность» — HTTPS и SSH.
- **Новая группа «Мониторинг»** с четырьмя демо:
  - **SNMP** — v2c: GetRequest, GetNext (обход таблицы), GetBulk (счётчики трафика), SetRequest с ошибкой `noAccess`, потеря запроса и повтор, Trap linkDown (UDP 161/162). Полный BER-разбор PDU в инспекторе пакетов.
  - **NetFlow v9** — Template FlowSet, Data FlowSet, потеря экспортного пакета (разрыв sequence), периодическая повторная отправка шаблона. Разбор полей по шаблону (UDP 2055).
  - **Syslog/UDP** — приоритет (facility × 8 + severity), форматы RFC 3164 и RFC 5424, тихая потеря сообщений, фильтрация по severity (UDP 514).
  - **Syslog/TCP** — TCP-соединение, сообщения с подсчётом октетов (RFC 6587), потеря сегмента и повторная передача (TCP 514).
- **Интерфейс на русском и английском.** Язык по умолчанию — русский (английский, если язык браузера не ru/be/uk/kk); переключатель — в шапке. Добавлен кириллический шрифт Iosevka.
- **Удалена RTL-локализация** (арабский, персидский, иврит) и остальные языки, а также шрифты Vazirmatn и стили направления справа налево.
- Строки «на проводе» (колонка Info, тексты логов, команды протоколов) намеренно оставлены на английском — так они выглядят в реальном трафике.

### Сборка

Исходный проект — это готовая сборка Vite, поэтому форк собирается патчем поверх исходного бандла:

```bash
python3 tools/build.py          # tools/upstream.pretty.js + src/monitoring.js -> assets/index.js
cd tools/i18n && node mkru.cjs  # переводы tools/i18n/tr/* -> assets/ru.js
python3 serve.py                # или любой статический сервер, затем открыть http://localhost:8000 (или первый свободный порт)
```

Деплой на GitHub Pages выполняется автоматически при пуше в `main` (`.github/workflows/deploy.yml`).

---

## English

An interactive visual tutor for network protocols: packets travel across a network diagram, and you can open any of them and inspect it byte by byte, Wireshark-style.

### Credits

- Original project and visual engine: **Dilum Sanjaya** — [protocol-explorer-alpha.vercel.app](https://protocol-explorer-alpha.vercel.app/).
- Extended edition this fork is based on: [AliShafiee2003/protocol-explorer](https://github.com/AliShafiee2003/protocol-explorer).

### Changes in this fork

- **Application layer (L7) only.** The TCP, UDP, IP, ICMP and TLS lessons were removed. Remaining: HTTP, HTTP/2, HTTP/3, DNS, DHCP, SMTP, POP3, IMAP, FTP, WebSocket, MQTT, SSE, Chunked, gRPC, plus HTTPS and SSH under "Security".
- **New "Monitoring" group** with four demos:
  - **SNMP** — v2c: GetRequest, GetNext (table walk), GetBulk (traffic counters), SetRequest failing with `noAccess`, lost request and retry, linkDown trap (UDP 161/162). Full BER decoding in the packet inspector.
  - **NetFlow v9** — Template FlowSet, Data FlowSet, a lost export packet (sequence gap), periodic template refresh. Template-driven field decoding (UDP 2055).
  - **Syslog/UDP** — priority (facility × 8 + severity), RFC 3164 and RFC 5424 formats, silent loss, severity filtering (UDP 514).
  - **Syslog/TCP** — TCP connection, octet-counted messages (RFC 6587), a lost segment and retransmission (TCP 514).
- **Russian and English UI.** Russian is the default (English when the browser language isn't ru/be/uk/kk); switch in the header.
- **RTL localization removed** (Arabic, Persian, Hebrew) together with the other languages, the Vazirmatn fonts and right-to-left styles.
- On-the-wire strings (Info column, log text, protocol commands) are intentionally kept in English.

### Build

```bash
python3 tools/build.py
cd tools/i18n && node mkru.cjs
python3 serve.py
```

GitHub Pages deploys automatically on push to `main`.
