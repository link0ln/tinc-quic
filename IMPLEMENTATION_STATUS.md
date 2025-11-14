# QUIC Integration Implementation Status

**Дата:** 2025-11-14
**Статус:** 🟡 В процессе (15% готово)

## ❌ ВАЖНО: Tinc НЕ работает по QUIC на данный момент!

Реализована только **базовая инфраструктура**. Старый TCP/UDP транспорт все еще активен и используется для всех соединений.

---

## ✅ Что УЖЕ реализовано

### 1. QUIC Абстракционный слой
**Файлы:** `src/quic.h`, `src/quic.c` (900+ строк)

**Реализованные функции:**
- ✅ `quic_init()` - инициализация MsQuic библиотеки
- ✅ `quic_start_listener()` - запуск QUIC listener
- ✅ `quic_connection_open()` - создание QUIC соединения
- ✅ `quic_connection_start()` - запуск QUIC соединения
- ✅ `quic_send_meta()` - отправка метаданных через QUIC stream
- ✅ `quic_send_packet()` - отправка VPN пакетов через QUIC datagram
- ✅ `quic_connection_callback()` - обработка QUIC событий
- ✅ `quic_stream_callback()` - обработка QUIC stream событий
- ✅ `quic_listener_callback()` - обработка входящих соединений

**Состояние:** ✅ Написан, но НЕ используется в data flow

---

### 2. Интеграция в структуры данных
**Файл:** `src/connection.h`

```c
typedef struct connection_t {
    // ... существующие поля ...

    /* QUIC support */
    void *quic_context;    // ✅ Добавлено
    uint16_t port;         // ✅ Добавлено
} connection_t;
```

**Состояние:** ✅ Готово, но поля не заполняются

---

### 3. Build система
**Файлы:** `configure.ac`, `src/Makefile.am`

**Изменения:**
- ✅ Добавлена проверка MsQuic в configure.ac
- ✅ Установлены MSQUIC_CFLAGS и MSQUIC_LIBS
- ✅ quic.c и quic.h добавлены в tincd_SOURCES
- ✅ MsQuic добавлен как git submodule

**Состояние:** ✅ Готово для компиляции (после сборки MsQuic)

---

### 4. Инициализация в net_setup.c
**Файл:** `src/net_setup.c`

```c
bool setup_network(void) {
    // ...

#ifdef HAVE_MSQUIC
    // ✅ QUIC инициализируется при старте
    if(!quic_init(quic_port)) {
        logger(DEBUG_ALWAYS, LOG_ERR, "Failed to initialize QUIC");
        return false;
    }

    if(!quic_start_listener(quic_port)) {
        logger(DEBUG_ALWAYS, LOG_ERR, "Failed to start QUIC listener");
        quic_cleanup();
        return false;
    }
#endif
    // ...
}
```

**Состояние:** ✅ QUIC listener запускается, но не принимает соединения

---

### 5. Документация
**Файл:** `QUIC_INTEGRATION_DESIGN.md`

- ✅ Детальный архитектурный дизайн
- ✅ План миграции
- ✅ API маппинг
- ✅ Анализ безопасности

---

## ❌ Что НЕ реализовано (критически важно)

### 1. MsQuic библиотека НЕ собрана
**Статус:** ❌ Не выполнено

**Проблема:**
- Submodule добавлен, но библиотека не скомпилирована
- Нет файла `libmsquic.so`
- Tinc не сможет линковаться с MsQuic

**Что нужно:**
```bash
cd msquic
git submodule update --init --recursive
mkdir build && cd build
cmake -G "Unix Makefiles" -DQUIC_TLS=openssl ..
make -j$(nproc)
```

---

### 2. meta.c НЕ использует QUIC
**Статус:** ❌ Использует старый TCP

**Текущий код:**
```c
// src/meta.c
bool send_meta(connection_t *c, const char *buffer, size_t length) {
    // ❌ Отправляет через TCP socket
    buffer_add(&c->outbuf, buffer, length);
    io_set(&c->io, IO_READ | IO_WRITE);
    return true;
}
```

**Что нужно изменить:**
```c
bool send_meta(connection_t *c, const char *buffer, size_t length) {
#ifdef HAVE_MSQUIC
    if(c->quic_context) {
        return quic_send_meta(c, buffer, length);  // ✅ Через QUIC stream
    }
#endif
    // Fallback to TCP
    buffer_add(&c->outbuf, buffer, length);
    io_set(&c->io, IO_READ | IO_WRITE);
    return true;
}
```

**Затронутые функции:**
- `send_meta()` - ❌ не обновлена
- `receive_meta()` - ❌ не обновлена
- `send_meta_sptps()` - ❌ не обновлена
- `receive_meta_sptps()` - ❌ не обновлена

---

### 3. net_packet.c НЕ использует QUIC
**Статус:** ❌ Использует старый UDP

**Текущий код:**
```c
// src/net_packet.c
static void send_udppacket(node_t *n, vpn_packet_t *packet) {
    // ❌ Отправляет через UDP socket
    sendto(listen_socket[sockindex].udp.fd, ...);
}
```

**Что нужно изменить:**
```c
static void send_udppacket(node_t *n, vpn_packet_t *packet) {
#ifdef HAVE_MSQUIC
    if(n->connection && n->connection->quic_context) {
        quic_send_packet(n->connection, packet);  // ✅ Через QUIC datagram
        return;
    }
#endif
    // Fallback to UDP
    sendto(listen_socket[sockindex].udp.fd, ...);
}
```

**Затронутые функции:**
- `send_udppacket()` - ❌ не существует (используется inline код)
- `handle_incoming_vpn_data()` - ❌ не обновлена
- `send_packet()` - ❌ не обновлена

---

### 4. net_socket.c создает TCP/UDP сокеты
**Статус:** ❌ Старый код активен

**Текущий код:**
```c
// src/net_socket.c:546
c->socket = socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

// src/net_socket.c:173
nfd = socket(sa->sa.sa_family, SOCK_STREAM, IPPROTO_TCP);  // TCP listener

// src/net_socket.c:250
nfd = socket(sa->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);   // UDP socket
```

**Что нужно изменить:**
- Заменить `setup_listen_socket()` на использование QUIC listener
- Заменить `setup_vpn_in_socket()` на QUIC datagram receive
- Обновить `setup_outgoing_connection()` для использования `quic_connection_open()`

**Затронутые функции:**
- `setup_listen_socket()` - ❌ не обновлена
- `setup_vpn_in_socket()` - ❌ не обновлена
- `setup_outgoing_connection()` - ❌ не обновлена
- `handle_new_meta_connection()` - ❌ не обновлена

---

### 5. protocol_auth.c использует старый flow
**Статус:** ❌ SPTPS handshake через TCP

**Текущий код:**
```c
// src/protocol_auth.c
bool send_id(connection_t *c) {
    // ❌ Отправляет через send_meta() -> TCP
    return send_request(c, "%d %s %d.%d", ID, ...);
}
```

**Проблема:**
- Handshake (ID, METAKEY, CHALLENGE, ACK) идет через старый TCP
- SPTPS шифрование применяется поверх TCP
- QUIC TLS не используется

**Что нужно:**
- Обновить `send_id()`, `send_metakey()`, etc. для работы через QUIC
- Отключить SPTPS если используется QUIC (TLS 1.3 уже есть)

---

### 6. Обработка QUIC событий в event loop
**Статус:** ❌ Не интегрировано

**Проблема:**
- QUIC callbacks вызываются MsQuic в отдельных потоках
- Tinc event loop (event.c) не знает о QUIC событиях
- Возможны race conditions

**Что нужно:**
- Интеграция QUIC с tinc event loop
- Синхронизация между QUIC threads и main loop
- Возможно использование QUIC в single-threaded режиме

---

### 7. Connection establishment flow
**Статус:** ❌ Полностью через TCP

**Текущий flow:**
```
1. setup_outgoing_connection()
2. socket() -> TCP
3. connect()
4. handle_meta_io() callback
5. send_id() через TCP
6. SPTPS handshake через TCP
7. Connection established
```

**Должен быть:**
```
1. setup_outgoing_connection()
2. quic_connection_open()
3. quic_connection_start()
4. QUIC TLS handshake (автоматически)
5. quic_connection_callback(CONNECTED)
6. Открыть control stream
7. send_id() через QUIC stream
8. Connection established
```

---

## 📊 Метрики реализации

| Компонент | Прогресс | Статус |
|-----------|----------|--------|
| QUIC абстракция (quic.c) | 100% | ✅ Готов |
| Build система | 100% | ✅ Готов |
| MsQuic библиотека | 0% | ❌ Не собран |
| Metadata через QUIC (meta.c) | 0% | ❌ Не реализовано |
| VPN packets через QUIC (net_packet.c) | 0% | ❌ Не реализовано |
| Socket layer (net_socket.c) | 0% | ❌ Не обновлен |
| Connection flow | 0% | ❌ Не обновлен |
| Protocol auth | 0% | ❌ Не обновлен |
| Event loop integration | 0% | ❌ Не реализовано |
| **Общий прогресс** | **15%** | 🟡 В процессе |

---

## 🚧 Что произойдет если запустить сейчас?

### Сценарий 1: Компиляция
```bash
./configure
make
```

**Результат:** ❌ **ОШИБКА компиляции**
```
/usr/bin/ld: cannot find -lmsquic
collect2: error: ld returned 1 exit status
```

**Причина:** MsQuic библиотека не собрана

---

### Сценарий 2: Если собрать MsQuic и скомпилировать
```bash
./configure
make
./src/tincd -D
```

**Результат:** ⚠️ **Tinc запустится, но будет использовать TCP/UDP**

**Что произойдет:**
1. ✅ QUIC инициализируется (`quic_init()`)
2. ✅ QUIC listener запустится (`quic_start_listener()`)
3. ❌ НО все соединения пойдут через старый TCP
4. ❌ Метаданные через TCP socket
5. ❌ VPN пакеты через UDP socket
6. ❌ QUIC listener будет ждать соединений, но никто не подключится

**Логи:**
```
QUIC transport layer initialized
[но далее все через TCP/UDP]
Connection from 192.168.1.2:655 via TCP
Sending packet to node1 via UDP
```

---

## 📝 Пошаговый план для ПОЛНОЙ реализации

### Фаза 1: Сборка зависимостей (1 час)
1. ✅ ~~Добавить MsQuic submodule~~ (готово)
2. ❌ Инициализировать submodules MsQuic
3. ❌ Собрать MsQuic библиотеку
4. ❌ Проверить что tinc линкуется

### Фаза 2: Metadata через QUIC (4 часа)
1. ❌ Обновить `send_meta()` для QUIC stream
2. ❌ Обновить `receive_meta()` для QUIC callback
3. ❌ Обновить `send_meta_sptps()` (или отключить SPTPS)
4. ❌ Тестировать handshake через QUIC

### Фаза 3: VPN packets через QUIC (4 часа)
1. ❌ Обновить `send_packet()` для QUIC datagram
2. ❌ Обновить `handle_incoming_vpn_data()` для QUIC callback
3. ❌ Реализовать buffering для больших пакетов
4. ❌ Тестировать передачу данных

### Фаза 4: Connection management (3 часа)
1. ❌ Обновить `setup_outgoing_connection()` для QUIC
2. ❌ Обновить `handle_new_meta_connection()` для QUIC listener
3. ❌ Обновить `terminate_connection()` для QUIC cleanup
4. ❌ Тестировать connection lifecycle

### Фаза 5: Удаление legacy кода (2 часа)
1. ❌ Удалить TCP socket creation
2. ❌ Удалить UDP socket creation
3. ❌ Опционально: удалить SPTPS (заменен на QUIC TLS)
4. ❌ Cleanup #ifdef guards

### Фаза 6: Тестирование (5 часов)
1. ❌ Unit тесты для QUIC layer
2. ❌ Integration тесты для 2-node setup
3. ❌ Тесты для mesh network (3+ nodes)
4. ❌ Performance benchmarks
5. ❌ Stress тесты (packet loss, reconnection)

---

## 🎯 Минимальная рабочая версия (MVP)

Для того чтобы tinc заработал по QUIC **минимально**, нужно:

### Must-have (критично):
1. ✅ ~~quic.c написан~~ (готово)
2. ❌ **MsQuic собран** (30 мин)
3. ❌ **meta.c обновлен** (2 часа)
4. ❌ **net_packet.c обновлен** (2 часа)
5. ❌ **setup_outgoing_connection обновлен** (1 час)

**Итого для MVP: ~6 часов работы**

### Nice-to-have (можно позже):
- Удаление TCP/UDP кода
- Удаление SPTPS
- Оптимизация performance
- Extensive testing

---

## 🔍 Проверка текущего состояния

### Проверить что QUIC код компилируется:
```bash
cd /home/user/tinc-quic
grep -r "quic_send_meta" src/  # Должно найти только в quic.c
grep -r "quic_send_packet" src/  # Должно найти только в quic.c
```

### Проверить что старый код все еще активен:
```bash
grep "socket(" src/net_socket.c  # ❌ Найдет много вызовов socket()
grep "sendto(" src/net_packet.c  # ❌ Найдет sendto() для UDP
```

---

## ❓ FAQ

**Q: Можно ли запустить tinc сейчас?**
A: Нет, не скомпилируется (нет libmsquic.so)

**Q: Если собрать MsQuic, tinc будет работать по QUIC?**
A: Нет, будет работать по TCP/UDP (старый код активен)

**Q: Сколько работы осталось до рабочей версии?**
A: ~6 часов для MVP (минимально), ~20 часов для полной версии

**Q: Можно ли использовать одновременно TCP/UDP и QUIC?**
A: Да, можно сделать dual-stack, но это усложнит код

**Q: Нужно ли удалять SPTPS?**
A: Опционально. QUIC TLS заменяет SPTPS, но можно оставить для compatibility

---

## 📅 Следующий шаг

**Рекомендация:** Начать с **Фазы 1** - собрать MsQuic библиотеку

```bash
cd /home/user/tinc-quic/msquic
git submodule update --init --recursive
mkdir build && cd build
cmake -G "Unix Makefiles" -DQUIC_TLS=openssl -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

После этого перейти к **Фазе 2** - обновить meta.c
