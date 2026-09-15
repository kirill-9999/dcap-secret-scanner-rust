# dcap-secret-scanner (Rust)

Сканер папок на наличие паролей и SSH-ключей (аналог `scan_folder.py`).
Regex-правила для .NET/Java/Kafka/Redis/k8s/AD-стека, чтение Office-файлов
(doc/xls/docx/xlsx), utf-8/cp1251. Распространяется как Docker-образ.

## Запуск в Docker

### Получение образа

```powershell
docker pull ghcr.io/kirill-9999/dcap-secret-scanner-rust:latest
```

### Два режима

Образ поддерживает два режима:

1. **Разовый скан** — одна папка или одна SMB-шара (entrypoint сканера).
2. **Runner** — периодический или одноразовый скан по списку ресурсов
   с расписанием, возобновлением, паузой и единым логом находок.

---

### Режим 1: разовый скан

#### Локальная папка (bind-mount)

```powershell
docker run --rm -v "D:\local\data:/data" `
  ghcr.io/kirill-9999/dcap-secret-scanner-rust:latest /data /out.log 8
```

Аргументы сканера: `<путь_к_папке> <лог-файл или папка> [потоков] [флаги]`.
Если третий аргумент — папка, отчёт сохраняется в неё автоматически.

#### SMB-шара (одиночный CIFS, учётка + домен + пароль в файле)

```powershell
docker run --rm --privileged `
  -e SMB_SHARE="//fileserver-01.corp/Платежи" `
  -e SMB_USER="svc-scan" `
  -e SMB_DOMAIN=CORP `
  -e SMB_PASS_FILE=/secret.txt `
  -v "D:\secrets\password.txt:/secret.txt:ro" `
  -v "D:\logs:/logs" `
  ghcr.io/kirill-9999/dcap-secret-scanner-rust:latest /logs 10
```

- `--privileged` обязателен — контейнер сам выполняет `mount.cifs`.
- Шара монтируется в `/mnt/share` (точка настраивается через `SMB_MOUNT`).
- Опция `ro` (read-only) добавляется автоматически — сканер ничего не пишет.
- Домен (`SMB_DOMAIN`) необязателен, если домен уже включён в `SMB_USER`
  в виде `DOMAIN\user`.

---

### Режим 2: runner (скан списка ресурсов)

#### 1. Подготовка

```powershell
# Каталог состояния (переживает перезапуски контейнера)
New-Item -ItemType Directory D:\dcap\manager\conf -Force

# Файл пароля (НЕ коммитить в git)
Set-Content -Path "D:\dcap\password.txt" -Value "P@ssw0rd!" -NoNewline
```

Список ресурсов (`conf/list.txt`) — по одному ресурсу на строку:

```text
# SMB-шары (начинаются с // или \\):
//fileserver-01.corp/Платежи
//fileserver-01.corp/Кадры
//fileserver-02.corp/Архив
# Обычный bind-mount или локальный каталог:
/tmp/shares/backup-архив
```

#### 2. Одноразовый прогон (RUN_ONCE)

Выполнит один полный проход по всем ресурсам из списка и завершится.
Прерванный проход при перезапуске дочитывается с места останова.

```powershell
docker run -d --name dcap-runner --privileged `
  -e "TZ=Europe/Moscow" `
  -e RESOURCE_LIST=/manager/conf/list.txt `
  -e RUN_ONCE=1 `
  -e SMB_USER="svc-scan" `
  -e SMB_DOMAIN=CORP `
  -e SMB_PASS_FILE=/secret.txt `
  -e "SCAN_ARGS=--no-generic --strict-filter" `
  -v "D:\dcap\manager:/manager" `
  -v "D:\dcap\password.txt:/secret.txt:ro" `
  ghcr.io/kirill-9999/dcap-secret-scanner-rust:latest runner
```

Проверка хода работ и результата:

```powershell
docker logs -f dcap-runner              # консольный вывод
Get-Content D:\dcap\manager\cycle.json  # статусы ресурсов
Get-Content D:\dcap\manager\unified.log # единый лог находок
```

Для повторного прогона — удалите контейнер и запустите снова (state и
cycle.json хранятся в `D:\dcap\manager` и переживают перезапуск).

#### 3. Запуск с расписанием (долгосрочный режим)

```powershell
docker run -d --name dcap-runner --restart unless-stopped --privileged `
  -e "TZ=Europe/Moscow" `
  -e RESOURCE_LIST=/manager/conf/list.txt `
  -e SCHEDULE="01:00-06:00;12:00-13:00" `
  -e SMB_USER="svc-scan" `
  -e SMB_DOMAIN=CORP `
  -e SMB_PASS_FILE=/secret.txt `
  -v "D:\dcap\manager:/manager" `
  -v "D:\dcap\password.txt:/secret.txt:ro" `
  ghcr.io/kirill-9999/dcap-secret-scanner-rust:latest runner
```

#### Структура каталога `manager`

| Путь | Назначение |
|------|------------|
| `conf/list.txt` | Список ресурсов (см. выше). |
| `state/<slug>.c<N>.tsv` | Состояние сканирования файла (для resume). Хранит пути, но **не** секреты. |
| `report/<slug>.c<N>.log` | Полный отчёт сканера по ресурсу (включает найденные значения). |
| `unified.log` | Единый лог находок всех ресурсов (TSV: время, ресурс, путь, категория, значение и т.д.). |
| `cycle.json` | Номер текущего цикла и статусы ресурсов (`done`/`error`). |
| `control/pause` | `touch` — пауза после текущего файла; `rm` — возобновить. |
| `control/stop` | `touch` — прервать проход и завершить процесс. Одноразовый — удаляется автоматически. |

`<slug>` — безопасное для файловой системы имя ресурса (автоматически из URL).
`<N>` — номер цикла из `cycle.json`.

#### Поведение

- **Цикл** — полный проход по списку. Прерванный при следующем запуске
  дочитывается с места останова (`state/*.tsv` + `cycle.json`); завершённые
  ресурсы не перечитываются. Новый цикл начинается всегда с начала.
- **Resume** — при `RUN_ONCE=1` или при перезапуске `docker start`.
  Прерванный ресурс продолжается там же, где остановился сканер.
- **Пауза** — `touch control/pause`; `rm` — возобновить.
  `docker stop` / SIGTERM ведёт себя как `control/stop`.
- **Один проход** — `RUN_ONCE=1`. После полного прохода — выход `exit 0`.
  Прерванный проход дочитывается, затем завершение.
- **Расписание** — `SCHEDULE` (см. таблицу ниже). По умолчанию `always`.
- **Креды** — `SMB_USER` / `SMB_PASS` / `SMB_PASS_FILE` / `SMB_DOMAIN`
  общие для всех SMB-ресурсов из списка.
- **Auto-unmount** — SMB-шара, смонтированная runner в этом проходе,
  размонтируется сразу после сканирования ресурса. Точки, смонтированные
  до старта runner, не трогаются.
- **Read-only** — все SMB-шары монтируются с `ro`; записи идут только
  в каталог `manager`.

#### Консольный вывод (`docker logs`)

```text
новый цикл 1; ресурсов: 3
  ресурс 1/3: //fileserver-01.corp/Платежи
    [slug_1] //fileserver-01.corp/Платежи -> /mnt/shares/slug_1 (смонтирован сейчас)
    [slug_1] [i] Прогресс: всего 1234, обработано 1000 (850.2/с), осталось 234, ...
    [slug_1] [i] Итого по ресурсу: файлов 1234 (912.5/с), с находками 1, ...
    [slug_1] готово: файлов 1234, находок 1 (880.2/с)
  обработано ресурсов 1/3, осталось 2
  итого по проходу: файлов 1234 (850.0/с), с находками 1, ...
  ресурс 2/3: //fileserver-01.corp/Кадры
    [slug_2] ...
  ...
  итог прохода: ресурсов 3, файлов 6500 (720.3/с), с находками 4, ...
цикл 1 завершён
```

#### Управление (файлы `control/` в `manager`)

| Действие | Команда (Windows-хост) |
|----------|------------------------|
| Пауза после текущего файла | `New-Item -ItemType File D:\dcap\manager\control\pause` |
| Возобновить (с места останова) | `Remove-Item D:\dcap\manager\control\pause` |
| Прервать проход и завершить | `New-Item -ItemType File D:\dcap\manager\control\stop` или `docker stop dcap-runner` |
| Остановить навсегда | `docker stop dcap-runner && docker rm dcap-runner` |
| Перезапуск (дочитка прерванного) | `docker start dcap-runner` (тот же `-v manager`) |

#### Docker Compose (runner)

В репозитории есть `docker-compose.runner.yml`:

```powershell
# Файлы создаются в папке, где лежит docker-compose.runner.yml:
New-Item -ItemType Directory .\manager\conf, .\secrets -Force
# .\manager\conf\list.txt — список ресурсов (см. выше)
# .\secrets\password.txt — пароль (НЕ коммитить)
Set-Content -Path ".\secrets\password.txt" -Value "P@ssw0rd!" -NoNewline
# .env рядом с docker-compose.runner.yml:
@"
SCHEDULE=01:00-06:00
SMB_USER=svc-scan
SMB_DOMAIN=CORP
SCAN_THREADS=4
SCAN_ARGS=--no-generic
"@ | Set-Content -Path ".env" -Encoding utf8
# Запуск:
docker compose -f docker-compose.runner.yml up -d
docker compose -f docker-compose.runner.yml logs -f
```

Volume-ы монтируются автоматически (относительно папки с compose-файлом):
`./manager:/manager` (состояние) и `./secrets/password.txt:/secret.txt:ro`
(пароль, read-only).

---

## Переменные окружения

### Переменные entrypoint (разовый скан)

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `SMB_SHARE` | *(пусто)* | Путь к SMB-шаре, например `//fileserver-01.corp/Share`. Если задана — entrypoint маунтит шару через `mount.cifs` и сканирует её. Если пуста — сканирует путь из первого аргумента командной строки (bind-mount / локальная папка). |
| `SMB_USER` | *(пусто)* | Учётная запись для CIFS-аутентификации. Формат: `user` или `DOMAIN\user` (домен в имени). Передаётся как `username=...` в `mount.cifs`. |
| `SMB_DOMAIN` | *(пусто)* | Домен / WORKGROUP для AD. Добавляет опцию `domain=...`. Необязательно, если домен уже включён в `SMB_USER` (формат `DOMAIN\user`). |
| `SMB_PASS` | *(пусто)* | Пароль напрямую. Виден в `docker inspect` — для продакшена используйте `SMB_PASS_FILE`. Альтернатива файлу; если заданы оба — приоритет у `SMB_PASS_FILE`. |
| `SMB_PASS_FILE` | *(пусто)* | Путь внутри контейнера к текстовому файлу с паролем (пробелы/переводы строк обрезаются). Пример: `-v "D:\secrets\password.txt:/secret.txt:ro" -e SMB_PASS_FILE=/secret.txt`. |
| `SMB_OPTS` | `,noperm,vers=3.0,cache=none` | Дополнительные опции `mount.cifs`. `vers=3.0` — версия протокола SMB (задайте `2.0`, если NAS не поддерживает 3.x); `cache=none` — без кеширования (актуальность данных); `noperm` — без проверки прав Linux. Опция `ro` добавляется автоматически. |
| `SMB_MOUNT` | `/mnt/share` | Точка монтирования шары внутри контейнера. При сканировании используется как первый аргумент сканера (по умолчанию). |

**Важно:** для `mount.cifs` контейнер должен быть запущен с флагом `--privileged`.

### Переменные супервайзера runner

Запускаются командой: `docker run ... ghcr.io/...:latest runner`.

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `RESOURCE_LIST` | `<MANAGER_DIR>/conf/list.txt` | Текстовый файл со списком ресурсов. По одному на строку; `#` — комментарии; строки с `//` или `\\` — SMB-шары (маунтятся runner'ом); обычные пути — доступные локальные/bind-каталоги. Кириллица и пробелы допустимы. |
| `MANAGER_DIR` | `/manager` | Корневой каталог состояния. Должен быть примонтирован как persist-volume (содержит `state/`, `report/`, `cycle.json`, `unified.log`). |
| `MOUNT_ROOT` | `/mnt/shares` | Корень точек монтирования SMB. Каждая шара получает подкаталог `<MOUNT_ROOT>/<slug>`. |
| `SCHEDULE` | `always` | Расписание работы (см. таблицу ниже). Время берётся в часовом поясе контейнера (`TZ`). |
| `SCAN_LOOP` | `0` | `0` — один проход за окно; `1` — повторять проходы непрерывно в течение окна. |
| `RUN_ONCE` | `0` | `1` — после одного полного прохода по списку завершиться с кодом `0`. Прерванный проход дочитывается, затем выход. Удобно для cron / одноразовых запусков. |
| `UNIFIED_LOG` | `<MANAGER_DIR>/unified.log` | Единый лог находок (TSV). |
| `SCANNER` | `/usr/local/bin/dcap-scan` | Путь к бинарнику сканера внутри образа. |
| `SCAN_THREADS` | `4` | Количество потоков (параллельных file-walkers) на каждый ресурс. |
| `SCAN_ARGS` | *(пусто)* | Дополнительные флаги сканера через пробел (см. таблицу флагов ниже). Пример: `--no-generic --strict-filter --min-entropy 3.2`. |
| `TZ` | `UTC` | Часовой пояс контейнера для `SCHEDULE`. Примеры: `Europe/Moscow`, `UTC`. |

#### Расписание (SCHEDULE)

| Формат | Поведение |
|--------|-----------|
| `always` *(по умолчанию)* | Работает, пока не остановят. |
| `01:00-06:00` | Работает только в окне 01:00–06:00. |
| `01:00-06:00;12:00-13:00` | Несколько окон через `;`. |
| `23:00-01:00` | Окно через полночь (работает 23:00–06:00). |

### Флаги сканера (для SCAN_ARGS)

Флаги управляют фильтрацией находок и снижают шум. **Все — фильтры-«убийцы»:**
могут скрыть и настоящие секреты. Используйте для шумных деревьев
(документация, локализации, схемы).

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `--min-entropy N` | `3.0` | Минимальная энтропия Шеннона значения (бит/символ). Действует только на правилах с `entropy_check=true` — оценивает «случайность» значения по соотношению уникальных символов к длине. |
| `--min-length N` | `4` | Минимальная длина значения (применяется ко всем правилам). |
| `--confidence-threshold N` | `0` | Отбрасывает находки правил с confidence ниже N. Confidence задаётся статически для каждого правила (0.70–0.99); рантайм-оценка значения не входит. |
| `--no-generic` | выкл | Отключает шумные правила `GENERIC_SECRET` и `GENERIC_TOKEN`. |
| `--require-mixed` | выкл | Требует от значения ≥ 8 символов и ≥ 3 из 4 классов (A–Z, a–z, 0–9, спецсимволы). Только для правил «секрет по имени». |
| `--strict-filter` | выкл | Экстра-фильтр плейсхолдеров (`password123`, `example_123`), значений < 6 символов, шаблонных имён. |

> Проверенные отсевы на эталонном наборе (39 находок):
> `--no-generic` → 30, `--require-mixed` → 33, `--min-length 8` → 38,
> `--min-entropy 3.5` → 26, `--confidence-threshold 0.86` → 15.

---

## Лог-отчёт и state

Значения секретов **записываются в лог-файл** (удобно разбирать шум):

```text
[ФАЙЛЫ С НАХОДКАМИ]
  /mnt/shares/slug_1/config.yaml
    CRED_API_KEY, CRED_PASSWORD
[НАХОДКИ]
  /mnt/shares/slug_1/config.yaml:12 :: CRED_PASSWORD (conf 0.75)
      value: SuperSecret1!
      context: db_password=SuperSecret1!
[НЕ УДАЛОСЬ ОБРАБОТАТЬ]
  /mnt/shares/slug_1/broken.docx :: не удалось извлечь текст (...)
```

**State-файл** (`state/<slug>.c<N>.tsv`) хранит только пути, типы файлов
и причины ошибок — секреты **не попадают** ни в state, ни в `cycle.json`.
При повторном запуске с тем же циклом уже обработанные файлы пропускаются.

## Паритет с Python-сканером

Паритет по находкам с `scan_folder.py` подтверждён на `test_scan_tree`
(1175 файлов) и синтетике новых паттернов (39). На корпусе ложных
срабатываний (локализации, документация, PowerCLI-скрипт) — 0 находок
при сохранении эталона.
