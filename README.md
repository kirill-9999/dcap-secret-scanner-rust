# dcap-secret-scanner (Rust)

Сканер папок на наличие паролей и SSH-ключей. Полнофункциональный порт
`scan_folder.py` на Rust — потоковый, с большим набором regex-правил под
.NET/Java/Kafka/Redis/k8s/AD-стек, поддержкой Office-файлов (doc/xls/docx/xlsx)
и чтения текста в utf-8/cp1251. Собран как отдельный бинарник и как Docker-образ.

## Сборка бинарника

Требуется Rust (тулчейн `x86_64-pc-windows-gnu` + MinGW-w64, т.к. MSVC-линкер не
предполагается):

```powershell
cargo +stable-x86_64-pc-windows-gnu build --release
# или просто, если линкер настроен:
# cargo build --release
```

Бинарь: `target/release/dcap-scan.exe`

## Использование

```text
dcap-scan <папка> <лог-файл|папка> [потоков] [--no-sniff] [--encoding enc] [--state <файл>] [-v]
          [--min-entropy N] [--min-length N] [--confidence-threshold N]
          [--no-generic] [--require-mixed] [--strict-filter] [--presidio]
```

Примеры:

```powershell
.\target\release\dcap-scan.exe "Z:\test_files" "e:\Temp\logs" 10
.\target\release\dcap-scan.exe "C:\src" .\out.log 8 --no-sniff
.\target\release\dcap-scan.exe "C:\src" .\out.log 8 --state .\state.tsv
.\target\release\dcap-scan.exe "C:\src" .\out.log 8 --no-generic --strict-filter
```

Код возврата: `0` = чисто, `1` = ошибка, `2` = найдены секреты.

## Управление ложными срабатываниями

Сканер уже фильтрует «не-секреты» по значению (плейсхолдеры `your_*`, `example`,
`changeme`, строки вида `NNN=...`, вызовы команд PowerShell), а также пропускает
находки на строках-комментариях (`#`, `//`, `;`, `*`, `--`, `<!--`, `!`). Есть
специальные правила `JWT_SECRET` и `OAUTH_CLIENT_SECRET`. Для сложных случаев
пороги настраиваются флагами:

| Флаг | По умолчанию | Что делает |
|------|--------------|------------|
| `--min-entropy N` | `3.0` | Минимальная энтропия Шеннона значения (бит/символ). Работает только на правилах с `entropy_check=true`. Ниже порога — находка отбрасывается. |
| `--min-length N` | `4` | Минимальная длина значения (применяется ко всем правилам). |
| `--confidence-threshold N` | `0` | Отбрасывает находки правил с уверенностью ниже N (0..1). |
| `--no-generic` | выкл | Отключает шумные правила `GENERIC_SECRET` и `GENERIC_TOKEN`. |
| `--require-mixed` | выкл | Значение должно быть длиной ≥ 8 и содержать ≥3 из 4 категорий символов (верхний/нижний регистр, цифры, спецсимволы). Только для правил «секрет по имени». |
| `--strict-filter` | выкл | Экстра-фильтр плейсхолдеров: `password123`, `example_123`, `simple_name`, значения короче 6 символов. |

Примеры для шумных деревьев (docs, схемы, локализации):

```powershell
.\dcap-scan.exe "C:\docs" out.log 8 --no-generic --strict-filter
.\dcap-scan.exe "C:\src"  out.log 8 --min-entropy 3.2 --no-generic
.\dcap-scan.exe "C:\src"  out.log 8 --confidence-threshold 0.86
```

> Внимание: все флаги — фильтры-«убийцы» (снижают число находок). Они могут
> скрыть и настоящие секреты. Проверенные отсевы на эталонном наборе:
> `--no-generic` 39→30, `--require-mixed` 39→33, `--min-length 8` 39→38,
> `--min-entropy 3.5` 39→26, `--confidence-threshold 0.86` 39→15.

## Лог-отчёт

Значения секретов в лог **записываются** (удобно разбирать шум и ложные
срабатывания):

```text
[ФАЙЛЫ С НАХОДКАМИ]
  D:\test_files\config.py
    CRED_API_KEY, CRED_PASSWORD
[НАХОДКИ]
  D:\test_files\config.py:12 :: CRED_PASSWORD (conf 0.75)
      value: SuperSecret1!
      context: db_password=SuperSecret1!
[НЕ УДАЛОСЬ ОБРАБОТАТЬ]
  D:\test_files\broken.docx :: не удалось извлечь текст (...)
```

В state-файл секреты по-прежнему не попадают (только пути, типы и причины ошибок).

## State (возобновление после прерывания)

`--state <файл>` сохраняет выполненную работу в отдельный файл. При повторном
запуске с тем же файлом уже обработанные файлы пропускаются, а отчёт собирается
из старых и новых данных. Секреты в state тоже не попадают (только пути, типы и
причины ошибок). Для другого `# folder:` state автоматически сбрасывается.

## Docker: сканирование сетевого диска (Z: / SMB-шары)

Проблема: Docker Desktop на Windows/Mac **не отдаёт** сетевые диски (Z:) в
контейнер при bind-mount (папка «не найдена»). Решение: контейнер маунтит SMB-шару
сам через `mount.cifs` внутри себя.

### Сборка образа

```powershell
docker build -t dcap-scan .
```

### Запуск со сканированием SMB-шары

```powershell
docker run --rm --privileged `
  -e SMB_SHARE="//mynas/MainStorage" `
  -e SMB_USER="mynas\username" `
  -e SMB_PASS="ПАРОЛЬ" `
  -e "SMB_OPTS=,vers=3.0,noperm,cache=none" `
  -v "${PWD}\logs:/logs" `
  dcap-scan /mnt/share /logs 10
```

- `--privileged` обязателен для `mount.cifs` внутри контейнера.
- SMB-шары монтируются **read-only** (`ro`) — сканер в них ничего не пишет.
- Лог пишется в bind-папку `logs` на хосте (это локальная папка, она монтируется нормально).
- Пароль безопаснее передать через файл:
  ```powershell
  # password.txt в локальной папке, не коммитить!
  docker run --rm --privileged `
    -e SMB_SHARE="//mynas/MainStorage" `
    -e SMB_USER="mynas\username" `
    -e SMB_PASS_FILE="/secret.txt" `
    -v "D:\secrets\password.txt:/secret.txt:ro" `
    -v "${PWD}\logs:/logs" `
    dcap-scan /mnt/share /logs 10
  ```

### Сканирование обычной bind-mounted папки (без SMB)

```powershell
docker run --rm -v "D:\local\data:/data" dcap-scan /data /out.log 8
```

### Docker Compose (рекомендуется для SMB)

1. Создайте `docker-compose.yml` (готов) и настроение окружения:
   ```powershell
   Copy-Item .env.example .env
   # заполните SMB_SHARE, SMB_USER и пароль (SMB_PASS или secrets/password.txt)
   ```
2. Запуск SMB-сканирования:
   ```powershell
   docker compose up --build
   ```
3. Сканирование локальной bind-mounted папки (без SMB):
   ```powershell
   docker compose run --rm -v "D:\local\data:/data" dcap-scan /data /logs 10
   ```

- `SMB_MOUNT` из `.env` меняет точку монтирования (по умолч. `/mnt/share`); команда сканера по умолчанию — `/mnt/share /logs 10`.
- Отчёты пишутся в `./logs`, пароль — `./secrets/password.txt` (папки в `.gitignore`).
- Лучше не оставлять пароль в `.env` на общем диске — используйте файл `secrets/password.txt`.
- Корректное завершение — после `docker compose up` Ctrl+C, либо `--rm` у `run` убирает контейнер.

## Супервайзер `runner`: периодический скан списка ресурсов

Сканирует по списку сетевых ресурсов с расписанием, паузой, возобновлением и
единым логом находок. Реализован в `runner/runner.py` (в образе — `/app/runner.py`).

### Запуск

```powershell
docker run -d --name dcap-runner --privileged `
  -v "D:\dcap\manager:/manager" `
  -v "D:\dcap\secret.txt:/secret.txt:ro" `
  -e RESOURCE_LIST=/manager/conf/list.txt `
  -e SCHEDULE="01:00-06:00;12:00-13:00" `
  -e SMB_USER="mynas\user" `
  -e SMB_PASS_FILE=/secret.txt `
  dcap-scan runner
```

### Список ресурсов

`RESOURCE_LIST` (по умолчанию `/manager/conf/list.txt`) — по одному ресурсу на
строку; строки с `#` — комментарии. Строка, начинающаяся с `//` или `\\` —
SMB-шара (маунтится в `MOUNT_ROOT/<slug>`); обычный путь (например bind-mounted
папка) считается уже доступным каталогом и сканируется как есть. Имена с
пробелами, слэшами и кириллицей допустимы — вся строка это один ресурс.

```
# production-шары
//fs-06.domain.net/Платежи
//fs-06.domain.net/Кадры
/tmp/shares/fs-06.domain.net-Архив
```

### Структура `/manager` (персистентный volume)

| Путь | Назначение |
|------|------------|
| `conf/list.txt` | список ресурсов |
| `state/<slug>.c<N>.tsv` | состояние прохода по ресурсу (продолжение с места останова) |
| `report/<slug>.c<N>.log` | полный отчёт сканера по ресурсу (с `[НАХОДКИ]`) |
| `unified.log` | единый лог находок |
| `cycle.json` | текущий проход: номер цикла, статусы ресурсов |
| `control/pause` | `touch` → пауза после текущего файла; `rm` → продолжить |
| `control/stop` | `touch` → прервать проход и завершить процесс; при запуске повторный скачок |

Формат `unified.log` — одна находка строкой:
`<время>\t<ресурс>\t<отн.путь>:<строка>\t<подкатегория>\t<уверенность>\t<значение>\t<контекст>`

### Поведение

- **Цикл** = полный проход по списку. Прерванный (stop/падение) проход при
  следующем запуске дочитывается с места останова (по `state/*.tsv` и `cycle.json`);
  завершённые в нём ресурсы не перечитываются. Новый цикл — всегда полная вычитка.
- **Пауза**: `control/pause` останавливает скан после текущего файла (state
  сохраняется), `rm control/pause` возобновляет; `docker stop`/SIGTERM ведёт себя
  как `control/stop`.
- **Расписание**: `SCHEDULE` — окна `HH:MM-HH:MM;...` (в часовом поясе контейнера,
  задаётся через `TZ`); поддерживаются окна через полночь. `always`/пусто — пока
  не остановят. По умолчанию `SCAN_LOOP=0`: один полный проход за окно;
  `SCAN_LOOP=1` повторяет проходы в течение окна. По завершении ресурса его
  итоги агрегируются в `unified.log`.
- **Креды**: `SMB_USER`/`SMB_PASS`/`SMB_PASS_FILE`/`SMB_DOMAIN`/`SMB_OPTS` — общие
  для всех SMB-ресурсов списка.
- Уже смонтированные точки проверяются через `/proc/self/mounts` и не
  перемонтируются; чужая точка перемонтируется.
- Все SMB-ресурсы маунтятся **только для чтения** (опция `ro`, добавляется всегда)
  — сканер их не изменяет; записи идут только в `manager` (state/report/unified.log).

### Быстрый старт: запуск, останов, расписание

1. Подготовьте каталог `manager` — всё состояние runner лежит в нём и
   переживает перезапуски:

   ```powershell
   New-Item -ItemType Directory D:\dcap\manager\conf
   # в D:\dcap\manager\conf\list.txt — по одному ресурсу на строку (см. выше)
   ```

2. Запуск (окно 01:00–06:00, все SMB-шары из списка, креды общие через файл):

   ```powershell
   docker run -d --name dcap-runner --restart unless-stopped --privileged `
     -e "TZ=Europe/Moscow" `
     -e RESOURCE_LIST=/manager/conf/list.txt `
     -e SCHEDULE="01:00-06:00" `
     -e SMB_USER="mynas\user" `
     -e SMB_PASS_FILE=/secret.txt `
     -e SMB_DOMAIN=MYNAS `
     -v "D:\dcap\manager:/manager" `
     -v "D:\dcap\secret.txt:/secret.txt:ro" `
     ghcr.io/kirill-9999/dcap-secret-scanner-rust:latest runner
   ```

   Или через compose (готовый `docker-compose.runner.yml`, пароль в
   `./secrets/password.txt`, окружение — из `.env`):

   ```powershell
   docker compose -f docker-compose.runner.yml up -d
   ```

3. Что происходит дальше:

   - `docker logs -f dcap-runner` — ход работ: старт цикла, ресурсы, находки, паузы;
   - `D:\dcap\manager\unified.log` — единый лог всех находок (путь, подкатегория, значение);
   - `D:\dcap\manager\cycle.json` — текущий проход и статусы ресурсов.

4. Останов и пауза (файлы `control/` в `manager` создаются пустыми):

   | Действие | Действие (Windows-хост) |
   |----------|--------------------------|
   | Пауза после текущего файла | `New-Item -ItemType File D:\dcap\manager\control\pause` |
   | Возобновить (с места останова) | `Remove-Item D:\dcap\manager\control\pause` |
   | Прервать проход и завершить процесс | `New-Item -ItemType File D:\dcap\manager\control\stop` (или `docker stop dcap-runner`) |
   | Остановить вовсе | `docker stop dcap-runner` + `docker rm dcap-runner` |
   | Перезапуск (дочитка прерванного прохода) | `docker start dcap-runner` (тот же `-v manager`) |

   `control/stop` одноразовый — при следующем старте супервайзор удаляет его сам.

5. Расписание — переменная `SCHEDULE`:

   | Значение | Поведение |
   |----------|-----------|
   | `SCHEDULE="01:00-06:00"` | работать только 01:00–06:00 |
   | `SCHEDULE="01:00-06:00;12:00-13:00"` | несколько окон через `;` |
   | `SCHEDULE="23:00-01:00"` | окно через полночь |
   | `SCHEDULE=always` (по умолч.) | работает, пока не остановят |

   Время берётся в часовом поясе контейнера (по умолчанию UTC; добавьте
   `-e "TZ=Europe/Moscow"`, чтобы окна были по Москве). `SCAN_LOOP=1` —
   повторять полные проходы внутри окна; по умолчанию `0` — один проход
   за окно, затем ожидание следующего.

## Переменные окружения (entrypoint)

| Переменная     | Назначение                                        |
|----------------|---------------------------------------------------|
| `SMB_SHARE`    | SMB-шара, напр. `//mynas/MainStorage`             |
| `SMB_USER`     | пользователь (`mynas\user`)                       |
| `SMB_PASS`     | пароль (альтернатива файлу)                       |
| `SMB_PASS_FILE`| путь в контейнере к файлу с паролем               |
| `SMB_DOMAIN`   | домен AD для cifs (опция `domain=`), напр. `MYNAS`; необязательно |
| `SMB_MOUNT`    | точка монтирования (по умолч. `/mnt/share`)         |
| `SMB_OPTS`     | доп. опции cifs, напр. `,vers=3.0,noperm,cache=none` |

Переменные супервайзора `runner` (`docker run ... dcap-scan runner`):

| Переменная        | Назначение                                                        |
|-------------------|-------------------------------------------------------------------|
| `RESOURCE_LIST`   | файл со списком ресурсов (по умолч. `<MANAGER_DIR>/conf/list.txt`)|
| `MANAGER_DIR`     | рабочий каталог с состоянием (по умолч. `/manager`)               |
| `MOUNT_ROOT`      | корень точек монтирования SMB (по умолч. `/mnt/shares`)           |
| `SCHEDULE`        | окна работы `HH:MM-HH:MM;...` или `always` (по умолч. `always`)   |
| `SCAN_LOOP`       | `1` — повторять проходы в течение окна (по умолч. `0`)            |
| `UNIFIED_LOG`     | единый лог (по умолч. `<MANAGER_DIR>/unified.log`)                |
| `SCANNER`         | путь к сканеру (по умолч. `/usr/local/bin/dcap-scan`)             |
| `SCAN_THREADS`    | потоков на ресурс (по умолч. `4`)                                 |
| `SCAN_ARGS`       | доп. флаги сканера через пробел (напр. `--no-generic --strict-filter`)|

## Проверено (10 потоков, сетевой диск Z:)

| Дерево        | Файлов | Python       | Rust        | Ускорение |
|---------------|--------|--------------|-------------|-----------|
| `bench_200k`  | 200k   | 628.4 s      | 552.8 s     | ~12%      |
| `bench`       | 776k   | 2108.2 s     | 1785.8 s    | ~15%      |

Паритет по находкам с Python-сканером подтверждён на `test_scan_tree` (1175) и
синтетике новых паттернов (39). С корпусом ложных срабатываний (локализации,
документация, PowerCLI-скрипт) — 0 находок при сохранении эталона.