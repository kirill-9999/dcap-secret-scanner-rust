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

В лог **не записываются сами значения секретов** — только пути и типы:

```text
[ФАЙЛЫ С НАХОДКАМИ]
  D:\test_files\config.py
    CRED_API_KEY, CRED_PASSWORD
[НЕ УДАЛОСЬ ОБРАБОТАТЬ]
  D:\test_files\broken.docx :: не удалось извлечь текст (...)
```

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

## Проверено (10 потоков, сетевой диск Z:)

| Дерево        | Файлов | Python       | Rust        | Ускорение |
|---------------|--------|--------------|-------------|-----------|
| `bench_200k`  | 200k   | 628.4 s      | 552.8 s     | ~12%      |
| `bench`       | 776k   | 2108.2 s     | 1785.8 s    | ~15%      |

Паритет по находкам с Python-сканером подтверждён на `test_scan_tree` (1175) и
синтетике новых паттернов (39). С корпусом ложных срабатываний (локализации,
документация, PowerCLI-скрипт) — 0 находок при сохранении эталона.