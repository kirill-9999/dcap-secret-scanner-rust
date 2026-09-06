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
dcap-scan <папка> <лог-файл|папка> [потоков] [--no-sniff] [--encoding enc] [-v] [--presidio]
```

Примеры:

```powershell
.\target\release\dcap-scan.exe "Z:\test_files" "e:\Temp\logs" 10
.\target\release\dcap-scan.exe "C:\src" .\out.log 8 --no-sniff
```

Код возврата: `0` = чисто, `1` = ошибка, `2` = найдены секреты.

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

## Переменные окружения (entrypoint)

| Переменная     | Назначение                                        |
|----------------|---------------------------------------------------|
| `SMB_SHARE`    | SMB-шара, напр. `//mynas/MainStorage`             |
| `SMB_USER`     | пользователь (`mynas\user`)                       |
| `SMB_PASS`     | пароль (альтернатива файлу)                       |
| `SMB_PASS_FILE`| путь в контейнере к файлу с паролем               |
| `SMB_MOUNT`    | точка монтирования (по умолч. `/mnt/share`)       |
| `SMB_OPTS`     | доп. опции cifs, напр. `,vers=3.0,noperm,cache=none` |

## Проверено (10 потоков, сетевой диск Z:)

| Дерево        | Файлов | Python       | Rust        | Ускорение |
|---------------|--------|--------------|-------------|-----------|
| `bench_200k`  | 200k   | 628.4 s      | 552.8 s     | ~12%      |
| `bench`       | 776k   | 2108.2 s     | 1785.8 s    | ~15%      |

Паритет по находкам с Python-сканером подтверждён на `test_scan_tree` (1175) и
синтетике новых паттернов (39).