#!/bin/sh
# Точка входа контейнера.
#
# Поддерживает сканирование сетевых SMB-шаров (например Z: = //mynas/MainStorage)
# через переменные окружения:
#   SMB_SHARE  - путь к шаре, например //mynas/MainStorage
#   SMB_USER   - пользователь домена (mynas\user или user@domain)
#   SMB_PASS   - пароль (или SMB_PASS_FILE)
#   SMB_PASS_FILE - путь к файлу с паролем (`--mount type=bind,source=...,target=/secret.txt:ro`)
#   SMB_MOUNT  - точка монтирования внутри контейнера (по умолчанию /mnt/share)
#   TARGET     - что сканировать. Если задан SMB_SHARE — маунтим и сканируем SMB_MOUNT.
#                Если нет — сканируем переданный аргументом путь (например bind-mounted папку).
#
# ВАЖНО: Docker Desktop (Windows/Mac) НЕ отдаёт в контейнер сетевые диски при монтировании папки.
# Поэтому сетевую шару маунтим САМИ с помощью mount.cifs внутри контейнера.

set -e

MOUNT="${SMB_MOUNT:-/mnt/share}"

if [ -n "$SMB_SHARE" ]; then
    echo "[entrypoint] Mounting SMB share $SMB_SHARE -> $MOUNT"
    mkdir -p "$MOUNT"

    if [ -n "$SMB_PASS_FILE" ] && [ -f "$SMB_PASS_FILE" ]; then
        PASS="$(cat "$SMB_PASS_FILE")"
    else
        PASS="${SMB_PASS:-}"
    fi
    if [ -z "$PASS" ]; then
        echo "[entrypoint] ERROR: нужно задать SMB_PASS или SMB_PASS_FILE для маунта $SMB_SHARE" >&2
        exit 1
    fi

    MOUNT_ARGS="-o username=${SMB_USER:-},password=$PASS,${SMB_OPTS:-,noperm,vers=3.0,cache=none}"
    mount -t cifs "$SMB_SHARE" "$MOUNT" $MOUNT_ARGS

    T="${1:-$MOUNT}"
    if [ "$T" = "." ] || [ "$T" = "/" ]; then
        T="$MOUNT"
    fi
    [ "$#" -ge 1 ] && shift
    echo "[entrypoint] Scanning $T"
    exec /usr/local/bin/dcap-scan "$T" "$@"
fi

# Без SMB_SHARE — просто выполняем сканер с переданными аргументами.
echo "[entrypoint] No SMB_SHARE set, scanning argument path"
exec /usr/local/bin/dcap-scan "$@"