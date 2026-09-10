# syntax=docker/dockerfile:1
FROM rust:1.98.0-alpine3.21 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3.21
# cifs-utils — утилита mount.cifs для маунта сетевых шаров (Z:, //mynas/...)
# dumb-init — корректная обработка сигналов/сирот-процессов
# findutils — нужен iconv для mount.cifs на некоторых схемах
RUN apk add --no-cache \
        cifs-utils \
        dumb-init \
        findutils \
        python3 \
        ca-certificates \
    && adduser -D -u 1000 scan

COPY --from=builder /app/target/release/dcap-scan /usr/local/bin/dcap-scan
COPY runner/runner.py /app/runner.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Контейнер работает от непривилегированного юзера по умолчанию,
# но SMB-маунт требует root (mount.cifs), поэтому entrypoint поднимает маунт.
USER root
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint.sh"]