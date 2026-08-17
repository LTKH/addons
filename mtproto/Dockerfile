ARG GOLANG_IMAGE="golang:1.26.6-alpine"
ARG TARGETARCH="arm64"
ARG BUILD_FROM="ghcr.io/home-assistant/aarch64-base:3.18"

# === Этап 1: Сборка Go-приложения ===
FROM ${GOLANG_IMAGE} AS builder

WORKDIR /build

# Копируем файлы зависимостей и исходный код
COPY . .

# Собираем оптимизированный бинарный файл без лишней отладочной информации
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o /build/mtproto app/main.go

# === Этап 2: Финальный образ для Home Assistant ===
FROM ${BUILD_FROM}

WORKDIR /app

# Копируем скомпилированный бинарник из первого этапа
COPY --from=builder /build/mtproto /app/mtproto
COPY run.sh /app/run.sh

# Делаем скрипт запуска исполняемым
RUN chmod a+x /app/run.sh

# Открываем порт внутри Docker
EXPOSE 8080

CMD [ "/app/run.sh" ]