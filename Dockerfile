# syntax=docker/dockerfile:1

# --- dashboard ---
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# --- binaries ---
FROM golang:1.27-alpine AS build

WORKDIR /src
ENV CGO_ENABLED=0
ENV GOPROXY=https://goproxy.cn,direct

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN go build -trimpath -ldflags "-s -w -X github.com/yqjwxz/beacon/internal/version.Version=${VERSION} -X github.com/yqjwxz/beacon/internal/version.Commit=${COMMIT}" -o /out/beacon ./cmd/beacon && \
    go build -trimpath -ldflags "-s -w -X github.com/yqjwxz/beacon/internal/version.Version=${VERSION} -X github.com/yqjwxz/beacon/internal/version.Commit=${COMMIT}" -o /out/beacon-server ./cmd/beacon-server

# --- runtime ---
FROM alpine:3.20
RUN adduser -D -H -u 10001 beacon
COPY --from=build /out/beacon /usr/local/bin/beacon
COPY --from=build /out/beacon-server /usr/local/bin/beacon-server
COPY --from=web /web/dist /app/web
USER 10001
EXPOSE 8080
ENTRYPOINT ["beacon-server", "-web-dir", "/app/web"]
