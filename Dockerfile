# syntax=docker/dockerfile:1
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

FROM alpine:3.20
RUN adduser -D -H -u 10001 beacon
COPY --from=build /out/beacon /usr/local/bin/beacon
COPY --from=build /out/beacon-server /usr/local/bin/beacon-server
USER 10001
EXPOSE 8080
ENTRYPOINT ["beacon-server"]
