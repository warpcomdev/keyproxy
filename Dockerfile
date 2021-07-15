FROM golang:1.16 AS builder

WORKDIR /app
COPY go.mod go.sum *.go /app/
COPY configs /app/configs
COPY resources /app/resources
RUN  CGO_ENABLED=0 go build

FROM busybox:1.33
WORKDIR /app
COPY --from=builder /app/keyproxy /app/keyproxy
COPY configs /app/configs
COPY resources /app/resources
ENTRYPOINT ["/app/keyproxy"]
