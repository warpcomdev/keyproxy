FROM node:14-alpine as node_builder
WORKDIR /app
COPY package.json package-lock.json /app/
RUN  npm ci
COPY .eslintrc.cjs .prettierrc jsconfig.json svelte.config.js /app/
COPY static /app/static
COPY src /app/src
COPY podstatic /app/podstatic
RUN  npm run build

FROM golang:1.17 AS builder
WORKDIR /app
COPY go.mod go.sum *.go /app/
COPY configs /app/configs
COPY templates /app/templates
COPY --from=node_builder /app/podstatic /app/podstatic
RUN  CGO_ENABLED=0 go build

FROM busybox:1.33
WORKDIR /app
COPY --from=node_builder /app/podstatic /app/podstatic
COPY --from=builder /app/keyproxy /app/keyproxy
COPY configs /app/configs
COPY templates /app/templates
ENTRYPOINT ["/app/keyproxy"]
