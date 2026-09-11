# syntax=docker/dockerfile:1.7
# Optional corporate root CA(s) for builds behind TLS-intercepting proxies:
# drop *.crt into deploy/ca/ (git-ignored). Harmless when empty.
FROM node:22-alpine AS ui
COPY deploy/ca/ /usr/local/share/ca-certificates/
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/corp-root.crt
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
COPY deploy/ca/ /etc/ssl/certs/
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/ui/dist ./ui/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X github.com/knumchoke/secure-pastebin/internal/version.Version=${VERSION}" \
    -o /out/pastebin ./cmd/pastebin

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pastebin /pastebin
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/pastebin"]
CMD ["serve"]
