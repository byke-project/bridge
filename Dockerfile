# byke bridge: the relay a customer runs in their own network (README.md).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /byke-bridge ./cmd/byke-bridge
RUN mkdir -p /state

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /byke-bridge /byke-bridge
# Owned by the user it runs as, so a new volume mounted here is writable.
COPY --from=build --chown=65532:65532 /state /var/lib/byke-bridge
# Its key and certificate: keep this on a volume, or the relay must be enrolled again.
VOLUME /var/lib/byke-bridge
USER nonroot
ENTRYPOINT ["/byke-bridge"]
