# syntax=docker/dockerfile:1
# cypher server image. Build: docker build -t cypher .

ARG GO_IMAGE=golang:1.26-alpine
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/cypher ./cmd/cypher \
 && mkdir -p /out/etc/cypher /out/var/www/cypher

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cypher /usr/local/bin/cypher
# Owned by the unprivileged user so a named volume mounted here is writable.
COPY --from=build --chown=nonroot:nonroot /out/etc/cypher /etc/cypher
COPY --from=build /out/var/www/cypher /var/www/cypher
ENV CYPHER_CONFIG=/etc/cypher/server.json \
    CYPHER_LISTEN=:8443 \
    CYPHER_PUBLIC_PORT=443
VOLUME /etc/cypher
EXPOSE 8443/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cypher"]
CMD ["serve"]
