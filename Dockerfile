# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
# Module cache layer: only re-downloaded when go.mod/go.sum change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
    -o /out/ecb-relay ./cmd/ecb-relay
# Empty data dir owned by distroless "nonroot" (uid/gid 65532).
RUN mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ecb-relay /ecb-relay
COPY --from=build --chown=65532:65532 /out/data /data
ENV ECB_ADDR=:8080 ECB_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/ecb-relay", "-healthcheck"]
ENTRYPOINT ["/ecb-relay"]
