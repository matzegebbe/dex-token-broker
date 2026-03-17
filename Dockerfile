# syntax=docker/dockerfile:1.7

FROM golang:1.26.1 AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG SOURCE_URL=https://github.com/matzegebbe/DexTokenBroker

WORKDIR /src

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN --mount=type=cache,target=/root/.cache/go-build \
	--mount=type=cache,target=/go/pkg/mod \
	CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -mod=readonly -buildvcs=false -trimpath -tags netgo,osusergo \
	-ldflags="-buildid= -s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
	-o /out/dextokenbroker ./cmd/dextokenbroker

FROM gcr.io/distroless/static-debian12:nonroot

ARG SOURCE_URL
ARG VERSION
ARG COMMIT
ARG BUILD_DATE

LABEL org.opencontainers.image.title="DexTokenBroker" \
	org.opencontainers.image.description="OAuth2 token broker for Envoy Gateway and Dex" \
	org.opencontainers.image.source="${SOURCE_URL}" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${COMMIT}" \
	org.opencontainers.image.created="${BUILD_DATE}"

WORKDIR /

COPY --from=build --chown=65532:65532 /out/dextokenbroker /dextokenbroker

EXPOSE 8080

USER nonroot:nonroot
STOPSIGNAL SIGTERM

ENTRYPOINT ["/dextokenbroker"]
