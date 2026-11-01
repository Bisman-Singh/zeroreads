# Release image: a static binary on distroless, running as non-root.
FROM golang:1.27.3@sha256:2669ec97bbb6e54602952b4171211116e3fe90e5f9c47619920c74554b3d7d09 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/zeroreads ./cmd/zeroreads

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/zeroreads /usr/local/bin/zeroreads
COPY LICENSE NOTICE THIRD_PARTY_LICENSES /usr/share/doc/zeroreads/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/zeroreads"]
