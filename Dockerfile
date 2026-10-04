# Release image: a static binary on distroless, running as non-root.
FROM golang:1.27.1@sha256:e0174e51e81218523251d85d248a90d24c3d5e81543b4f07a5d66229397db190 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/zeroreads ./cmd/zeroreads

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/zeroreads /usr/local/bin/zeroreads
COPY LICENSE NOTICE THIRD_PARTY_LICENSES /usr/share/doc/zeroreads/
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/zeroreads"]
