# Release image: a static binary on distroless, running as non-root.
FROM golang:1.27.1@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS build
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
