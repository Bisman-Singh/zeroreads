# Release image: a static binary on distroless, running as non-root.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sievelog ./cmd/sievelog

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sievelog /usr/local/bin/sievelog
COPY LICENSE NOTICE /usr/share/doc/sievelog/
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/sievelog"]
