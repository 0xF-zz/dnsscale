FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dnsscale .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates \
    && addgroup -S dnsscale \
    && adduser -S -G dnsscale dnsscale
WORKDIR /app
COPY --from=build /out/dnsscale /usr/local/bin/dnsscale
USER dnsscale
ENTRYPOINT ["dnsscale"]
