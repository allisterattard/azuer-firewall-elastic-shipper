FROM golang:1.27.2-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o azure-firewall-shipper

FROM alpine:3.24

RUN apk update && apk upgrade --no-cache && \
    apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/azure-firewall-shipper /app/azure-firewall-shipper

RUN adduser -D -g '' app
USER app

EXPOSE 8080

CMD ["/app/azure-firewall-shipper"]
