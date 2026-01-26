FROM golang:1.24.3 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/trustd ./cmd/trustd

FROM alpine:3.20
RUN apk add --no-cache ca-certificates

COPY --from=build /out/trustd /usr/local/bin/trustd

ENV HTTP_ADDR=:8080
EXPOSE 8080

ENTRYPOINT ["trustd"]
