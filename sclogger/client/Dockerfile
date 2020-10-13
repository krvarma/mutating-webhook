FROM golang:alpine AS builder
RUN mkdir /app
ADD . /app/
WORKDIR /app
RUN go build -o logclient client.go

FROM alpine
RUN mkdir /app
WORKDIR /app
COPY --from=builder /app/logclient .

ENV LOG_SERVER http://localhost
ENV LOG_PORT 8082

CMD ["./logclient"]