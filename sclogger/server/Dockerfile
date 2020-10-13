FROM golang:alpine AS builder
RUN mkdir /app
ADD . /app/
WORKDIR /app
RUN go build -o logserver server.go

FROM alpine
RUN mkdir /app
WORKDIR /app
COPY --from=builder /app/logserver .

ENV LOGGER_PORT 8082

CMD ["./logserver"]