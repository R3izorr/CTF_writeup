FROM golang:1.25-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=1 go build -o server .

FROM alpine:3.21
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080
CMD ["./server"]
