FROM cgr.dev/chainguard/go AS builder
COPY . /app
WORKDIR /app
RUN go build -o bin/main cmd/offat/main.go

FROM cgr.dev/chainguard/glibc-dynamic
COPY --from=builder /app/bin/main /usr/bin/
ENTRYPOINT ["/usr/bin/main"]