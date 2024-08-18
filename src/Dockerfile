FROM cgr.dev/chainguard/go AS builder
WORKDIR /go/src/github.com/owasp/offat
COPY . .
RUN go build -o ./bin/offat ./cmd/offat/

FROM cgr.dev/chainguard/glibc-dynamic
COPY --from=builder /go/src/github.com/owasp/offat/bin/offat /bin/offat
ENTRYPOINT ["/bin/offat"]