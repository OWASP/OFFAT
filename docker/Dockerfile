# Combined image: the Go DAST binary + the Python white-box/triager pipelines.
# Stage 1 — build the Go DAST engine.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY dast/go.mod dast/go.sum ./dast/
RUN cd dast && go mod download
COPY dast ./dast
RUN cd dast && CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/offat-dast ./cmd/offat-dast

# Stage 2 — runtime.
FROM python:3.12-slim
LABEL org.opencontainers.image.title="offat-ai" \
      org.opencontainers.image.description="AI-augmented API pentesting automation (DAST + SAST)" \
      org.opencontainers.image.source="https://github.com/dmdhrumilmistry/offat-ai" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY --from=build /out/offat-dast /usr/local/bin/offat-dast
COPY triager ./triager
COPY whitebox ./whitebox
COPY knowledge-base ./knowledge-base
COPY examples ./examples
RUN pip install --no-cache-dir ./triager ./whitebox

# Non-root by default.
RUN useradd -m offat
USER offat

# Default: show DAST help. Override the entrypoint for offat-whitebox / offat-triage.
ENTRYPOINT ["offat-dast"]
CMD ["--help"]
