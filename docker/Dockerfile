# OFFAT-AI platform image: the Rust execution engine + the Python platform.
# Stage 1 - build the Rust execution engine.
FROM rust:1.88-slim AS engine
WORKDIR /src
COPY engine-rs ./engine-rs
RUN cd engine-rs && cargo build --release && cp target/release/offat-engine /out-offat-engine

# Stage 2 - runtime.
FROM python:3.12-slim
LABEL org.opencontainers.image.title="offat-ai" \
      org.opencontainers.image.description="AI-augmented API pentesting platform (map, threat-model, test-gen, execute, triage, report)" \
      org.opencontainers.image.source="https://github.com/dmdhrumilmistry/offat-ai" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY --from=engine /out-offat-engine /usr/local/bin/offat-engine
COPY bundle ./bundle
COPY triager ./triager
COPY whitebox ./whitebox
COPY graybox ./graybox
COPY platform ./platform
COPY reporter ./reporter
COPY examples ./examples
RUN pip install --no-cache-dir ./bundle ./triager ./whitebox ./graybox ./platform ./reporter

# Non-root by default.
RUN useradd -m offat
USER offat

# Default: show the platform help. offat-engine and offat-report are also on PATH.
ENTRYPOINT ["offat-platform"]
CMD ["--help"]
