# syntax=docker/dockerfile:1
# Multi-stage, multi-arch (amd64 + arm64), non-root runtime.
# Default: Python reference server (FastAPI/uvicorn) on :3200.
# Set RUN_RUST=1 at runtime to run the Rust implementation instead.

FROM python:3.12-slim AS base
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY bastion.py ./

FROM base AS test
RUN pip install --no-cache-dir pytest
COPY tests/ tests/
RUN python -m pytest tests/ -q

FROM rust:1-slim AS rust-builder
WORKDIR /build
COPY Cargo.toml ./
COPY src/ src/
RUN cargo build --release

FROM base AS runtime
COPY --from=rust-builder /build/target/release/bastion /usr/local/bin/bastion
RUN useradd --create-home --uid 1000 appuser
USER appuser
ENV RUN_RUST=0
EXPOSE 3200
CMD ["sh", "-c", "if [ \"$RUN_RUST\" = \"1\" ]; then exec bastion; else exec python -m uvicorn bastion:app --host 0.0.0.0 --port 3200; fi"]
