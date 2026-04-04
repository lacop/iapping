FROM rust:1.94.1-slim AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./

RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

COPY src ./src
COPY README.md ./
RUN touch src/main.rs && \
    cargo build --release

FROM gcr.io/distroless/cc-debian13
COPY --from=builder /app/target/release/iapping /
ENTRYPOINT ["/iapping"]