FROM rust:1.87-slim

WORKDIR /app

# Cache built dependencies
RUN mkdir -p src && touch src/lib.rs
ADD Cargo.toml Cargo.lock ./
RUN cargo build --release --locked

# Build
ADD . .
RUN touch Cargo.toml
RUN cargo build --release --locked

ENTRYPOINT [ "target/release/web-rust" ]