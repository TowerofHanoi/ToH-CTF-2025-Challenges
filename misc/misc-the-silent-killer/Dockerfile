
FROM rust:1.87 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y netcat-traditional && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/killer /usr/local/bin/killer

COPY dbfile.json /app/dbfile.json
RUN chmod 666 /app/dbfile.json

EXPOSE 4242
