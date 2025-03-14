FROM rust:1.84 as builder
WORKDIR /usr/src/udplbd
RUN apt-get update && apt-get install -y protobuf-compiler sqlite3 && rm -rf /var/lib/apt/lists/*
RUN cargo install sqlx-cli
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "fn lib() {}" > src/lib.rs
RUN cargo build -r
RUN rm src/main.rs src/lib.rs
ENV DATABASE_URL sqlite:///tmp/udplbd.db
COPY . .
RUN cargo sqlx database setup
RUN cargo build --offline -r

FROM debian:bookworm-slim as udplbd
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/udplbd/target/release/udplbd /usr/local/bin/udplbd
CMD ["udplbd", "start"]
