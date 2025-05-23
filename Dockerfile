FROM ghcr.io/rust-cross/cargo-zigbuild as builder
WORKDIR /usr/src/udplbd
RUN apt-get update && apt-get install -y protobuf-compiler sqlite3 libssl-dev musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo install --locked sqlx-cli
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "fn lib() {}" > src/lib.rs
RUN cargo zigbuild --release --target x86_64-unknown-linux-musl
RUN rm src/main.rs src/lib.rs
ENV DATABASE_URL sqlite:///tmp/udplbd.db
COPY . .
RUN cargo sqlx database setup
RUN cargo zigbuild --release --target x86_64-unknown-linux-musl

FROM alpine as udplbd
RUN apk --no-cache add ca-certificates curl openssl && update-ca-certificates
COPY --from=builder /usr/src/udplbd/target/x86_64-unknown-linux-musl/release/udplbd /bin/udplbd
CMD ["udplbd", "mock"]
