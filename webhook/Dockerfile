FROM rust:1.58-slim as builder

RUN apt-get update
RUN apt-get install -y libssl-dev build-essential zlib1g-dev pkg-config

RUN mkdir -p /opt/builder

COPY . /opt/builder

WORKDIR /opt/builder

RUN cargo build --release

FROM debian:buster-slim

RUN apt-get update && apt-get install -y ca-certificates libssl-dev

RUN mkdir -p /opt/webhook

COPY --from=builder /opt/builder/target/release/webhook /opt/webhook

CMD ["/opt/webhook/webhook"]
