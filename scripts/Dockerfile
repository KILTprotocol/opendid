FROM rust:1.72-bookworm as builder-rs
WORKDIR /app
RUN apt update && apt install protobuf-compiler -y
COPY Cargo.toml Cargo.lock metadata-peregrine-11210.scale metadata-spiritnet-11110.scale ./
COPY src ./src
RUN cargo build --release

FROM node:alpine as builder-frontend

WORKDIR /build
COPY ./login-frontend /build
RUN yarn && yarn build

FROM docker.io/library/debian:stable-slim

RUN apt update && apt install -y openssl ca-certificates libssl-dev

COPY --from=builder-rs /app/target/release/opendid /app/opendid
COPY --from=builder-frontend /build/dist /srv

VOLUME /app/config.yaml

CMD [ "/app/opendid", "--config", "/app/config.yaml"]
