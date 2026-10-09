FROM rust:1.97.1-alpine3.24 AS build

RUN apk add --no-cache musl-dev

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# musl links the binary statically, so the final image needs nothing beside it
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=ldap-app-password-proxy-target,target=/app/target,sharing=locked \
  cargo build --release --locked \
  && cp target/release/ldap-app-password-proxy /ldap-app-password-proxy

FROM scratch

COPY --from=build /ldap-app-password-proxy /ldap-app-password-proxy

USER 65534:65534

ENTRYPOINT ["/ldap-app-password-proxy"]
