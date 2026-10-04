# syntax=docker/dockerfile:1
FROM rust:1.91-bookworm AS build
ARG TARGETARCH
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target,id=mcp-proxy-target-${TARGETARCH} \
    cargo build --release --locked && \
    cp target/release/oauth-to-key-mcp-proxy /usr/local/bin/oauth-to-key-mcp-proxy
RUN mkdir /data && chown 65532:65532 /data

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=build /usr/local/bin/oauth-to-key-mcp-proxy /usr/local/bin/oauth-to-key-mcp-proxy
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/oauth-to-key-mcp-proxy"]
CMD ["--config", "/etc/mcp-proxy/config.toml"]
