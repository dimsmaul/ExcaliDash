# Release build of the Rust backend. Migrations are embedded at compile time.
FROM rust:1.93-slim-bookworm AS build
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
 && cp target/release/excalidash-server /excalidash-server

# glibc runtime without a shell; TLS roots are compiled in (webpki-roots).
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /excalidash-server /usr/local/bin/excalidash-server
ENV PORT=8000
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/excalidash-server"]
