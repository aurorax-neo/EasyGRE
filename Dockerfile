# Local / single-host compatible build template (no regional mirrors hardcoded).
# Production deployments may pin a specific image digest via:
# --build-arg RUST_IMAGE=rust:1-alpine@sha256:<digest>
ARG RUST_IMAGE=rust:1-alpine
FROM ${RUST_IMAGE} AS builder

WORKDIR /src
COPY Cargo.toml ./
COPY src ./src

RUN rm -f .cargo/config.toml .cargo/config \
    && RUSTFLAGS="-C target-feature=+crt-static" cargo build --release \
    && install -d -m 1777 /rootfs/tmp \
    && install -d -m 0700 /rootfs/run/easygre \
    && install -d -m 0755 /rootfs/etc \
    && install -m 0755 target/release/easygre /rootfs/easygre

FROM scratch

COPY --from=builder /rootfs /

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/easygre", "healthcheck"]

ENTRYPOINT ["/easygre"]
