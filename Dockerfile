# syntax=docker/dockerfile:1.9
#
# The `agentplane` CLI, so a YAML agent needs no Rust toolchain.
#
# `spec.execution.kind: completion` exists precisely so that a file and a key
# are the whole agent. Until this image, that person still had to install a Rust
# toolchain and wait several minutes to run a YAML file — a gap between what the
# declarative tier promises and what it costs to reach.
#
# # Why distroless and not `scratch`
#
# Not an aesthetic call. `Cargo.toml` documents the trust anchor as a decision:
# the verifier is `rustls-platform-verifier`, which reads the **operating
# system's** certificate store, because an operator already administers a CA
# policy and a runtime that ignored it would break every corporate inspection
# proxy while claiming to be more secure.
#
# A `scratch` image has no OS trust store. The verifier would trust nothing and
# every provider handshake would fail. The only way to make `scratch` work is to
# bake in a CA bundle — which quietly re-introduces Mozilla's roots as this
# plane's trust anchors and overrides the operator's policy, in the one artifact
# most likely to run inside a corporate network. That is the same mistake
# `Cargo.toml` records removing when it dropped the phantom `webpki-roots`
# feature.
#
# So: distroless, which carries `ca-certificates`, `/etc/passwd` for a nonroot
# UID and tzdata, and still has no shell, no package manager and no busybox. An
# operator who needs their own anchors mounts them over `/etc/ssl/certs`.
#
# `cc-debian12` rather than `static-debian12`: reqwest 0.13's default HTTPS
# client is `rustls-aws-lc`, which builds C and links `libgcc`. A musl static
# build is smaller and is worth revisiting, but shipping a working image beats
# promising a smaller one.

# Kept in step with `rust-version` by `tools/check-doc-examples.sh`, which
# already holds the justfile, the CI toolchain pin and two lines of README to
# the same number. A fifth copy is fine when something checks it; the failure
# this project actually had was a copy nothing checked.
ARG RUST_VERSION=1.94.1

FROM rust:${RUST_VERSION}-bookworm AS build

# `slim` is every model provider — Anthropic, OpenAI, Gemini, Bedrock, any
# OpenAI-compatible server, and the deterministic fake — because an image that
# cannot reach the model somebody uses is not smaller, it is useless to them.
# `full` adds the *surfaces*: MCP, the A2A peer server, the operator HTTP API,
# Cedar, key rings, governed media, blobs.
ARG FEATURES=cli

WORKDIR /src
COPY . .

# `--locked` so the image is built from the resolved graph the repository tests,
# not from whatever resolved today. A container that drifted from `Cargo.lock`
# would be a second dependency truth.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin agentplane --features "${FEATURES}" \
 && install -Dm755 target/release/agentplane /out/agentplane

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

ARG FEATURES
ARG VERSION=0.0.0
ARG REVISION=unknown

LABEL org.opencontainers.image.title="agentplane" \
      org.opencontainers.image.description="Durable, replayable, policy-governed agent runtime — the CLI" \
      org.opencontainers.image.source="https://github.com/hupe1980/agentplane" \
      org.opencontainers.image.documentation="https://hupe1980.github.io/agentplane/" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      io.github.hupe1980.agentplane.features="${FEATURES}"

COPY --from=build /out/agentplane /usr/local/bin/agentplane

# Manifests are mounted here, so the documented command has a short path in it.
WORKDIR /work

# Already the image's default, restated because it is a security property rather
# than an inherited detail: nothing here needs root, and the journal defaults to
# memory, so the container runs read-only unless somebody asks for `--store`.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/agentplane"]
CMD ["--help"]
