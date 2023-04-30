# Builder
FROM rust AS builder

ENV NODE_VERSION=16.17.0
RUN apt install -y curl
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash
ENV NVM_DIR=/root/.nvm
RUN . "$NVM_DIR/nvm.sh" && nvm install ${NODE_VERSION}
RUN . "$NVM_DIR/nvm.sh" && nvm use v${NODE_VERSION}
RUN . "$NVM_DIR/nvm.sh" && nvm alias default v${NODE_VERSION}
ENV PATH="/root/.nvm/versions/node/v${NODE_VERSION}/bin/:${PATH}"
RUN npm install --global yarn
RUN node --version
RUN yarn --version

RUN update-ca-certificates

WORKDIR /subql

COPY . .

RUN --mount=type=bind,source=/tmp/.cargo-cache/cargo_bin,target=/root/.cargo/bin/ \
    --mount=type=bind,source=/tmp/.cargo-cache/cargo_reg_index,target=/root/.cargo/registry/index/ \
    --mount=type=bind,source=/tmp/.cargo-cache/cargo_reg_cache,target=/root/.cargo/registry/cache/ \
    --mount=type=bind,source=/tmp/.cargo-cache/cargo_git,target=/root/.cargo/git/db/ \
    --mount=type=bind,source=/tmp/.cargo-cache/target,target=/subql/target/ \
    cargo build --release && mv /subql/target/release/subql-proxy /subql/

# Final image
FROM debian:buster-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    apt-get --assume-yes install curl && \
    update-ca-certificates

WORKDIR /subql

# Copy our build
COPY --from=builder /subql/target/release/subql-proxy .

# Use an unprivileged user.
RUN groupadd --gid 10001 subql && \
    useradd  --home-dir /subql \
             --create-home \
             --shell /bin/bash \
             --gid subql \
             --groups subql \
             --uid 10000 subql
RUN mkdir -p /subql/.local/share && \
	mkdir /subql/data && \
	chown -R subql:subql /subql && \
	ln -s /subql/data /subql/.local/share
USER subql:subql

ENTRYPOINT ["./subql-proxy"]
