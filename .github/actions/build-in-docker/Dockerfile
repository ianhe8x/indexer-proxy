# Builder
FROM rust AS builder

ENV NODE_VERSION=16.20.0
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

COPY .dummy/Cargo.toml ./
COPY Cargo.lock ./
COPY .dummy/proxy/Cargo.toml ./proxy/
COPY .dummy/proxy/src/main.rs ./proxy/src/
COPY .dummy/utils/Cargo.toml ./utils/
COPY .dummy/utils/src/lib.rs ./utils/src/

RUN --mount=type=bind,source=${GITHUB_WORKSPACE}/target,target=/subql/target,rw=true \
    cargo build --release && rm -f target/release/deps/libsubql_utils*
