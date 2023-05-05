# Builder
FROM rust:1.69 AS builder

ENV NODE_VERSION=16.20.0
RUN apt install -y curl && update-ca-certificates && curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash
ENV NVM_DIR=/root/.nvm
RUN . "$NVM_DIR/nvm.sh" && nvm install ${NODE_VERSION} && nvm use v${NODE_VERSION} && nvm alias default v${NODE_VERSION} && npm install --global yarn
ENV PATH="/root/.nvm/versions/node/v${NODE_VERSION}/bin/:${PATH}"

WORKDIR /subql

COPY .dummy ./
COPY Cargo.lock ./

