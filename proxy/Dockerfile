# Builder
FROM localhost:5000/dep-builder:latest AS builder

WORKDIR /subql

COPY . .

RUN cargo build --release

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
