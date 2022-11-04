// This file is part of SubQuery.

// Copyright (C) 2020-2022 SubQuery Pte Ltd authors & contributors
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
#![allow(clippy::or_fun_call)]

#[macro_use]
extern crate tracing;

mod account;
mod auth;
mod cli;
mod contracts;
mod payg;
mod project;
mod prometheus;
mod server;
mod subscriber;

#[cfg(feature = "p2p")]
mod p2p;

use cli::COMMAND;
use tracing::Level;

#[cfg(feature = "p2p")]
use subql_p2p::{libp2p::identity::Keypair, server::server as p2p_server, PeerId};

#[tokio::main]
async fn main() {
    let port = COMMAND.port();
    let host = COMMAND.host();
    let debug = COMMAND.debug();

    let log_filter = if debug { Level::DEBUG } else { Level::INFO };
    tracing_subscriber::fmt().with_max_level(log_filter).init();

    cli::init_redis().await;
    account::init_account().await;
    project::init_projects().await;
    payg::init_channels().await;

    subscriber::subscribe();

    #[cfg(feature = "p2p")]
    {
        let channel = p2p::listen().await;
        let p2p_bind = COMMAND.p2p();
        info!("P2P bind: {}", p2p_bind);
        let seeds = COMMAND.bootstrap();

        let key_path = std::path::PathBuf::from("indexer.key"); // DEBUG TODO
        let key = if key_path.exists() {
            let key_bytes = tokio::fs::read(&key_path).await.unwrap_or(vec![]); // safe.
            Keypair::from_protobuf_encoding(&key_bytes).unwrap()
        } else {
            let key = Keypair::generate_ed25519();
            let _ = tokio::fs::write(key_path, key.to_protobuf_encoding().unwrap()).await;
            key
        };
        let peer_id = PeerId::from(key.public());
        p2p::update_peer(peer_id).await;
        tokio::spawn(async move {
            p2p_server::<p2p::IndexerP2p>(p2p_bind, None, None, Some(channel), None, key)
                .await
                .unwrap();
        });

        // init bootstrap seeds
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            for seed in seeds {
                p2p::send(subql_utils::request::jsonrpc_params(
                    0,
                    "connect",
                    vec![serde_json::json!(seed)],
                ))
                .await
            }
        });
    }

    server::start_server(host, port).await;
}
