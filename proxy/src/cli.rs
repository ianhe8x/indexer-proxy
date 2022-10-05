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

use once_cell::sync::Lazy;
use openssl::symm::{decrypt, Cipher};
use structopt::StructOpt;
use subql_contracts::Network;
use subql_utils::error::Error;

#[cfg(feature = "p2p")]
use subql_p2p::{libp2p::Multiaddr, primitives::DEFAULT_P2P_ADDR};

pub static COMMAND: Lazy<CommandLineArgs> = Lazy::new(CommandLineArgs::from_args);

#[derive(Debug, StructOpt)]
#[structopt(name = "Indexer Proxy", about = "Command line for starting indexer proxy server")]
pub struct CommandLineArgs {
    /// Endpoint of this service
    #[structopt(long = "endpoint", default_value = "http://localhost:8003")]
    pub endpoint: String,
    /// IP address for the server
    #[structopt(long = "host", default_value = "127.0.0.1")]
    pub host: String,
    /// Port the service will listen on
    #[structopt(short = "p", long = "port", default_value = "8003")]
    pub port: u16,
    /// Coordinator service endpoint
    #[structopt(long = "service-url")]
    pub service_url: String,
    /// Secret key for decrypt key
    #[structopt(long = "secret-key")]
    pub secret_key: String,
    /// Enable auth
    #[structopt(short = "a", long = "auth")]
    pub auth: bool,
    /// Auth token duration
    #[structopt(long = "token-duration", default_value = "12")]
    pub token_duration: i64,
    /// Enable debug mode
    #[structopt(short = "d", long = "debug")]
    pub debug: bool,
    /// Enable dev mode
    #[structopt(long = "dev")]
    pub dev: bool,
    /// port of p2p network.
    #[structopt(long = "p2p-port")]
    pub p2p_port: Option<u16>,
    /// Secret key for generate auth token
    #[structopt(short = "j", long = "jwt-secret", default_value = "needchange")]
    pub jwt_secret: String,
    /// Blockchain network type.
    #[structopt(long = "network")]
    pub network: String,
    /// Blockchain network endpoint.
    #[structopt(long = "network-endpoint")]
    pub network_endpoint: String,
}

impl CommandLineArgs {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn graphql_url(&self) -> String {
        self.service_url.clone() + "/graphql"
    }

    pub fn decrypt(&self, iv: &str, ciphertext: &str) -> Result<String, Error> {
        let iv = hex::decode(iv).map_err(|_| Error::InvalidEncrypt)?;
        let ctext = hex::decode(ciphertext).map_err(|_| Error::InvalidEncrypt)?;

        let ptext = decrypt(Cipher::aes_256_ctr(), self.secret_key.as_bytes(), Some(&iv), &ctext)
            .map_err(|_| Error::InvalidEncrypt)?;

        String::from_utf8(ptext).map_err(|_| Error::InvalidEncrypt)
    }

    pub fn debug(&self) -> bool {
        self.debug
    }

    pub fn auth(&self) -> bool {
        self.auth
    }

    pub fn dev(&self) -> bool {
        self.dev
    }

    pub fn token_duration(&self) -> i64 {
        self.token_duration
    }

    #[cfg(feature = "p2p")]
    pub fn p2p(&self) -> Multiaddr {
        if let Some(port) = self.p2p_port {
            format!("/ip4/0.0.0.0/tcp/{}", port).parse().unwrap()
        } else {
            DEFAULT_P2P_ADDR.parse().unwrap()
        }
    }

    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    pub fn network_endpoint(&self) -> &str {
        &self.network_endpoint
    }

    pub fn network(&self) -> Network {
        match self.network.as_str() {
            "testnet" => Network::Testnet,
            "moonbase" => Network::Moonbase,
            "mainnet" => Network::Mainnet,
            _ => Network::Testnet,
        }
    }
}
