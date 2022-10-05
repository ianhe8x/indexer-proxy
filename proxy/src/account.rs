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

use ethers::{
    signers::{LocalWallet, Signer},
    types::Address,
};
use once_cell::sync::Lazy;
use serde_json::json;
use subql_utils::{error::Error, request::graphql_request, types::Result};
use tokio::sync::RwLock;

use crate::cli::COMMAND;

pub struct Account {
    pub indexer: Address,
    pub controller: LocalWallet,
}

impl Default for Account {
    fn default() -> Self {
        let wallet = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<LocalWallet>()
            .unwrap();
        Self {
            indexer: Address::default(),
            controller: wallet,
        }
    }
}

pub static ACCOUNT: Lazy<RwLock<Account>> = Lazy::new(|| RwLock::new(Account::default()));

pub async fn fetch_account_metadata() -> Result<()> {
    let url = COMMAND.graphql_url();
    let query = json!({"query": "query { accountMetadata { indexer controller } }" });
    let result = graphql_request(&url, &query).await;
    let value = result.map_err(|_e| Error::InvalidServiceEndpoint)?;
    let indexer: Address = value
        .pointer("/data/accountMetadata/indexer")
        .ok_or(Error::InvalidServiceEndpoint)?
        .as_str()
        .unwrap_or("")
        .trim()
        .parse()
        .map_err(|_e| Error::InvalidServiceEndpoint)?;

    let fetch_controller = value
        .pointer("/data/accountMetadata/controller")
        .map(|sk| {
            let data = sk.as_str().unwrap_or("").trim();
            if data.len() > 0 {
                Some(data)
            } else {
                None
            }
        })
        .flatten();

    let controller = if let Some(sk) = fetch_controller {
        let sk_values = serde_json::from_str::<serde_json::Value>(sk).map_err(|_e| Error::InvalidController)?;
        if sk_values.get("iv").is_none() || sk_values.get("content").is_none() {
            return Err(Error::InvalidController);
        }
        let sk = COMMAND.decrypt(
            sk_values["iv"].as_str().ok_or(Error::InvalidController)?,
            sk_values["content"].as_str().ok_or(Error::InvalidController)?,
        )?; // with 0x...

        sk[2..].parse::<LocalWallet>().map_err(|_| Error::InvalidController)?
    } else {
        "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<LocalWallet>()
            .unwrap()
    };
    info!("indexer: {:?}, controller: {:?}", indexer, controller.address());

    let new_account = Account { indexer, controller };
    let mut account = ACCOUNT.write().await;
    *account = new_account;

    Ok(())
}

pub async fn get_indexer() -> String {
    format!("{:?}", ACCOUNT.read().await.indexer)
}
