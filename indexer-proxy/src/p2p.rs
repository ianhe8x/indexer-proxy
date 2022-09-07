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

use async_trait::async_trait;
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use subql_proxy_utils::p2p::{GroupId, P2pHandler, PeerId, Response};
use tokio::sync::RwLock;

use crate::account::ACCOUNT;
use crate::cli::COMMAND;
use crate::payg::{open_state, query_state};
use crate::project::{get_project, list_projects};

pub static PEER: Lazy<RwLock<PeerId>> = Lazy::new(|| RwLock::new(PeerId::random()));

pub async fn update_peer(peer: PeerId) {
    let mut key = PEER.write().await;
    *key = peer;
    drop(key);
}

pub struct IndexerP2p;

#[async_trait]
impl P2pHandler for IndexerP2p {
    async fn channel_handle(info: &str) -> Response {
        channel_handle(info).await
    }

    async fn info_handle(group: Option<GroupId>) -> String {
        let account = ACCOUNT.read().await;
        let peer_str = PEER.read().await.to_base58();
        let data = if let Some(group) = group {
            let (id, price) = if let Ok(project) = get_project(&group.id()) {
                (group.id(), project.price)
            } else {
                ("", "".to_owned())
            };
            json!({
                "endpoint": COMMAND.endpoint(),
                "peer": peer_str,
                "indexer": format!("{:?}", account.indexer),
                "controller": format!("{:?}", account.controller),
                "deployment": id,
                "price": price,
            })
        } else {
            let projects = list_projects();
            json!({
                "endpoint": COMMAND.endpoint(),
                "peer": peer_str,
                "indexer": format!("{:?}", account.indexer),
                "controller": format!("{:?}", account.controller),
                "deployments": projects,
            })
        };
        drop(account);

        serde_json::to_string(&data).unwrap()
    }

    async fn event() {
        todo!()
    }
}

/// Handle the state channel request/response infos.
async fn channel_handle(infos: &str) -> Response {
    let params = serde_json::from_str::<Value>(infos).unwrap_or(Value::default());
    if params.get("method").is_none() || params.get("state").is_none() {
        return Response::Error("Invalid request".to_owned());
    }
    let state_res = serde_json::from_str::<Value>(params["state"].as_str().unwrap());
    if state_res.is_err() {
        return Response::Error("Invalid request state".to_owned());
    }
    let state = state_res.unwrap(); // safe unwrap.
    match params["method"].as_str().unwrap() {
        "open" => match open_state(&state).await {
            Ok(state) => Response::StateChannel(serde_json::to_string(&state).unwrap()),
            Err(err) => Response::Error(err.to_status_message().1),
        },
        "query" => {
            if params.get("project").is_none() || params.get("query").is_none() {
                return Response::Error("Invalid request".to_owned());
            }
            let project = params.get("project").unwrap().as_str().unwrap();
            let query_raw = params.get("query").unwrap().as_str().unwrap();
            let query: Value = serde_json::from_str(query_raw).unwrap();
            match query_state(project, &state, &query).await {
                Ok((state, query)) => {
                    Response::StateChannel(serde_json::to_string(&json!(vec![query, state])).unwrap())
                }
                Err(err) => Response::Error(err.to_status_message().1),
            }
        }
        _ => Response::Error("Invalid request".to_owned()),
    }
}
