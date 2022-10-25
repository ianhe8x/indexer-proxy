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
use once_cell::sync::{Lazy, OnceCell};
use serde_json::{json, Value};
use subql_p2p::{
    rpc::{channel_rpc_channel, helper::RpcParam, ChannelAddr, ChannelRpcSender},
    GroupId, Multiaddr, P2pHandler, PeerId, Request, Response,
};
use tokio::sync::{mpsc::Receiver, RwLock};

use crate::payg::{merket_price, open_state, query_state};

pub static P2P_SENDER: OnceCell<ChannelRpcSender> = OnceCell::new();

pub async fn send(msg: RpcParam) {
    P2P_SENDER.get().expect("P2P SENDER is not initialized").send(msg).await;
}

pub async fn listen() -> ChannelAddr {
    let (out_send, out_recv, inner_send, inner_recv) = channel_rpc_channel();
    tokio::spawn(async move { handle_channel(out_recv).await });
    P2P_SENDER.set(inner_send).unwrap();

    (out_send, inner_recv)
}

async fn handle_channel(mut out_recv: Receiver<RpcParam>) {
    while let Some(msg) = out_recv.recv().await {
        // Do nothings
        debug!("{}", msg);
    }
}

pub static PEER: Lazy<RwLock<PeerId>> = Lazy::new(|| RwLock::new(PeerId::random()));
pub static PEERADDR: OnceCell<Multiaddr> = OnceCell::new();

pub async fn update_peer(peer: PeerId) {
    let mut key = PEER.write().await;
    *key = peer;
    drop(key);
}

pub struct IndexerP2p;

#[async_trait]
impl P2pHandler for IndexerP2p {
    async fn address(addr: Multiaddr) {
        debug!("PUBLIC ADDRESS: {}", addr);
        let _ = PEERADDR.set(addr);
    }

    async fn channel_handle(info: &str) -> Response {
        channel_handle(info).await
    }

    async fn info_handle(group: Option<GroupId>) -> String {
        let project = group.map(|v| v.id().to_owned());
        let data = merket_price(project).await;
        serde_json::to_string(&data).unwrap()
    }

    async fn event() {
        debug!("handle event");
    }

    async fn group_join(peer: PeerId, group: GroupId) -> Option<Request> {
        debug!("Peer:{} join group: {}", peer, group);
        None
    }

    async fn group_leave(peer: PeerId, group: GroupId) {
        debug!("Peer:{} leave group: {}", peer, group);
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
