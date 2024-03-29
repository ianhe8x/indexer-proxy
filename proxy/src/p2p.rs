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
use std::collections::HashMap;
use std::io::Result;
use std::path::PathBuf;
use std::sync::Arc;
use subql_utils::{
    error::Error,
    p2p::{Event, JoinData, ROOT_GROUP_ID, ROOT_NAME},
    request::GraphQLQuery,
};
use tdn::{
    prelude::{
        channel_rpc_channel, start_with_config_and_key, ChannelRpcSender, Config, GroupId,
        HandleResult, NetworkType, Peer, PeerId, PeerKey, ReceiveMessage, RecvType, SendMessage,
        SendType,
    },
    types::{
        group::hash_to_group_id,
        primitives::{vec_check_push, vec_remove_item},
        rpc::{json, rpc_request, RpcError, RpcHandler, RpcParam},
    },
};
use tokio::sync::{mpsc::Sender, RwLock};

use crate::{
    account::get_indexer,
    auth::{check_and_get_agreement_limit, check_and_save_agreement},
    cli::COMMAND,
    metrics::{get_services_version, get_status, get_timer_metrics},
    payg::{merket_price, open_state, query_state},
    project::{project_metadata, project_query},
};

pub static P2P_SENDER: Lazy<RwLock<Vec<ChannelRpcSender>>> = Lazy::new(|| RwLock::new(vec![]));

pub async fn send(method: &str, params: Vec<RpcParam>, gid: GroupId) {
    let senders = P2P_SENDER.read().await;
    if !senders.is_empty() {
        senders[0].send(rpc_request(0, method, params, gid)).await;
    }
}

pub async fn stop_network() {
    let senders = P2P_SENDER.read().await;
    if senders.is_empty() {
        warn!("NONE NETWORK");
    } else {
        debug!("RESTART NEW P2P NETWORK");
        senders[0].send(rpc_request(0, "p2p-stop", vec![], 0)).await;
        drop(senders);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn report_healthy() {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(600)).await; // 10min=600
        let senders = P2P_SENDER.read().await;
        if senders.is_empty() {
            warn!("NONE NETWORK");
        } else {
            debug!("Report projects healthy");
            senders[0]
                .send(rpc_request(0, "project-report-healthy", vec![], 0))
                .await;
        }
        drop(senders);
    }
}

async fn report_metrics() {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(300)).await; // 5min=300
        let senders = P2P_SENDER.read().await;
        if senders.is_empty() {
            warn!("NONE NETWORK");
        } else {
            debug!("Report projects metrics");
            senders[0]
                .send(rpc_request(0, "project-report-metrics", vec![], 0))
                .await;
        }
        drop(senders);
    }
}

async fn report_status() {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await; // 1h=3600
        let senders = P2P_SENDER.read().await;
        if senders.is_empty() {
            warn!("NONE NETWORK");
        } else {
            debug!("Report projects status");
            senders[0]
                .send(rpc_request(0, "project-report-status", vec![], 0))
                .await;
        }
        drop(senders);
    }
}

pub async fn start_network(key: PeerKey) {
    // start new network
    let (out_send, mut out_recv, inner_send, inner_recv) = channel_rpc_channel();
    let mut senders = P2P_SENDER.write().await;
    if !senders.is_empty() {
        senders.pop();
    }
    senders.push(inner_send);
    drop(senders);
    tokio::spawn(async move {
        while let Some(msg) = out_recv.recv().await {
            warn!("GOT NOT HANDLE RPC: {:?}", msg);
        }
    });
    tokio::spawn(report_healthy());
    tokio::spawn(report_metrics());
    tokio::spawn(report_status());

    let mut config = Config::default();
    config.only_stable_data = false;
    config.db_path = Some(PathBuf::from("./.data/p2p"));
    config.rpc_http = None;
    config.p2p_peer = Peer::socket(COMMAND.p2p());
    config.rpc_channel = Some((out_send, inner_recv));
    config.group_ids = vec![ROOT_GROUP_ID];

    let (peer_addr, send, mut out_recv) = start_with_config_and_key(config, key).await.unwrap();
    debug!("Peer id: {:?}", peer_addr);

    let mut init_groups = HashMap::new();
    init_groups.insert(ROOT_GROUP_ID, (ROOT_NAME.to_owned(), vec![]));
    let ledger = Arc::new(RwLock::new(Ledger {
        groups: init_groups,
    }));
    bootstrap(&send).await;

    let rpc_handler = rpc_handler(ledger.clone());
    while let Some(message) = out_recv.recv().await {
        match message {
            ReceiveMessage::Group(gid, msg) => {
                if let Ok(result) = handle_group(gid, msg, ledger.clone()).await {
                    handle_result(result, &send, 0, true).await;
                }
            }
            ReceiveMessage::Rpc(uid, params, is_ws) => {
                if let Ok(result) = rpc_handler.handle(params).await {
                    handle_result(result, &send, uid, is_ws).await;
                }
            }
            ReceiveMessage::NetworkLost => {
                debug!("No network connections, will re-connect");
                bootstrap(&send).await;
            }
            ReceiveMessage::Own(_) => {
                debug!("Nothing about own");
            }
        }
    }
}

async fn handle_result(result: HandleResult, sender: &Sender<SendMessage>, uid: u64, is_ws: bool) {
    let HandleResult {
        mut owns,
        mut rpcs,
        mut groups,
        mut networks,
    } = result;

    loop {
        if !rpcs.is_empty() {
            let msg = rpcs.remove(0);
            sender
                .send(SendMessage::Rpc(uid, msg, is_ws))
                .await
                .expect("TDN channel closed");
        } else {
            break;
        }
    }

    loop {
        if !owns.is_empty() {
            let msg = owns.remove(0);
            sender
                .send(SendMessage::Own(msg))
                .await
                .expect("TDN channel closed");
        } else {
            break;
        }
    }

    loop {
        if !groups.is_empty() {
            let (gid, msg) = groups.remove(0);
            sender
                .send(SendMessage::Group(gid, msg))
                .await
                .expect("TDN channel closed");
        } else {
            break;
        }
    }

    // must last send, because it will has stop type.
    loop {
        if !networks.is_empty() {
            let msg = networks.remove(0);
            sender
                .send(SendMessage::Network(msg))
                .await
                .expect("TDN channel closed");
        } else {
            break;
        }
    }
}

struct Ledger {
    groups: HashMap<GroupId, (String, Vec<PeerId>)>,
}

struct State(Arc<RwLock<Ledger>>);

fn rpc_handler(ledger: Arc<RwLock<Ledger>>) -> RpcHandler<State> {
    let mut rpc_handler = RpcHandler::new(State(ledger));

    rpc_handler.add_method("say_hello", |_gid: GroupId, _params, _state| async move {
        Ok(HandleResult::rpc(json!("hello")))
    });

    rpc_handler.add_method("p2p-stop", |_gid, _params, _state| async move {
        Ok(HandleResult::network(NetworkType::NetworkStop))
    });

    rpc_handler.add_method(
        "project-join",
        |_gid: GroupId, params: Vec<RpcParam>, state: Arc<State>| async move {
            if params.len() != 1 {
                return Err(RpcError::ParseError);
            }
            let project = params[0].as_str().ok_or(RpcError::ParseError)?;
            let gid = hash_to_group_id(project.as_bytes());

            let mut results = HandleResult::new();
            if state.0.read().await.groups.contains_key(&gid) {
                return Ok(results);
            }

            let mut ledger = state.0.write().await;
            ledger.groups.insert(gid, (project.to_owned(), vec![]));
            let (_, root_peers) = ledger.groups.get(&ROOT_GROUP_ID).cloned().unwrap();
            drop(ledger);

            // broadcast event in root group
            results.networks.push(NetworkType::AddGroup(gid));
            let bytes = Event::ProjectJoin(gid).to_bytes();
            for peer in root_peers {
                results
                    .groups
                    .push((ROOT_GROUP_ID, SendType::Event(0, peer, bytes.clone())));
            }

            Ok(results)
        },
    );

    rpc_handler.add_method(
        "project-leave",
        |gid: GroupId, _params: Vec<RpcParam>, state: Arc<State>| async move {
            let mut results = HandleResult::new();

            let mut ledger = state.0.write().await;
            let peers = ledger.groups.remove(&gid);
            let _ = ledger.groups.remove(&gid);
            drop(ledger);

            if let Some((_, peers)) = peers {
                let leave_event = Event::ProjectLeave.to_bytes();
                let ledger = state.0.read().await;
                for peer in peers {
                    let mut is_keep = false;
                    for (_, (_, ps)) in ledger.groups.iter() {
                        if ps.contains(&peer) {
                            is_keep = true;
                            break;
                        }
                    }
                    if is_keep {
                        results
                            .groups
                            .push((gid, SendType::Event(0, peer, leave_event.clone())));
                    } else {
                        results.groups.push((gid, SendType::Disconnect(peer)))
                    }
                }
                drop(ledger);
            }

            Ok(results)
        },
    );

    rpc_handler.add_method(
        "project-report-healthy",
        |_gid: GroupId, _params: Vec<RpcParam>, state: Arc<State>| async move {
            let mut results = HandleResult::new();

            let ledger = state.0.read().await;
            let groups = ledger.groups.clone();
            drop(ledger);

            for (gid, (project, peers)) in groups {
                let res = match project_metadata(&project).await {
                    Ok(res) => res,
                    Err(err) => err.to_json(),
                };
                let data = serde_json::to_string(&res).unwrap_or("".to_owned());

                let event = Event::ProjectHealthy(data).to_bytes();
                for peer in peers {
                    results
                        .groups
                        .push((gid, SendType::Event(0, peer, event.clone())));
                }
            }

            Ok(results)
        },
    );

    rpc_handler.add_method("project-report-metrics", |_, _, _| async move {
        let mut results = HandleResult::new();

        let metrics = get_timer_metrics().await;
        let versions = get_services_version().await;
        if !metrics.is_empty() {
            let indexer = get_indexer().await;
            let event = Event::ProjectMetrics(indexer, versions, metrics).to_bytes();
            for peer in COMMAND.telemetries() {
                results
                    .groups
                    .push((ROOT_GROUP_ID, SendType::Event(0, peer, event.clone())));
            }
        }

        Ok(results)
    });

    rpc_handler.add_method("project-report-status", |_, _, _| async move {
        let mut results = HandleResult::new();

        let status = get_status().await;
        let indexer = get_indexer().await;
        let event = Event::ProjectStatus(indexer, status.0, status.1).to_bytes();
        for peer in COMMAND.telemetries() {
            results
                .groups
                .push((ROOT_GROUP_ID, SendType::Event(0, peer, event.clone())));
        }

        Ok(results)
    });

    rpc_handler.add_method(
        "project-broadcast-payg",
        |gid: GroupId, params: Vec<RpcParam>, state: Arc<State>| async move {
            if params.len() != 1 {
                return Err(RpcError::ParseError);
            }
            let payg = params[0].as_str().ok_or(RpcError::ParseError)?;

            let mut results = HandleResult::new();
            let e = Event::ProjectInfoRes(payg.to_owned()).to_bytes();
            let ledger = state.0.read().await;
            if let Some((_, peers)) = ledger.groups.get(&gid) {
                for p in peers {
                    results
                        .groups
                        .push((gid, SendType::Event(0, *p, e.clone())));
                }
            }

            Ok(results)
        },
    );

    rpc_handler
}

async fn handle_group(
    gid: GroupId,
    msg: RecvType,
    ledger: Arc<RwLock<Ledger>>,
) -> Result<HandleResult> {
    let mut results = HandleResult::new();
    let project = if let Some((project, _)) = ledger.read().await.groups.get(&gid) {
        project.to_owned()
    } else {
        return Ok(results);
    };

    match msg {
        RecvType::Connect(peer, bytes) => {
            debug!("Receive project {} peer {} join", gid, peer.id.short_show());
            let mut is_stable = false;
            if let Ok(data) = bincode::deserialize::<JoinData>(&bytes) {
                let peer_id = peer.id;
                let mut ledger = ledger.write().await;
                for project in data.0 {
                    let gid = hash_to_group_id(project.as_bytes());
                    if let Some((_, peers)) = ledger.groups.get_mut(&gid) {
                        vec_check_push(peers, peer_id);
                        is_stable = true;
                    }
                }
                drop(ledger);
            }

            let projects: Vec<String> = ledger
                .read()
                .await
                .groups
                .iter()
                .map(|(_, (p, _))| p.to_owned())
                .collect();
            let self_bytes = bincode::serialize(&JoinData(projects)).unwrap_or(vec![]);
            let msg = SendType::Result(0, peer, is_stable, false, self_bytes);
            results.groups.push((gid, msg));
        }
        RecvType::Result(peer, _, bytes) => {
            debug!(
                "Receive project {} peer {} join result",
                gid,
                peer.id.short_show()
            );
            if let Ok(data) = bincode::deserialize::<JoinData>(&bytes) {
                let peer_id = peer.id;
                let mut ledger = ledger.write().await;
                for project in data.0 {
                    let gid = hash_to_group_id(project.as_bytes());
                    if let Some((_, peers)) = ledger.groups.get_mut(&gid) {
                        vec_check_push(peers, peer_id);
                    }
                }
                drop(ledger);
            }
        }
        RecvType::Event(peer_id, data) => {
            debug!(
                "Receive project {} event from {}",
                gid,
                peer_id.short_show()
            );
            let event = Event::from_bytes(&data)?;
            match event {
                Event::ProjectJoin(gid) => {
                    let mut ledger = ledger.write().await;
                    if let Some((_, peers)) = ledger.groups.get_mut(&gid) {
                        vec_check_push(peers, peer_id);
                        let e = Event::ProjectJoinRes;
                        let msg = SendType::Event(0, peer_id, e.to_bytes());
                        results.groups.push((gid, msg));
                    }
                    drop(ledger);
                }
                Event::ProjectJoinRes => {
                    let mut ledger = ledger.write().await;
                    if let Some((_, peers)) = ledger.groups.get_mut(&gid) {
                        vec_check_push(peers, peer_id);
                    }
                    drop(ledger);
                }
                Event::ProjectLeave => {
                    // update ledger
                    let mut ledger = ledger.write().await;
                    if let Some((_, peers)) = ledger.groups.get_mut(&gid) {
                        vec_remove_item(peers, &peer_id);
                    }
                    drop(ledger);
                }
                Event::ProjectInfo(project) => {
                    let payg = merket_price(project).await;
                    let e = Event::ProjectInfoRes(serde_json::to_string(&payg)?);

                    let msg = SendType::Event(0, peer_id, e.to_bytes());
                    results.groups.push((gid, msg));
                }
                Event::PaygOpen(uid, state) => {
                    let res = match open_state(&serde_json::from_str(&state)?).await {
                        Ok(state) => state,
                        Err(err) => err.to_json(),
                    };
                    let e = Event::PaygOpenRes(uid, serde_json::to_string(&res)?);
                    let msg = SendType::Event(0, peer_id, e.to_bytes());
                    results.groups.push((gid, msg));
                }
                Event::PaygQuery(uid, query, state) => {
                    let query: GraphQLQuery = serde_json::from_str(&query)?;
                    let state: RpcParam = serde_json::from_str(&state)?;
                    let (res_data, res_state) = match query_state(&project, &query, &state).await {
                        Ok((res_query, res_state)) => (res_query, res_state),
                        Err(err) => (err.to_json(), state),
                    };

                    let e = Event::PaygQueryRes(
                        uid,
                        serde_json::to_string(&res_data)?,
                        serde_json::to_string(&res_state)?,
                    );
                    let msg = SendType::Event(0, peer_id, e.to_bytes());
                    results.groups.push((gid, msg));
                }
                Event::CloseAgreementLimit(uid, agreement) => {
                    let res =
                        match handle_close_agreement_limit(&peer_id.to_hex(), &agreement).await {
                            Ok(data) => data,
                            Err(err) => err.to_json(),
                        };

                    let e = Event::CloseAgreementLimitRes(uid, serde_json::to_string(&res)?);
                    let msg = SendType::Event(0, peer_id, e.to_bytes());
                    results.groups.push((gid, msg));
                }
                Event::CloseAgreementQuery(uid, agreement, query) => {
                    let raw_query = serde_json::from_str(&query)?;
                    let res = match handle_close_agreement_query(
                        &peer_id.to_hex(),
                        &agreement,
                        &project,
                        &raw_query,
                    )
                    .await
                    {
                        Ok(data) => data,
                        Err(err) => err.to_json(),
                    };

                    let e = Event::CloseAgreementQueryRes(uid, serde_json::to_string(&res)?);
                    let msg = SendType::Event(0, peer_id, e.to_bytes());
                    results.groups.push((gid, msg));
                }
                _ => {
                    debug!("Not handle event: {:?}", event);
                }
            }
        }
        _ => {}
    }

    Ok(results)
}

async fn bootstrap(sender: &Sender<SendMessage>) {
    for seed in COMMAND.bootstrap() {
        if let Ok(addr) = seed.parse() {
            let peer = Peer::socket(addr);
            sender
                .send(SendMessage::Network(NetworkType::Connect(peer)))
                .await
                .expect("TDN channel closed");
        }
    }
}

async fn handle_close_agreement_limit(
    signer: &str,
    agreement: &str,
) -> std::result::Result<RpcParam, Error> {
    let (daily_limit, daily_used, rate_limit, rate_used) =
        check_and_get_agreement_limit(signer, &agreement).await?;

    Ok(json!({
        "daily_limit": daily_limit,
        "daily_used": daily_used,
        "rate_limit": rate_limit,
        "rate_used": rate_used,
    }))
}

async fn handle_close_agreement_query(
    signer: &str,
    agreement: &str,
    project: &str,
    query: &GraphQLQuery,
) -> std::result::Result<RpcParam, Error> {
    check_and_save_agreement(signer, &agreement).await?;

    project_query(project, query).await
}
