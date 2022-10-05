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

use std::collections::HashMap;
use std::io::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::{
    net::TcpListener,
    select,
    sync::{
        mpsc::{self, Receiver, Sender},
        oneshot,
    },
};

mod channel;
pub mod helper;
mod http;
mod ws;

use helper::RpcParam;

pub type ChannelAddr = (Sender<RpcParam>, Receiver<ChannelMessage>);

pub struct RpcConfig {
    pub http: Option<SocketAddr>,
    pub ws: Option<SocketAddr>,
    pub channel: Option<ChannelAddr>,
    pub index: Option<PathBuf>,
}

/// packaging the rpc message. not open to ouside.
#[derive(Debug)]
pub struct RpcMessage(pub u64, pub RpcParam, pub bool);

pub fn rpc_channel() -> (Sender<RpcMessage>, Receiver<RpcMessage>) {
    mpsc::channel(128)
}

pub enum ChannelMessage {
    Sync(RpcParam, oneshot::Sender<RpcInnerMessage>),
    Async(RpcParam),
}

/// sender for channel rpc. support sync and no-sync
#[derive(Clone, Debug)]
pub struct ChannelRpcSender(pub Sender<ChannelMessage>);

impl ChannelRpcSender {
    pub async fn send(&self, msg: RpcParam) {
        let _ = self.0.send(ChannelMessage::Async(msg)).await;
    }

    pub async fn sync_send(&self, msg: RpcParam) -> Result<RpcParam> {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChannelMessage::Sync(msg, tx)).await;
        let msg = rx
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        match msg {
            RpcInnerMessage::Response(param) => Ok(param),
            _ => Ok(Default::default()),
        }
    }
}

pub fn channel_rpc_channel() -> (
    Sender<RpcParam>,
    Receiver<RpcParam>,
    ChannelRpcSender,
    Receiver<ChannelMessage>,
) {
    let (out_send, out_recv) = mpsc::channel(128);
    let (inner_send, inner_recv) = mpsc::channel(128);
    (out_send, out_recv, ChannelRpcSender(inner_send), inner_recv)
}

pub async fn start(config: RpcConfig, send: Sender<RpcMessage>) -> Result<Sender<RpcMessage>> {
    let (out_send, out_recv) = rpc_channel();

    let (self_send, self_recv) = rpc_inner_channel();

    server(self_send, config).await?;
    listen(send, out_recv, self_recv).await?;

    Ok(out_send)
}

#[derive(Debug)]
pub enum RpcInnerMessage {
    Open(u64, Sender<RpcInnerMessage>),
    Close(u64),
    Request(u64, RpcParam, Option<oneshot::Sender<RpcInnerMessage>>),
    Response(RpcParam),
}

fn rpc_inner_channel() -> (Sender<RpcInnerMessage>, Receiver<RpcInnerMessage>) {
    mpsc::channel(128)
}

enum FutureResult {
    Out(RpcMessage),
    Stream(RpcInnerMessage),
}

async fn listen(
    send: Sender<RpcMessage>,
    mut out_recv: Receiver<RpcMessage>,
    mut self_recv: Receiver<RpcInnerMessage>,
) -> Result<()> {
    tokio::spawn(async move {
        let mut ws_connections: HashMap<u64, Sender<RpcInnerMessage>> = HashMap::new();
        let mut sync_connections: HashMap<u64, oneshot::Sender<RpcInnerMessage>> = HashMap::new();

        loop {
            let res = select! {
                v = async { out_recv.recv().await.map(FutureResult::Out) } => v,
                v = async { self_recv.recv().await.map(FutureResult::Stream) } => v
            };

            match res {
                Some(FutureResult::Out(msg)) => {
                    let RpcMessage(id, params, is_ws) = msg;
                    if is_ws {
                        if id == 0 {
                            // default send to all ws.
                            for s in ws_connections.values() {
                                let _ = s.send(RpcInnerMessage::Response(params.clone())).await;
                            }
                        } else if let Some(s) = ws_connections.get(&id) {
                            let _ = s.send(RpcInnerMessage::Response(params)).await;
                        }
                    } else {
                        let s = sync_connections.remove(&id);
                        if s.is_some() {
                            let _ = s.unwrap().send(RpcInnerMessage::Response(params));
                        }
                    }
                }
                Some(FutureResult::Stream(msg)) => {
                    match msg {
                        RpcInnerMessage::Request(uid, params, sender) => {
                            let is_ws = sender.is_none();
                            if !is_ws {
                                sync_connections.insert(uid, sender.unwrap());
                            }
                            send.send(RpcMessage(uid, params, is_ws))
                                .await
                                .expect("Rpc to Outside channel closed");
                        }
                        RpcInnerMessage::Open(id, sender) => {
                            ws_connections.insert(id, sender);
                        }
                        RpcInnerMessage::Close(id) => {
                            // clear this id
                            ws_connections.remove(&id);
                            sync_connections.remove(&id);
                        }
                        _ => {} // others not handle
                    }
                }
                None => break,
            }
        }
    });

    Ok(())
}

async fn server(send: Sender<RpcInnerMessage>, config: RpcConfig) -> Result<()> {
    // HTTP blind
    if let Some(http) = config.http {
        tokio::spawn(http::http_listen(
            config.index.clone(),
            send.clone(),
            TcpListener::bind(http).await.map_err(|e| {
                error!("RPC HTTP listen {:?}", e);
                std::io::Error::new(std::io::ErrorKind::Other, "TCP Listen")
            })?,
        ));
    }

    // WS
    if let Some(ws) = config.ws {
        tokio::spawn(ws::ws_listen(
            send.clone(),
            TcpListener::bind(ws).await.map_err(|e| {
                error!("RPC WS listen {:?}", e);
                std::io::Error::new(std::io::ErrorKind::Other, "TCP Listen")
            })?,
        ));
    }

    // Channel
    if let Some((out_send, my_recv)) = config.channel {
        tokio::spawn(channel::channel_listen(send, out_send, my_recv));
    }

    Ok(())
}
