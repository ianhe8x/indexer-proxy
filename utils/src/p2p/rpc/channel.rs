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

use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use std::io::Result;
use tokio::{
    select,
    sync::mpsc::{Receiver, Sender},
};

use super::helper::RpcParam;
use super::{rpc_inner_channel, ChannelMessage, RpcInnerMessage};

enum FutureResult {
    Out(RpcInnerMessage),
    Stream(ChannelMessage),
}

pub(super) async fn channel_listen(
    send: Sender<RpcInnerMessage>,
    out_send: Sender<RpcParam>,
    mut my_recv: Receiver<ChannelMessage>,
) -> Result<()> {
    let mut rng = ChaChaRng::from_entropy();
    let id: u64 = rng.next_u64();
    let (s_send, mut s_recv) = rpc_inner_channel();
    send.send(RpcInnerMessage::Open(id, s_send))
        .await
        .expect("Channel to Rpc channel closed");

    loop {
        let res = select! {
            v = async { s_recv.recv().await.map(FutureResult::Out) } => v,
            v = async { my_recv.recv().await.map(FutureResult::Stream) } => v,
        };

        match res {
            Some(FutureResult::Out(msg)) => {
                let param = match msg {
                    RpcInnerMessage::Response(param) => param,
                    _ => Default::default(),
                };
                let _ = out_send.send(param).await;
            }
            Some(FutureResult::Stream(msg)) => match msg {
                ChannelMessage::Sync(msg, tx) => {
                    let id: u64 = rng.next_u64();
                    send.send(RpcInnerMessage::Request(id, msg, Some(tx)))
                        .await
                        .expect("Channel to Rpc channel closed");
                }
                ChannelMessage::Async(msg) => {
                    send.send(RpcInnerMessage::Request(id, msg, None))
                        .await
                        .expect("Channel to Rpc channel closed");
                }
            },
            None => break,
        }
    }

    send.send(RpcInnerMessage::Close(id))
        .await
        .expect("Channel to Rpc channel closed");
    Ok(())
}
