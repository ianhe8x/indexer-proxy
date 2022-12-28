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

use futures_util::{SinkExt, StreamExt};
use reqwest::header::HeaderValue;
use serde_json::{json, Value};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Message},
};

use crate::account::handle_account;
use crate::cli::COMMAND;
use crate::payg::handle_channel;
use crate::project::handle_project;

pub fn subscribe() {
    tokio::spawn(async move {
        subscribe_project_change(COMMAND.graphql_url()).await;
    });
}

async fn subscribe_project_change(mut websocket_url: String) {
    websocket_url.replace_range(0..4, "ws");

    let mut request = websocket_url.into_client_request().unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_str("graphql-ws").unwrap(),
    );
    let (mut socket, _) = connect_async(request).await.unwrap();
    info!("Connected to the websocket server");

    let account_message = json!({
        "type": "start",
        "payload": {
            "query": "subscription {
                accountChanged { indexer controller }
            }"
        }
    })
    .to_string();
    let project_message = json!({
        "type": "start",
        "payload": {
            "query": "subscription {
                projectChanged { id queryEndpoint paygPrice paygExpiration paygOverflow },
            }"
        }
    })
    .to_string();
    let payg_message = json!({
        "type": "start",
        "payload": {
            "query": "subscription {
                channelChanged { id consumer total spent remote price lastFinal expiredAt }
            }"
        }
    })
    .to_string();
    socket.send(Message::Text(account_message)).await.unwrap();
    socket.send(Message::Text(project_message)).await.unwrap();
    socket.send(Message::Text(payg_message)).await.unwrap();

    while let Some(Ok(message)) = socket.next().await {
        let text = message.to_text().unwrap();
        let value = serde_json::from_str::<Value>(text);
        if value.is_err() {
            warn!("incoming message invalid!");
            continue;
        }
        let value = value.unwrap();

        if let Some(account) = value.pointer("/payload/data/accountChanged") {
            debug!("fetch account changed: {}", account);
            let _ = handle_account(account).await.map_err(|e| warn!("{:?}", e));
        }

        if let Some(project) = value.pointer("/payload/data/projectChanged") {
            debug!("fetch project changed: {}", project);
            let _ = handle_project(project, false).map_err(|e| warn!("{:?}", e));
        }

        if let Some(channel) = value.pointer("/payload/data/channelChanged") {
            debug!("fetch channel changed: {}", channel);
            let _ = handle_channel(channel).await.map_err(|e| warn!("{:?}", e));
        }
    }
}
