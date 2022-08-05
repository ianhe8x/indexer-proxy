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

use axum::{
    extract::Path,
    http::Method,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use subql_proxy_utils::{
    constants::HEADERS,
    error::Error,
    payg::{convert_recovery_sign, convert_sign_to_bytes, convert_string_to_sign, OpenState, QueryState},
};
use tower_http::cors::{Any, CorsLayer};
use web3::{
    contract::tokens::Tokenizable,
    ethabi::encode,
    signing::{keccak256, recover},
    types::{Address, U256},
};

use crate::cli::COMMAND;
use crate::payg::StateChannel;

pub async fn start_server(host: &str, port: u16) {
    let app = Router::new()
        // `POST /query/123` goes to `query_handler`.
        .route("/query/:id", post(query_handler))
        // `POST /open` goes to `open_payg`.
        .route("/open", post(open_payg))
        // `Get /graphql` goes to open graphql playground.
        .route("/graphql", get(|| async { Html(include_str!("./playground.html")) }))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(HEADERS.to_vec())
                .allow_methods([Method::GET, Method::POST]),
        );

    let ip_address: Ipv4Addr = host.parse().unwrap_or(Ipv4Addr::LOCALHOST);
    let addr = SocketAddr::new(IpAddr::V4(ip_address), port);
    info!("HTTP server bind: {}", addr);
    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
}

pub async fn query_handler(Path(id): Path<String>, Json(query): Json<Value>) -> Result<Json<Value>, Error> {
    let channel = StateChannel::get(&id).await?;
    let channel_id = channel.id;
    let state = channel.next_query(COMMAND.signer())?;

    let raw_state = serde_json::to_string(&state.to_json()).unwrap();
    let raw_query = serde_json::to_string(&query).unwrap();
    let res = COMMAND.indexer.query(id, raw_query, raw_state).await;

    match res {
        Ok(mut fulldata) => {
            let query = fulldata[0].take();
            let raw_data = fulldata[1].take();

            // save state to db.
            let state = QueryState::from_json(&raw_data).unwrap();
            StateChannel::renew(channel_id, state).await;

            Ok(Json(query))
        }
        Err(err) => {
            info!("Open Error: {}", err);
            Err(Error::ServiceException)
        }
    }
}

// the input to `open payg`
#[allow(non_snake_case)]
#[derive(Deserialize)]
struct OpenPayg {
    channelId: String,
    indexer: String,
    amount: String,
    expiration: String,
    consumer: String,
    deploymentId: String,
    sign: String,
}

async fn open_payg(Json(payload): Json<OpenPayg>) -> Result<Json<Value>, Error> {
    let channel_id: U256 = payload.channelId.parse()?;
    let indexer: Address = payload.indexer.parse()?;
    let amount: U256 = U256::from_dec_str(&payload.amount)?;
    let expiration: U256 = U256::from_dec_str(&payload.expiration)?;
    let consumer: Address = payload.consumer.parse()?;
    let deployment = hex::decode(payload.deploymentId)?;
    let mut deployment_id = [0u8; 32];
    deployment_id.copy_from_slice(&deployment);
    let sign = convert_string_to_sign(&payload.sign);

    // check the sign.
    let msg = encode(&[channel_id.into_token(), amount.into_token()]);
    let mut bytes = "\x19Ethereum Signed Message:\n32".as_bytes().to_vec();
    bytes.extend(keccak256(&msg));
    let payload = keccak256(&bytes);
    let (i_sign, i_id) = convert_recovery_sign(&sign);
    let signer = recover(&payload, &i_sign, i_id).map_err(|_| Error::InvalidSignature)?;
    if signer != consumer {
        return Err(Error::InvalidSignature);
    }

    // TODO handle consumer
    let state = OpenState::consumer_generate(
        Some(channel_id),
        indexer,
        COMMAND.contract(),
        amount,
        expiration,
        deployment_id,
        convert_sign_to_bytes(&sign),
        COMMAND.signer(),
    )?;
    let raw_state = serde_json::to_string(&state.to_json()).unwrap();
    let res = COMMAND.indexer.open(raw_state).await;

    match res {
        Ok(data) => {
            let state = OpenState::from_json(&data).unwrap();
            StateChannel::add(state).await;
            Ok(Json(data))
        }
        Err(err) => {
            info!("Open Error: {}", err);
            Err(Error::ServiceException)
        }
    }
}
