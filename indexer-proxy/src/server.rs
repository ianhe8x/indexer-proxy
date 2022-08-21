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

#![deny(warnings)]
use axum::{
    extract::Path,
    http::Method,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use std::time::{SystemTime, UNIX_EPOCH};
use subql_proxy_utils::{
    constants::HEADERS,
    eip712::recover_signer,
    error::Error,
    query::METADATA_QUERY,
    request::{graphql_request, proxy_request},
};
use tower_http::cors::{Any, CorsLayer};

use crate::auth::{create_jwt, AuthQuery, Payload};
use crate::payg::{open_state, query_state, AuthPayg};
use crate::project::get_project;
use crate::{account, cli::COMMAND, prometheus};

#[derive(Serialize)]
pub struct QueryUri {
    /// the url refer to specific project
    pub uri: String,
}

#[derive(Serialize)]
pub struct QueryToken {
    /// jwt auth token
    pub token: String,
}

pub async fn start_server(host: &str, port: u16) {
    let app = Router::new()
        // `POST /token` goes to create token for query.
        .route("/token", post(generate_token))
        // `POST /query/123` goes to query with agreement.
        .route("/query/:id", post(query_handler))
        // `POST /open` goes to open a state channel for payg.
        .route("/open", post(generate_payg))
        // `POST /payg/123` goes to query with Pay-As-You-Go with state channel.
        .route("/payg/:id", post(payg_handler))
        // `Get /metadata/123` goes to query the metadata (indexer, controller, payg-price).
        .route("/metadata/:id", get(metadata_handler))
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

pub async fn generate_token(Json(payload): Json<Payload>) -> Result<Json<Value>, Error> {
    get_project(&payload.deployment_id)?;
    let message = format!("{}{}{}", payload.indexer, payload.deployment_id, payload.timestamp);
    let signer = recover_signer(message, &payload.signature).to_lowercase();

    let checked = if signer == payload.indexer.to_lowercase() {
        // if signer is indexer itself, return the token
        true
    } else {
        // if singer is consumer, check signer is consumer,
        // and check whether the agreement is expired and the it is consistent with
        // `indexer` and `consumer`
        match (&payload.consumer, &payload.agreement) {
            (Some(consumer), Some(agreement)) => {
                if signer == consumer.to_lowercase() {
                    let res = proxy_request(
                        "get",
                        COMMAND.service_url(),
                        &format!("/agreements/{}", agreement),
                        "",
                        "".to_owned(),
                        vec![],
                    )
                    .await;
                    if let Ok(data) = res {
                        match (data.get("consumer"), data.get("startDate"), data.get("period")) {
                            (Some(sac), Some(sstart), Some(speriod)) => {
                                let ac = sac.as_str().unwrap_or("");
                                let start = sstart.as_i64().unwrap_or(0);
                                let period = speriod.as_i64().unwrap_or(0);
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map(|s| s.as_secs())
                                    .unwrap_or(0) as i64;
                                now > (start + period) && ac.to_lowercase() == signer
                            }
                            _ => false,
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    };

    if checked {
        let token = create_jwt(payload)?;
        Ok(Json(json!(QueryToken { token })))
    } else {
        Err(Error::JWTTokenCreationError)
    }
}

pub async fn query_handler(
    AuthQuery(deployment_id): AuthQuery,
    Path(id): Path<String>,
    Json(query): Json<Value>,
) -> Result<Json<Value>, Error> {
    if COMMAND.auth() && id != deployment_id {
        return Err(Error::JWTTokenError);
    };

    let query_url = get_project(&id)?;

    prometheus::push_query_metrics(id.to_owned());

    let response = graphql_request(&query_url, &query).await?;
    Ok(Json(response))
}

pub async fn generate_payg(Json(payload): Json<Value>) -> Result<Json<Value>, Error> {
    let state = open_state(&payload).await?;
    Ok(Json(state))
}

pub async fn payg_handler(
    AuthPayg(state): AuthPayg,
    Path(id): Path<String>,
    Json(query): Json<Value>,
) -> Result<Json<Value>, Error> {
    let (state_data, query_data) = query_state(&id, &state, &query).await?;
    prometheus::push_query_metrics(id);
    Ok(Json(json!([query_data, state_data])))
}

pub async fn metadata_handler(Path(id): Path<String>) -> Result<Json<Value>, Error> {
    let query_url = get_project(&id)?;

    // TODO: move to other place
    let _ = account::fetch_account_metadata().await;

    let query = json!({ "query": METADATA_QUERY });
    let response = graphql_request(&query_url, &query).await?;
    Ok(Json(response))
}
