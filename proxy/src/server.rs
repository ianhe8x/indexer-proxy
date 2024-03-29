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
    extract::{ConnectInfo, Path},
    http::{Method, Response, StatusCode},
    routing::{get, post},
    Json, Router,
};
use axum_auth::AuthBearer;
use serde::Serialize;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use subql_utils::{
    constants::HEADERS,
    eip712::{recover_consumer_token_payload, recover_indexer_token_payload},
    error::Error,
    request::GraphQLQuery,
};
use tower_http::cors::{Any, CorsLayer};

use crate::account::get_indexer;
use crate::auth::{create_jwt, AuthQuery, AuthQueryLimit, Payload};
use crate::cli::COMMAND;
use crate::contracts::check_agreement_and_consumer;
use crate::metrics::{get_owner_metrics_count, get_owner_metrics_time};
use crate::payg::{open_state, query_state, AuthPayg};
use crate::project::{get_project, project_metadata, project_poi, project_query};

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
        // `POST /query/Qm...955X` goes to query with agreement.
        .route("/query/:deployment", post(query_handler))
        // `GET /query-limit` get the query limit times with agreement.
        .route("/query-limit", get(query_limit_handler))
        // `POST /open` goes to open a state channel for payg.
        .route("/open", post(generate_payg))
        // `POST /payg/Qm...955X` goes to query with Pay-As-You-Go with state channel.
        .route("/payg/:deployment", post(payg_handler))
        // `Get /metadata/Qm...955X` goes to query the metadata (indexer, controller, payg-price).
        .route("/metadata/:deployment", get(metadata_handler))
        // `Get /healthy` goes to query the service in running success (response the indexer)
        .route("/healthy", get(healthy_handler))
        // `Get /poi/Qm...955X/123` goes to query the poi
        .route("/poi/:deployment/:block", get(poi_block_handler))
        // `Get /poi/Qm...955X` goes to query the latest block poi
        .route("/poi/:deployment", get(poi_latest_handler))
        .route("/metrics-count8", get(metrics_count_handler))
        .route("/metrics-time", get(metrics_time_handler))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(HEADERS.to_vec())
                .allow_methods([Method::GET, Method::POST]),
        );

    let ip_address: Ipv4Addr = host.parse().unwrap_or(Ipv4Addr::LOCALHOST);
    let addr = SocketAddr::new(IpAddr::V4(ip_address), port);
    info!("HTTP server bind: {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

async fn generate_token(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<Payload>,
) -> Result<Json<Value>, Error> {
    get_project(&payload.deployment_id)?;
    let indexer = get_indexer().await;
    if indexer.to_lowercase() != payload.indexer.to_lowercase() {
        return Err(Error::AuthCreate(1002));
    }

    let signer = match (&payload.consumer, &payload.agreement) {
        (Some(consumer), Some(agreement)) => recover_consumer_token_payload(
            consumer,
            &payload.indexer,
            agreement,
            &payload.deployment_id,
            payload.timestamp,
            payload.chain_id,
            &payload.signature,
        )?,
        _ => recover_indexer_token_payload(
            &payload.indexer,
            &payload.deployment_id,
            payload.timestamp,
            payload.chain_id,
            &payload.signature,
        )?,
    };

    let (checked, daily, rate, free) = if signer == payload.indexer.to_lowercase() {
        // if signer is indexer itself, return the token
        (true, 0, 0, None)
    } else {
        // if singer is consumer, check signer is consumer,
        // and check whether the agreement is expired and the it is consistent with
        // `indexer` and `consumer`
        match &payload.agreement {
            Some(agreement) => {
                let (checked, daily, rate) =
                    check_agreement_and_consumer(&signer, agreement).await?;
                (checked, daily, rate, None)
            }
            _ => {
                // fixed plan just for try and dispute usecase. 10/minutes
                if let Some(consumer) = &payload.consumer {
                    if signer == consumer.to_lowercase() {
                        (true, COMMAND.free_limit, 10, Some(addr))
                    } else {
                        (false, 0, 0, None)
                    }
                } else {
                    (false, 0, 0, None)
                }
            }
        }
    };

    if checked {
        let token = create_jwt(payload, daily, rate, free).await?;
        Ok(Json(json!(QueryToken { token })))
    } else {
        Err(Error::AuthCreate(1001))
    }
}

async fn query_handler(
    AuthQuery(deployment_id): AuthQuery,
    Path(deployment): Path<String>,
    Json(query): Json<GraphQLQuery>,
) -> Result<Json<Value>, Error> {
    if COMMAND.auth() && deployment != deployment_id {
        return Err(Error::AuthVerify(1004));
    };

    let res = project_query(&deployment, &query).await?;
    Ok(Json(res))
}

async fn query_limit_handler(
    AuthQueryLimit(daily_limit, daily_used, rate_limit, rate_used): AuthQueryLimit,
) -> Result<Json<Value>, Error> {
    Ok(Json(json!({
        "daily_limit": daily_limit,
        "daily_used": daily_used,
        "rate_limit": rate_limit,
        "rate_used": rate_used,
    })))
}

async fn generate_payg(Json(payload): Json<Value>) -> Result<Json<Value>, Error> {
    let state = open_state(&payload).await?;
    Ok(Json(state))
}

async fn payg_handler(
    AuthPayg(state): AuthPayg,
    Path(deployment): Path<String>,
    Json(query): Json<GraphQLQuery>,
) -> Result<Json<Value>, Error> {
    let (query_data, state_data) = query_state(&deployment, &query, &state).await?;
    Ok(Json(json!([query_data, state_data])))
}

async fn metadata_handler(Path(deployment): Path<String>) -> Result<Json<Value>, Error> {
    project_metadata(&deployment).await.map(Json)
}

async fn poi_block_handler(
    Path((deployment, block)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    project_poi(&deployment, Some(block)).await.map(Json)
}

async fn poi_latest_handler(Path(deployment): Path<String>) -> Result<Json<Value>, Error> {
    project_poi(&deployment, None).await.map(Json)
}

async fn healthy_handler() -> Result<Json<Value>, Error> {
    let indexer = get_indexer().await;
    Ok(Json(json!({ "indexer": indexer })))
}

async fn metrics_count_handler(AuthBearer(token): AuthBearer) -> Response<String> {
    if token == COMMAND.metrics_token {
        let body = get_owner_metrics_count().await;
        let res = Response::builder()
            .header(
                "Content-Type",
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )
            .status(StatusCode::OK);
        match res.body(body) {
            Ok(res) => res,
            Err(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("".to_owned())
                .unwrap(),
        }
    } else {
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body("".to_owned())
            .unwrap()
    }
}

async fn metrics_time_handler(AuthBearer(token): AuthBearer) -> Response<String> {
    if token == COMMAND.metrics_token {
        let body = get_owner_metrics_time().await;
        let res = Response::builder()
            .header(
                "Content-Type",
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )
            .status(StatusCode::OK);
        match res.body(body) {
            Ok(res) => res,
            Err(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("".to_owned())
                .unwrap(),
        }
    } else {
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body("".to_owned())
            .unwrap()
    }
}
