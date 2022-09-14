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

//! Pay-As-You-Go with state channel helper functions.

use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::header::AUTHORIZATION,
};
use ethers::types::U256;
use serde_json::{json, Value};
use subql_proxy_utils::{
    error::Error,
    payg::{OpenState, QueryState},
    request::graphql_request,
    tools::deployment_cid,
};

use crate::account::ACCOUNT;
use crate::cli::COMMAND;
use crate::p2p::PEER;
use crate::project::{get_project, list_projects};

pub async fn merket_price(project_id: Option<String>) -> Value {
    let account = ACCOUNT.read().await;
    let peer_str = PEER.read().await.to_base58();
    let projects: Vec<(String, String)> = if let Some(pid) = project_id {
        if let Ok(project) = get_project(&pid) {
            if project.price == U256::from(0) {
                vec![]
            } else {
                vec![(pid, project.price.to_string())]
            }
        } else {
            vec![]
        }
    } else {
        list_projects()
            .iter()
            .filter_map(|(pid, price)| {
                if *price == U256::from(0) {
                    None
                } else {
                    Some((pid.clone(), price.to_string()))
                }
            })
            .collect()
    };
    json!({
        "endpoint": COMMAND.endpoint(),
        "peer": peer_str,
        "indexer": format!("{:?}", account.indexer),
        "controller": format!("{:?}", account.controller),
        "deployments": projects,
    })
}

pub async fn open_state(body: &Value) -> Result<Value, Error> {
    let mut state = OpenState::from_json(body)?;

    // check project is exists. unify the deployment id store style.
    let project_id = deployment_cid(&state.deployment_id);
    if let Ok(project) = get_project(&project_id) {
        // check project price.
        if project.price != state.price {
            return Err(Error::InvalidProjectPrice);
        }
    } else {
        return Err(Error::InvalidProjectId);
    }

    let account = ACCOUNT.read().await;
    state.sign(&account.controller, false).await?;
    drop(account);

    let (_, _consumer) = state.recover()?;

    let url = COMMAND.graphql_url();

    let mdata = format!(
        r#"mutation {{
             channelOpen(
               id:"{:#X}",
               indexer:"{:?}",
               consumer:"{:?}",
               total:"{}",
               expiration:{},
               deploymentId:"{}",
               callback:"0x{}",
               lastIndexerSign:"0x{}",
               lastConsumerSign:"0x{}",
               price:"{}")
           {{ price }}
        }}"#,
        state.channel_id,
        state.indexer,
        state.consumer,
        state.total,
        state.expiration,
        deployment_cid(&state.deployment_id),
        hex::encode(&state.callback),
        state.indexer_sign,
        state.consumer_sign,
        state.price,
    );

    let query = json!({ "query": mdata });
    let result = graphql_request(&url, &query)
        .await
        .map_err(|_| Error::ServiceException)?;
    let price: U256 = result
        .get("data")
        .ok_or(Error::ServiceException)?
        .get("channelOpen")
        .ok_or(Error::ServiceException)?
        .get("price")
        .ok_or(Error::ServiceException)?
        .as_str()
        .ok_or(Error::ServiceException)?
        .parse()
        .map_err(|_| Error::ServiceException)?;
    state.price = price;

    Ok(state.to_json())
}

pub async fn query_state(project: &str, state: &Value, query: &Value) -> Result<(Value, Value), Error> {
    let project = get_project(project)?;
    let mut state = QueryState::from_json(state)?;

    let account = ACCOUNT.read().await;
    state.sign(&account.controller, false).await?;
    drop(account);
    let (_, _signer) = state.recover()?;
    // TODO more verify the signer

    // query the data.
    let data = match graphql_request(&project.query_endpoint, query).await {
        Ok(result) => {
            let _string = serde_json::to_string(&result).unwrap(); // safe unwrap

            // let _sign = sign_message(string.as_bytes()); // TODO add to header
            // TODO add state to header and request to coordiantor know the response.

            Ok(result)
        }
        Err(_e) => Err(Error::ServiceException),
    }?;

    // query the state.
    let url = COMMAND.graphql_url();
    let mdata = format!(
        r#"mutation {{
             channelUpdate(
               id:"{:#X}",
               spent:"{}",
               isFinal:{},
               indexerSign:"0x{}",
               consumerSign:"0x{}")
           {{ id, spent }}
        }}"#,
        state.channel_id, state.spent, state.is_final, state.indexer_sign, state.consumer_sign
    );

    let query = json!({ "query": mdata });
    let result = graphql_request(&url, &query)
        .await
        .map_err(|_| Error::ServiceException)?;
    let spent: U256 = result
        .get("data")
        .ok_or(Error::PaygConflict)?
        .get("channelUpdate")
        .ok_or(Error::PaygConflict)?
        .get("spent")
        .ok_or(Error::PaygConflict)?
        .as_str()
        .ok_or(Error::PaygConflict)?
        .parse()
        .map_err(|_| Error::PaygConflict)?;
    state.remote = spent;

    Ok((state.to_json(), data))
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthPayg(pub Value);

#[async_trait]
impl<B> FromRequest<B> for AuthPayg
where
    B: Send,
{
    type Rejection = Error;

    async fn from_request(req: &mut RequestParts<B>) -> std::result::Result<Self, Self::Rejection> {
        // Get authorisation header
        let authorisation = req
            .headers()
            .get(AUTHORIZATION)
            .ok_or(Error::NoPermissionError)?
            .to_str()
            .map_err(|_| Error::NoPermissionError)?;

        serde_json::from_str::<Value>(authorisation)
            .map(AuthPayg)
            .map_err(|_| Error::InvalidAuthHeaderError)
    }
}
