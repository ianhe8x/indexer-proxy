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

use ethers::types::U256;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;
use subql_utils::{
    error::Error,
    request::{graphql_request, GraphQLQuery},
    types::Result,
};
use tdn::types::group::hash_to_group_id;

use crate::graphql::{poi_with_block, METADATA_QUERY, POI_LATEST};
use crate::metrics::add_metrics_query;
use crate::p2p::send;
use crate::payg::merket_price;

pub static PROJECTS: Lazy<Mutex<HashMap<String, Project>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone)]
pub struct Project {
    pub query_endpoint: String,
    pub payg_price: U256,
    pub payg_expiration: u64,
    pub payg_overflow: U256,
}

pub fn add_project(
    deployment_id: String,
    query_endpoint: String,
    payg_price: U256,
    payg_expiration: u64,
    payg_overflow: U256,
) {
    let mut map = PROJECTS.lock().unwrap();

    let is_had = map.contains_key(&deployment_id);

    map.insert(
        deployment_id.clone(),
        Project {
            query_endpoint,
            payg_price,
            payg_expiration,
            payg_overflow,
        },
    );

    if is_had {
        let gid = hash_to_group_id(deployment_id.as_bytes());
        tokio::spawn(async move {
            let price = merket_price(Some(deployment_id.clone())).await;
            let data = serde_json::to_string(&price).unwrap();
            send("project-broadcast-payg", vec![json!(data)], gid).await
        });
    } else {
        let params = vec![json!(&deployment_id)];
        tokio::spawn(async move {
            send("project-join", params, 0).await;
        });
    }
}

pub fn get_project(key: &str) -> Result<Project> {
    let map = PROJECTS.lock().unwrap();
    if let Some(url) = map.get(key) {
        Ok(url.clone())
    } else {
        Err(Error::InvalidProjectId(1032))
    }
}

/// list the project id and price
pub fn list_projects() -> Vec<(String, U256, u64)> {
    let mut projects = vec![];
    let map = PROJECTS.lock().unwrap();
    for (k, v) in map.iter() {
        projects.push((k.clone(), v.payg_price, v.payg_expiration));
    }
    projects
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProjectItem {
    pub id: String,
    #[serde(rename = "queryEndpoint")]
    pub query_endpoint: String,
    #[serde(rename = "price")]
    pub payg_price: String,
    #[serde(rename = "expiration")]
    pub payg_expiration: u64,
    #[serde(rename = "overflow")]
    pub payg_overflow: u64,
}

pub fn handle_project(value: &Value) -> Result<()> {
    let item: ProjectItem = serde_json::from_str(value.to_string().as_str()).unwrap();
    let payg_price = U256::from_dec_str(&item.payg_price).unwrap_or(U256::from(0));
    let payg_overflow = item.payg_overflow.into();
    add_project(
        item.id,
        item.query_endpoint,
        payg_price,
        item.payg_expiration,
        payg_overflow,
    );

    Ok(())
}

pub async fn project_metadata(id: &str) -> Result<Value> {
    project_query(id, &GraphQLQuery::query(METADATA_QUERY)).await
}

pub async fn project_poi(id: &str, block: Option<String>) -> Result<Value> {
    let query = if let Some(block) = block {
        GraphQLQuery::query(&poi_with_block(block))
    } else {
        GraphQLQuery::query(POI_LATEST)
    };
    project_query(id, &query).await
}

pub async fn project_query(id: &str, query: &GraphQLQuery) -> Result<Value> {
    let project = get_project(id)?;

    let now = Instant::now();
    let res = graphql_request(&project.query_endpoint, query).await;
    let time = now.elapsed().as_millis() as u64;

    add_metrics_query(id.to_owned(), time);

    res
}
