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
use subql_utils::{error::Error, query::METADATA_QUERY, request::graphql_request, types::Result};
use tdn::types::group::hash_to_group_id;

use crate::cli::COMMAND;
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
    is_init: bool,
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
            send("group-broadcast-payg", vec![json!(data)], gid).await
        });
    } else {
        let params = vec![json!(&deployment_id)];
        tokio::spawn(async move {
            // waiting 10s for init network
            if is_init {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
            send("group-join", params, 0).await;
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
    #[serde(rename = "paygPrice")]
    pub payg_price: String,
    #[serde(rename = "paygExpiration")]
    pub payg_expiration: u64,
    #[serde(rename = "paygOverflow")]
    pub payg_overflow: u64,
}

pub fn handle_project(value: &Value, is_init: bool) -> Result<()> {
    let item: ProjectItem = serde_json::from_str(value.to_string().as_str()).unwrap();
    let payg_price = U256::from_dec_str(&item.payg_price).unwrap_or(U256::from(0));
    let payg_overflow = item.payg_overflow.into();
    add_project(
        item.id,
        item.query_endpoint,
        payg_price,
        item.payg_expiration,
        payg_overflow,
        is_init,
    );

    Ok(())
}

pub async fn init_projects() {
    // graphql query for getting alive projects
    let url = COMMAND.graphql_url();
    let query = json!({ "query": "query { getAliveProjects { id queryEndpoint paygPrice paygExpiration paygOverflow } }" });
    let value = graphql_request(&url, &query).await.unwrap(); // init need unwrap
    println!("==== DEBUG ==== : {}", value);

    if let Some(items) = value.pointer("/data/getAliveProjects") {
        if let Some(projects) = items.as_array() {
            for project in projects {
                let _ = handle_project(project, true);
            }
        }
    }
}

pub async fn project_metadata(id: &str) -> Result<Value> {
    let project = get_project(id)?;
    let query = json!({ "query": METADATA_QUERY });
    graphql_request(&project.query_endpoint, &query).await
}
