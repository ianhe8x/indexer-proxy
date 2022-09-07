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
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use subql_proxy_utils::{
    error::Error,
    request::{graphql_request, jsonrpc_request},
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{connect, Message};

use crate::cli::COMMAND;

pub static PROJECTS: Lazy<Mutex<HashMap<String, Project>>> = Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone)]
pub struct Project {
    pub query_endpoint: String,
    pub price: String,
}

pub fn add_project(deployment_id: String, query_endpoint: String, price: String, is_init: bool) {
    let mut map = PROJECTS.lock().unwrap();

    #[cfg(feature = "p2p")]
    {
        let is_had = map.contains_key(&deployment_id);
        if !is_had {
            let params = vec![json!(&deployment_id)];
            tokio::spawn(async move {
                // waiting 10s for init network
                if is_init {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
                debug!("p2p group join: {:?}", params);
                let _ = jsonrpc_request(0, &COMMAND.rpc_url(), "group-join", params).await;
            });
        }
    }

    map.insert(deployment_id, Project { query_endpoint, price });
}

pub fn get_project(key: &str) -> Result<Project, Error> {
    let map = PROJECTS.lock().unwrap();
    if let Some(url) = map.get(key) {
        Ok(url.clone())
    } else {
        Err(Error::InvalidProejctId)
    }
}

/// list the project id and price
pub fn list_projects() -> Vec<(String, String)> {
    let mut projects = vec![];
    let map = PROJECTS.lock().unwrap();
    for (k, v) in map.iter() {
        projects.push((k.clone(), v.price.clone()));
    }
    projects
}

#[derive(Serialize, Deserialize, Debug)]
struct ProjectsResponse {
    #[serde(rename = "getAliveProjects")]
    get_alive_projects: Vec<ProjectItem>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProjectItem {
    id: String,
    #[serde(rename = "queryEndpoint")]
    query_endpoint: String,
    #[serde(rename = "paygPrice")]
    price: String,
}

pub async fn fetch_projects(url: &str, is_init: bool) {
    // graphql query for getting alive projects
    let query = json!({ "query": "query { getAliveProjects { id queryEndpoint paygPrice } }" });
    let result = graphql_request(url, &query).await;

    match result {
        Ok(value) => {
            if let Some(v_d) = value.pointer("/data") {
                let v_str: String = serde_json::to_string(v_d).unwrap_or(String::from(""));
                let v: ProjectsResponse = serde_json::from_str(v_str.as_str()).unwrap();
                for item in v.get_alive_projects {
                    add_project(item.id, item.query_endpoint, item.price, is_init);
                }
            }
        }
        Err(e) => error!("Init projects failed: {:?}", e),
    };
}

pub async fn init_projects() {
    let url = COMMAND.graphql_url();
    fetch_projects(&url, true).await;
    debug!("indexing projects: {:?}", PROJECTS.lock().unwrap());

    let url_clone = url.clone();
    tokio::spawn(async move {
        loop {
            debug!("loop fetch projects");
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            fetch_projects(&url_clone, false).await;
        }
    });
}

pub fn subscribe() {
    tokio::spawn(async move {
        subscribe_project_change(COMMAND.graphql_url()).await;
    });
}

async fn subscribe_project_change(mut websocket_url: String) {
    websocket_url.replace_range(0..4, "ws");

    let mut request = websocket_url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", HeaderValue::from_str("graphql-ws").unwrap());
    let (mut socket, _) = connect(request).unwrap();
    info!("Connected to the websocket server");

    let out_message = json!({
        "type": "start",
        "payload": {
            "query": "subscription { projectChanged { id queryEndpoint price } }"
        }
    })
    .to_string();
    socket.write_message(Message::Text(out_message)).unwrap();
    loop {
        let incoming_msg = socket.read_message().expect("Error reading message");
        let text = incoming_msg.to_text().unwrap();
        let value: Value = serde_json::from_str(text).unwrap();
        if let Some(project) = value.pointer("/payload/data/projectChanged") {
            let item: ProjectItem = serde_json::from_str(project.to_string().as_str()).unwrap();
            add_project(item.id, item.query_endpoint, item.price, false);

            debug!("indexing projects: {:?}", PROJECTS.lock().unwrap());
        }
    }
}
