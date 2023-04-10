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

use serde_json::{json, Value};
use std::collections::HashMap;
use subql_utils::request::{graphql_request, GraphQLQuery};

use crate::account::handle_account;
use crate::cli::COMMAND;
use crate::graphql::{ACCOUNT_QUERY, CHANNEL_QUERY, PAYG_QUERY, PROJECT_QUERY};
use crate::payg::handle_channel;
use crate::project::handle_project;

fn merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (&mut Value::Object(ref mut a), &Value::Object(ref b)) => {
            for (k, v) in b {
                merge(a.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (a, b) => {
            *a = b.clone();
        }
    }
}

pub fn subscribe() {
    tokio::spawn(async {
        let url = COMMAND.graphql_url();
        let mut next_time = 10;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(next_time)).await;
            let query = GraphQLQuery::query(ACCOUNT_QUERY);
            if let Ok(value) = graphql_request(&url, &query).await {
                if let Some(value) = value.pointer("/data/accountMetadata") {
                    if handle_account(value).await.is_ok() {
                        next_time = 120;
                    }
                }
            }
        }
    });

    tokio::spawn(async {
        let url = COMMAND.graphql_url();
        let mut next_time = 10;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(next_time)).await;
            let query = GraphQLQuery::query(PROJECT_QUERY);
            let payg = GraphQLQuery::query(PAYG_QUERY);
            let mut raw_projects = HashMap::new();
            let mut raw_paygs = HashMap::new();
            if let Ok(value) = graphql_request(&url, &query).await {
                if let Some(items) = value.pointer("/data/getAliveProjects") {
                    if let Some(projects) = items.as_array() {
                        for project in projects {
                            let pid = project["id"].as_str().unwrap_or("").to_owned();
                            raw_projects.insert(pid, project.clone());
                        }
                    }
                }
            }
            if let Ok(value) = graphql_request(&url, &payg).await {
                if let Some(items) = value.pointer("/data/getAlivePaygs") {
                    if let Some(paygs) = items.as_array() {
                        for payg in paygs {
                            let pid = payg["id"].as_str().unwrap_or("").to_owned();
                            raw_paygs.insert(pid, payg.clone());
                        }
                    }
                }
            }

            if !raw_projects.is_empty() {
                next_time = 120;
            }

            for (k, project) in raw_projects.iter_mut() {
                if let Some(payg) = raw_paygs.get(k) {
                    merge(project, payg);
                } else {
                    merge(
                        project,
                        &json!({
                            "price": "",
                            "expiration": 0,
                            "overflow": 0,
                        }),
                    );
                }
                let _ = handle_project(project);
            }
        }
    });

    tokio::spawn(async {
        let url = COMMAND.graphql_url();
        let next_time = 120;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(next_time)).await;
            let query = GraphQLQuery::query(CHANNEL_QUERY);
            if let Ok(value) = graphql_request(&url, &query).await {
                if let Some(items) = value.pointer("/data/getAliveChannels") {
                    if let Some(channels) = items.as_array() {
                        for channel in channels {
                            let _ = handle_channel(channel).await;
                        }
                    }
                }
            }
        }
    });
}
