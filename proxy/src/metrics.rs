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
use std::collections::HashMap;
use subql_utils::request::REQUEST_CLIENT;
use tokio::sync::Mutex;

use crate::cli::COMMAND;

static TIMER_COUNTER: Lazy<Mutex<HashMap<String, u64>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static OWNER_COUNTER: Lazy<Mutex<HashMap<String, u64>>> = Lazy::new(|| Mutex::new(HashMap::new()));

const JOB_NAME: &str = "indexer_query";
const FIELD_NAME: &str = "query_count";

pub fn listen() {
    let url_some = COMMAND.pushgateway_endpoint.clone();
    if let Some(url) = url_some {
        if url.len() < 10 {
            return;
        }

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let projects = get_owner_metrics().await;
                for (project, count) in projects {
                    let uri = format!("{}/metrics/job/{}/instance/{}", url, JOB_NAME, project);
                    let data = format!("{} {}\n", FIELD_NAME, count);
                    tokio::spawn(async move {
                        let _res = REQUEST_CLIENT
                            .post(uri)
                            .header("X-Requested-With", "Indexer metrics service")
                            .header("Content-type", "text/xml")
                            .body(data)
                            .send()
                            .await;
                    });
                }
            }
        });
    }
}

pub async fn get_timer_metrics() -> Vec<(String, u64)> {
    let mut counter = TIMER_COUNTER.lock().await;
    let mut results = vec![];
    for (project, count) in counter.iter_mut() {
        results.push((project.clone(), *count));
        *count = 0;
    }

    results
}

async fn get_owner_metrics() -> Vec<(String, u64)> {
    let mut counter = OWNER_COUNTER.lock().await;
    let mut results = vec![];
    for (project, count) in counter.iter_mut() {
        results.push((project.clone(), *count));
        *count = 0;
    }

    results
}

pub fn add_metrics_query(deployment: String) {
    tokio::spawn(async move {
        let mut counter = TIMER_COUNTER.lock().await;
        counter
            .entry(deployment.clone())
            .and_modify(|f| *f += 1)
            .or_insert(1);
        drop(counter);

        let mut counter = OWNER_COUNTER.lock().await;
        counter
            .entry(deployment)
            .and_modify(|f| *f += 1)
            .or_insert(1);
        drop(counter);
    });
}
