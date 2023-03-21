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
use prometheus::{gather, labels, push_add_metrics, register_int_counter_vec, IntCounterVec};
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::cli::COMMAND;

static TIMER_COUNTER: Lazy<Mutex<HashMap<String, u64>>> = Lazy::new(|| Mutex::new(HashMap::new()));

static QUERY_COUNTER: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "subquery_indexer_query_total",
        "Total number of query request.",
        &["deployment_id"]
    )
    .unwrap()
});

pub async fn get_timer_metrics() -> Vec<(String, u64)> {
    let mut counter = TIMER_COUNTER.lock().await;
    let result = counter.drain().map(|(p, c)| (p, c)).collect();
    *counter = HashMap::new();

    result
}

async fn add_timer_metrics(deployment: String) {
    let mut counter = TIMER_COUNTER.lock().await;
    counter
        .entry(deployment)
        .and_modify(|f| *f += 1)
        .or_insert(1);
}

pub fn add_metrics_query(deployment: String) {
    tokio::spawn(add_timer_metrics(deployment.clone()));

    std::thread::spawn(move || {
        if let Some(url) = &COMMAND.prometheus_endpoint {
            QUERY_COUNTER.with_label_values(&[&deployment]).inc();

            let _res = push_add_metrics(
                "subql_indexer_query",
                labels! {"instance".to_owned() => deployment},
                url,
                gather(),
                None,
            );
        }
    });
}
