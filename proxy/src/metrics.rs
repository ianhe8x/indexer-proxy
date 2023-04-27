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
use prometheus_client::{
    encoding::{text::encode, EncodeLabelSet},
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use std::collections::HashMap;
use std::time::Instant;
use sysinfo::{System, SystemExt};
use tokio::sync::Mutex;

const PROXY_VERSION: &str = env!("CARGO_PKG_VERSION");
pub static COORDINATOR_VERSION: Lazy<Mutex<u32>> = Lazy::new(|| Mutex::new(0));

static TIMER_COUNTER: Lazy<Mutex<HashMap<String, (u64, u64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static UPTIME: Lazy<Instant> = Lazy::new(|| Instant::now());

static OWNER_COUNT: Lazy<Mutex<Family<Labels, Counter>>> =
    Lazy::new(|| Mutex::new(Family::default()));

static OWNER_TIME: Lazy<Mutex<Family<Labels, Counter>>> =
    Lazy::new(|| Mutex::new(Family::default()));

const FIELD_NAME_COUNT: &str = "query_count";
const FIELD_NAME_TIME: &str = "query_time";

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Labels {
    pub deployment: String,
}

pub async fn get_services_version() -> u64 {
    // proxy: 0.3.3-4
    let mut version = [0u8; 4];
    let slice = PROXY_VERSION.split(".").collect::<Vec<&str>>();
    if slice.len() == 3 {
        version[0] = slice[0].parse().unwrap_or(0);
        version[1] = slice[1].parse().unwrap_or(0);
        let next = slice[2].split("-").collect::<Vec<&str>>();
        version[2] = next[0].parse().unwrap_or(0);
        if next.len() == 2 {
            version[3] = next[1].parse().unwrap_or(0);
        }
    }

    let cv = COORDINATOR_VERSION.lock().await;
    let cv_bytes = cv.to_le_bytes();
    drop(cv);

    let mut versions = [0u8; 8];
    versions[..4].copy_from_slice(&version);
    versions[4..].copy_from_slice(&cv_bytes);

    u64::from_le_bytes(versions)
}

pub async fn get_status() -> (u64, String) {
    let uptime = UPTIME.elapsed().as_secs();
    let sys = System::new();
    let name = sys.name().unwrap_or("NULL".to_owned());
    let os = sys.os_version().unwrap_or("NULL".to_owned());
    let cpu_count = sys
        .physical_core_count()
        .map(|v| v.to_string())
        .unwrap_or("NULL".to_owned());
    let info = format!("{} {} {}-CPU", name, os, cpu_count);

    (uptime, info)
}

pub async fn get_timer_metrics() -> Vec<(String, u64, u64)> {
    let mut counter = TIMER_COUNTER.lock().await;
    let mut results = vec![];
    for (project, count) in counter.iter_mut() {
        results.push((project.clone(), count.0, count.1));
        *count = (0, 0); // only report need clear
    }

    results
}

pub async fn get_owner_metrics_count() -> String {
    let family = OWNER_COUNT.lock().await;
    let mut registry = Registry::default();
    registry.register(FIELD_NAME_COUNT, "Count of requests", (*family).clone());
    drop(family);

    let mut body = String::new();
    let _ = encode(&mut body, &registry);
    body
}

pub async fn get_owner_metrics_time() -> String {
    let family = OWNER_TIME.lock().await;
    let mut registry = Registry::default();
    registry.register(FIELD_NAME_TIME, "Time of requests", (*family).clone());
    drop(family);

    let mut body = String::new();
    let _ = encode(&mut body, &registry);
    body
}

pub fn add_metrics_query(deployment: String, time: u64) {
    tokio::spawn(async move {
        let mut counter = TIMER_COUNTER.lock().await;
        counter
            .entry(deployment.clone())
            .and_modify(|f| {
                f.0 += 1;
                f.1 += time;
            })
            .or_insert((1, time));
        drop(counter);

        let label = Labels { deployment };
        let family = OWNER_COUNT.lock().await;
        family.get_or_create(&label).inc();
        drop(family);

        let family = OWNER_TIME.lock().await;
        family.get_or_create(&label).inc_by(time);
        drop(family);
    });
}
