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
#![allow(clippy::or_fun_call)]

#[macro_use]
extern crate tracing;

mod account;
mod auth;
mod cli;
mod contracts;
mod graphql;
mod metrics;
mod monitor;
mod p2p;
mod payg;
mod project;
mod server;
mod subscriber;

use cli::COMMAND;
use tracing::Level;

#[tokio::main]
async fn main() {
    let port = COMMAND.port();
    let host = COMMAND.host();
    let debug = COMMAND.debug();

    let log_filter = if debug { Level::DEBUG } else { Level::INFO };
    tracing_subscriber::fmt().with_max_level(log_filter).init();

    cli::init_redis().await;

    subscriber::subscribe();
    monitor::listen();

    server::start_server(host, port).await;
}
