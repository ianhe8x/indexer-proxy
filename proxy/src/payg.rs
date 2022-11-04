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
use chrono::prelude::*;
use ethers::{
    signers::Signer,
    types::{Address, U256},
};
use redis::{AsyncCommands, RedisResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subql_utils::{
    error::Error,
    payg::{convert_sign_to_string, OpenState, QueryState},
    request::graphql_request,
    tools::deployment_cid,
    types::Result,
};

use crate::account::ACCOUNT;
use crate::cli::{redis, COMMAND};
use crate::contracts::check_state_channel_consumer;
use crate::p2p::{PEER, PEERADDR};
use crate::project::{get_project, list_projects};

struct StateCache {
    price: U256,
    total: U256,
    spent: U256,
    remote: U256,
    coordi: U256,
    signer: ConsumerType,
}

impl StateCache {
    fn from_bytes(bytes: &[u8]) -> StateCache {
        let price = U256::from_little_endian(&bytes[0..32]);
        let total = U256::from_little_endian(&bytes[32..64]);
        let spent = U256::from_little_endian(&bytes[64..96]);
        let remote = U256::from_little_endian(&bytes[96..128]);
        let coordi = U256::from_little_endian(&bytes[128..160]);
        let signer = ConsumerType::from_bytes(&bytes[160..]);
        StateCache {
            price,
            total,
            spent,
            remote,
            coordi,
            signer,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let mut u256_bytes = [0u8; 32];
        self.price.to_little_endian(&mut u256_bytes);
        bytes.extend(&u256_bytes);
        self.total.to_little_endian(&mut u256_bytes);
        bytes.extend(&u256_bytes);
        self.spent.to_little_endian(&mut u256_bytes);
        bytes.extend(&u256_bytes);
        self.remote.to_little_endian(&mut u256_bytes);
        bytes.extend(&u256_bytes);
        self.coordi.to_little_endian(&mut u256_bytes);
        bytes.extend(&u256_bytes);
        bytes.extend(&self.signer.to_bytes());
        bytes
    }
}

/// Supported consumer type.
pub enum ConsumerType {
    /// real account
    Account(Address),
    /// use consumer host service. Contract Signer and real account
    Host(Vec<Address>),
}

impl ConsumerType {
    fn contains(&self, s: &Address) -> bool {
        match self {
            ConsumerType::Account(a) => a == s,
            ConsumerType::Host(signers) => signers.contains(s),
        }
    }

    fn from_bytes(bytes: &[u8]) -> ConsumerType {
        match bytes[0] {
            1 => {
                let num = bytes[1] as usize;
                let mut signers = vec![];
                let a_bytes = &bytes[2..];
                for i in 0..num {
                    signers.push(Address::from_slice(&a_bytes[20 * i..20 * (i + 1)]));
                }
                ConsumerType::Host(signers)
            }
            _ => {
                let a = Address::from_slice(&bytes[1..21]);
                ConsumerType::Account(a)
            }
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        match self {
            ConsumerType::Account(a) => {
                bytes.push(0);
                bytes.extend(a.as_bytes());
            }
            ConsumerType::Host(signers) => {
                // MAX only store 256 signers
                bytes.push(1);
                let num = if signers.len() > 255 { 255 } else { signers.len() };
                bytes.push(num as u8);
                for i in 0..num {
                    bytes.extend(signers[i].as_bytes());
                }
            }
        }
        bytes
    }
}

pub async fn merket_price(project_id: Option<String>) -> Value {
    let account = ACCOUNT.read().await;
    let peer_str = PEER.read().await.to_base58();
    let projects: Vec<(String, String, String)> = if let Some(pid) = project_id {
        if let Ok(project) = get_project(&pid) {
            if project.payg_price == U256::from(0) {
                vec![]
            } else {
                vec![(pid, project.payg_price.to_string(), project.payg_expiration.to_string())]
            }
        } else {
            vec![]
        }
    } else {
        list_projects()
            .iter()
            .filter_map(|(pid, price, expiration)| {
                if *price == U256::from(0) {
                    None
                } else {
                    Some((pid.clone(), price.to_string(), expiration.to_string()))
                }
            })
            .collect()
    };
    json!({
        "endpoint": COMMAND.endpoint(),
        "peer": peer_str,
        "multiaddr": PEERADDR.get().map(|a| a.to_string()).unwrap_or("".to_owned()),
        "indexer": format!("{:?}", account.indexer),
        "controller": format!("{:?}", account.controller.address()),
        "deployments": projects,
    })
}

pub async fn open_state(body: &Value) -> Result<Value> {
    let mut state = OpenState::from_json(body)?;

    // check project is exists. unify the deployment id store style.
    let project_id = deployment_cid(&state.deployment_id);
    if let Ok(project) = get_project(&project_id) {
        // check project price.
        if project.payg_price > state.price {
            return Err(Error::InvalidProjectPrice);
        }
        // check project expiration
        if U256::from(project.payg_expiration) < state.expiration {
            return Err(Error::InvalidProjectExpiration);
        }
    } else {
        return Err(Error::InvalidProjectId);
    }

    let account = ACCOUNT.read().await;
    let indexer = account.indexer;
    state.sign(&account.controller, false).await?;
    drop(account);

    let (sindexer, sconsumer) = state.recover()?;
    debug!("Open signer: {:?}, {:?}", sindexer, sconsumer);

    // check indexer is own
    if indexer != state.indexer {
        return Err(Error::InvalidRequest);
    }

    // async to coordinator
    let mdata = format!(
        r#"mutation {{
             channelOpen(
               id:"{:#X}",
               indexer:"{:?}",
               consumer:"{:?}",
               total:"{}",
               deploymentId:"{}",
               price:"{}")
           {{ price }}
        }}"#,
        state.channel_id,
        state.indexer,
        state.consumer,
        state.total,
        deployment_cid(&state.deployment_id),
        state.price,
    );
    tokio::spawn(async move {
        let url = COMMAND.graphql_url();
        let query = json!({ "query": mdata });
        let _ = graphql_request(&url, &query).await.map_err(|e| error!("{:?}", e));
    });

    debug!("Handle open channel success");
    Ok(state.to_json())
}

pub async fn query_state(project: &str, state: &Value, query: &Value) -> Result<(Value, Value)> {
    debug!("Got query channel");
    let project = get_project(project)?;
    let mut state = QueryState::from_json(state)?;

    let account = ACCOUNT.read().await;
    state.sign(&account.controller, false).await?;
    drop(account);
    let (_, signer) = state.recover()?;

    // check channel state
    let conn = redis();
    let mut conn_lock = conn.lock().await;
    let mut keyname = [0u8; 32];
    state.channel_id.to_little_endian(&mut keyname);
    let cache_bytes: RedisResult<Vec<u8>> = conn_lock.get(&keyname).await;
    drop(conn_lock);
    if cache_bytes.is_err() {
        return Err(Error::Expired);
    }
    let cache_raw_bytes = cache_bytes.unwrap();
    if cache_raw_bytes.is_empty() {
        return Err(Error::Expired);
    }
    let mut state_cache = StateCache::from_bytes(&cache_raw_bytes);

    // check signer
    if !state_cache.signer.contains(&signer) {
        return Err(Error::InvalidSignature);
    }

    let total = state_cache.total;
    let price = state_cache.price;
    let local_prev = state_cache.spent;
    let remote_prev = state_cache.remote;
    let remote_next = state.spent;
    let conflict = project.payg_overflow;

    if remote_prev < remote_next && remote_prev + price > remote_next {
        // price invalid
        return Err(Error::InvalidProjectPrice);
    }

    if local_prev > remote_prev + price * conflict {
        // overflow the conflict
        return Err(Error::PaygConflict);
    }

    if remote_next >= total + price {
        // overflow the total
        return Err(Error::Expired);
    }

    // query the data.
    let data = match graphql_request(&project.query_endpoint, query).await {
        Ok(result) => {
            let _string = serde_json::to_string(&result).unwrap(); // safe unwrap

            // let _sign = sign_message(string.as_bytes()); // TODO add to header
            // TODO add state to header and request to coordinator know the response.

            Ok(result)
        }
        Err(_e) => Err(Error::ServiceException),
    }?;

    state_cache.spent = local_prev + remote_next - remote_prev;
    state_cache.remote = remote_next;

    let mut conn_lock = conn.lock().await;
    if state.is_final {
        // close
        let _: RedisResult<()> = conn_lock.del(&keyname).await;
    } else {
        // update, missing KEEPTTL, so use two operation.
        let exp: RedisResult<usize> = conn_lock.ttl(&keyname).await;
        let _: RedisResult<()> = conn_lock
            .set_ex(&keyname, state_cache.to_bytes(), exp.unwrap_or(86400))
            .await;
    }
    drop(conn_lock);

    // async to coordiantor
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
        state.channel_id,
        remote_next,
        state.is_final,
        convert_sign_to_string(&state.indexer_sign),
        convert_sign_to_string(&state.consumer_sign),
    );
    tokio::spawn(async move {
        // query the state.
        let url = COMMAND.graphql_url();
        let query = json!({ "query": mdata });
        let _ = graphql_request(&url, &query).await.map_err(|e| error!("{:?}", e));
    });

    state.remote = state_cache.spent;
    debug!("Handle query channel success");
    Ok((state.to_json(), data))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelItem {
    pub id: String,
    pub consumer: String,
    pub total: String,
    pub spent: String,
    pub remote: String,
    pub price: String,
    #[serde(rename = "expiredAt")]
    pub expired: i64,
    #[serde(rename = "lastFinal")]
    pub is_final: bool,
}

pub async fn handle_channel(value: &Value) -> Result<()> {
    debug!("handle channel change");
    let channel: ChannelItem = serde_json::from_str(value.to_string().as_str()).unwrap();

    // coordinator use bignumber to store channel id
    let channel_id = U256::from_dec_str(&channel.id).map_err(|_e| Error::InvalidSerialize)?;
    let consumer: Address = channel.consumer.parse().map_err(|_e| Error::InvalidSerialize)?;
    let total = U256::from_dec_str(&channel.total).map_err(|_e| Error::InvalidSerialize)?;
    let spent = U256::from_dec_str(&channel.spent).map_err(|_e| Error::InvalidSerialize)?;
    let remote = U256::from_dec_str(&channel.remote).map_err(|_e| Error::InvalidSerialize)?;
    let price = U256::from_dec_str(&channel.price).map_err(|_e| Error::InvalidSerialize)?;
    let mut keyname = [0u8; 32];
    channel_id.to_little_endian(&mut keyname);

    let conn = redis();
    let mut conn_lock = conn.lock().await;

    let now = Utc::now().timestamp();

    if channel.is_final || now > channel.expired {
        // delete from cache
        let _: RedisResult<()> = conn_lock.del(&keyname).await;
    } else {
        let cache_bytes: RedisResult<Vec<u8>> = conn_lock.get(&keyname).await;
        let cache_ok = cache_bytes.ok().and_then(|v| if v.is_empty() { None } else { Some(v) });

        let state_cache = if let Some(bytes) = cache_ok {
            let mut state_cache = StateCache::from_bytes(&bytes);
            state_cache.total = total;
            state_cache.remote = std::cmp::max(state_cache.remote, remote);

            // spent = max(cache_spent - (cache_coordi - spent), spent)
            let fixed = state_cache.spent - state_cache.coordi + spent;
            state_cache.spent = std::cmp::max(fixed, spent);

            state_cache
        } else {
            let signer = check_state_channel_consumer(channel_id, consumer).await?;
            StateCache {
                price,
                total,
                spent,
                remote,
                signer,
                coordi: spent,
            }
        };

        let exp = (channel.expired - now) as usize;
        let _: RedisResult<()> = conn_lock.set_ex(&keyname, state_cache.to_bytes(), exp).await;
    }

    Ok(())
}

pub async fn init_channels() {
    let url = COMMAND.graphql_url();
    let query =
        json!({ "query": "query { getAliveChannels { id consumer total spent remote price lastFinal expiredAt } }" });
    let value = graphql_request(&url, &query).await.unwrap(); // init need unwrap

    if let Some(items) = value.pointer("/data/getAliveChannels") {
        if let Some(channels) = items.as_array() {
            for channel in channels {
                let _ = handle_channel(channel).await;
            }
        }
    }
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
