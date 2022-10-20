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

use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::header::AUTHORIZATION,
};
use chrono::prelude::*;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use redis::{AsyncCommands, RedisResult};
use serde::{Deserialize, Serialize};
use subql_utils::{error::Error, types::Result};

use crate::cli::{redis, COMMAND};

#[derive(Serialize, Deserialize, Debug)]
pub struct Payload {
    /// indexer address
    pub indexer: String,
    /// consumer address
    pub consumer: Option<String>,
    /// service agreement contract address
    pub agreement: Option<String>,
    /// deployment id for the proejct
    pub deployment_id: String,
    /// signature of user
    pub signature: String,
    /// timestamp
    pub timestamp: i64,
    /// chain id
    pub chain_id: i64,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    /// ethereum address
    pub indexer: String,
    /// agreement
    pub agreement: Option<String>,
    /// deployment id for the proejct
    pub deployment_id: String,
    /// issue timestamp
    pub iat: i64,
    /// token expiration
    pub exp: i64,
}

pub async fn create_jwt(payload: Payload, daily: u64, rate: u64) -> Result<String> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::hours(COMMAND.token_duration()))
        .expect("valid timestamp")
        .timestamp_millis();

    if (Utc::now().timestamp_millis() - payload.timestamp).abs() > 120000 {
        return Err(Error::JWTTokenCreationError);
    }

    let header = Header::new(Algorithm::HS512);
    let claims = Claims {
        indexer: payload.indexer,
        agreement: payload.agreement.clone(),
        deployment_id: payload.deployment_id,
        iat: payload.timestamp,
        exp: expiration,
    };

    if let Some(agreement) = payload.agreement {
        // Add the limit to cache.
        let daily_limit = format!("{}-dlimit", agreement);
        let rate_limit = format!("{}-rlimit", agreement);

        // keep the redis expired slower than token.
        let limit_expired = (COMMAND.token_duration() as usize * 3600) * 2;

        // update the limit
        let conn = redis();
        let mut conn_lock = conn.lock().await;
        let _: RedisResult<()> = conn_lock.set_ex(&daily_limit, daily, limit_expired).await;
        let _: RedisResult<()> = conn_lock.set_ex(&rate_limit, rate, limit_expired).await;
        drop(conn_lock);
    }

    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(COMMAND.jwt_secret().as_bytes()),
    )
    .map_err(|_| Error::JWTTokenCreationError)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthQuery(pub String);

#[async_trait]
impl<B> FromRequest<B> for AuthQuery
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

        // Check that is bearer and jwt
        let split = authorisation.split_once(' ');
        let jwt = match split {
            Some((name, contents)) if name == "Bearer" => Ok(contents),
            _ => Err(Error::InvalidAuthHeaderError),
        }?;

        let decoded = decode::<Claims>(
            jwt,
            &DecodingKey::from_secret(COMMAND.jwt_secret().as_bytes()),
            &Validation::new(Algorithm::HS512),
        )
        .map_err(|_| Error::JWTTokenError)?;

        if decoded.claims.exp < Utc::now().timestamp_millis() {
            return Err(Error::JWTTokenExpiredError);
        }

        if let Some(agreement) = decoded.claims.agreement {
            // check limit
            let daily_key = format!("{}-daily", agreement);
            let rate_key = format!("{}-rate", agreement);
            let daily_limit = format!("{}-dlimit", agreement);
            let rate_limit = format!("{}-rlimit", agreement);

            let conn = redis();
            let mut conn_lock = conn.lock().await;

            let daily_limit: u64 = conn_lock.get(&daily_limit).await.unwrap_or(86400);
            let rate_limit: u64 = conn_lock.get(&rate_limit).await.unwrap_or(60);

            let daily_times: RedisResult<u64> = conn_lock.get(&daily_key).await;
            let rate_times: RedisResult<u64> = conn_lock.get(&rate_key).await;

            let daily_times = if let Ok(times) = daily_times {
                if times > daily_limit {
                    return Err(Error::DailyLimit);
                } else {
                    times + 1
                }
            } else {
                1
            };
            let rate_times = if let Ok(times) = rate_times {
                if times > rate_limit {
                    return Err(Error::RateLimit);
                } else {
                    times + 1
                }
            } else {
                1
            };

            let _: RedisResult<()> = conn_lock.set_ex(&daily_key, daily_times, 86400).await;
            let _: RedisResult<()> = conn_lock.set_ex(&rate_key, rate_times, 60).await;
            drop(conn_lock);
        }

        Ok(AuthQuery(decoded.claims.deployment_id))
    }
}
