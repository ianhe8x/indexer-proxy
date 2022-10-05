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
use serde::{Deserialize, Serialize};
use subql_utils::{error::Error, types::Result};

use crate::cli::COMMAND;

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
    /// deployment id for the proejct
    pub deployment_id: String,
    /// issue timestamp
    pub iat: i64,
    /// token expiration
    pub exp: i64,
}

pub fn create_jwt(payload: Payload) -> Result<String> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::hours(COMMAND.token_duration()))
        .expect("valid timestamp")
        .timestamp_millis();

    let msg_verified = true; // verify_message(&payload).map_err(|_| Error::JWTTokenCreationError)?;
    if !msg_verified || (Utc::now().timestamp_millis() - payload.timestamp).abs() > 120000 {
        return Err(Error::JWTTokenCreationError);
    }

    let header = Header::new(Algorithm::HS512);
    let claims = Claims {
        indexer: payload.indexer,
        deployment_id: payload.deployment_id,
        iat: payload.timestamp,
        exp: expiration,
    };

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

        Ok(AuthQuery(decoded.claims.deployment_id))
    }
}
