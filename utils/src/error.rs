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
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// App error type.
#[derive(Debug)]
pub enum Error {
    JWTTokenError,
    JWTTokenCreationError,
    JWTTokenExpiredError,
    GraphQLQueryError(String),
    GraphQLInternalError(String),
    InvalidAuthHeaderError,
    NoPermissionError,
    ServiceException,
    InvalidProjectId,
    InvalidProjectPrice,
    InvalidProjectExpiration,
    InvalidServiceEndpoint,
    InvalidController,
    InvalidSerialize,
    InvalidSignature,
    InvalidEncrypt,
    InvalidRequest,
    PaygConflict,
    DailyLimit,
    RateLimit,
    Expired,
}

impl Error {
    pub fn to_status_message(self) -> (StatusCode, String) {
        match self {
            Error::JWTTokenError => (StatusCode::UNAUTHORIZED, "invalid auth token".to_owned()),
            Error::JWTTokenCreationError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid payload to create token".to_owned(),
            ),
            Error::JWTTokenExpiredError => (StatusCode::UNAUTHORIZED, "token expired".to_owned()),
            Error::GraphQLQueryError(e) => (
                StatusCode::NOT_FOUND,
                format!("GraphQL server error (query error): {}", e),
            ),
            Error::GraphQLInternalError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("GraphQL server error (internal error): {}", e),
            ),
            Error::NoPermissionError => (StatusCode::UNAUTHORIZED, "permission deny".to_owned()),
            Error::ServiceException => (StatusCode::UNAUTHORIZED, "service exception".to_owned()),
            Error::InvalidAuthHeaderError => (StatusCode::BAD_REQUEST, "invalid auth header".to_owned()),
            Error::InvalidProjectId => (StatusCode::BAD_REQUEST, "invalid project id".to_owned()),
            Error::InvalidProjectPrice => (StatusCode::BAD_REQUEST, "invalid project price".to_owned()),
            Error::InvalidProjectExpiration => (StatusCode::BAD_REQUEST, "invalid project expiration".to_owned()),
            Error::InvalidServiceEndpoint => (
                StatusCode::BAD_REQUEST,
                "invalid coordinator service endpoint".to_owned(),
            ),
            Error::InvalidController => (StatusCode::BAD_REQUEST, "invalid or missing controller".to_owned()),
            Error::InvalidSerialize => (StatusCode::BAD_REQUEST, "invalid serialize".to_owned()),
            Error::InvalidSignature => (StatusCode::BAD_REQUEST, "invalid signature".to_owned()),
            Error::InvalidEncrypt => (StatusCode::BAD_REQUEST, "invalid encrypt or decrypt".to_owned()),
            Error::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid request".to_owned()),
            Error::PaygConflict => (StatusCode::BAD_REQUEST, "PAYG conflict".to_owned()),
            Error::DailyLimit => (StatusCode::BAD_REQUEST, "exceed daily limit".to_owned()),
            Error::RateLimit => (StatusCode::BAD_REQUEST, "exceed rate limit".to_owned()),
            Error::Expired => (StatusCode::BAD_REQUEST, "service expired".to_owned()),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error_message) = self.to_status_message();
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

impl From<hex::FromHexError> for Error {
    fn from(_err: hex::FromHexError) -> Error {
        Error::InvalidSerialize
    }
}

impl From<rustc_hex::FromHexError> for Error {
    fn from(_err: rustc_hex::FromHexError) -> Error {
        Error::InvalidSerialize
    }
}

impl From<uint::FromHexError> for Error {
    fn from(_err: uint::FromHexError) -> Error {
        Error::InvalidSerialize
    }
}

impl From<ethereum_types::FromDecStrErr> for Error {
    fn from(_err: ethereum_types::FromDecStrErr) -> Error {
        Error::InvalidSerialize
    }
}

impl From<ethers::types::SignatureError> for Error {
    fn from(_err: ethers::types::SignatureError) -> Error {
        Error::InvalidSignature
    }
}

impl From<ethers::signers::WalletError> for Error {
    fn from(_err: ethers::signers::WalletError) -> Error {
        Error::InvalidController
    }
}
