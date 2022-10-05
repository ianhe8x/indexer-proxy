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

use ethers::{
    abi::{encode, Tokenizable},
    signers::Signer,
    types::{Address, Signature, H256, U256},
    utils::keccak256,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use serde_json::{json, Value};

use crate::error::Error;
use crate::tools::{cid_deployment, deployment_cid};

pub struct OpenState {
    pub channel_id: U256,
    pub indexer: Address,
    pub consumer: Address,
    pub total: U256,
    pub expiration: U256,
    pub deployment_id: H256,
    pub callback: Vec<u8>,
    pub indexer_sign: Signature,
    pub consumer_sign: Signature,
    pub price: U256,
}

impl OpenState {
    pub async fn consumer_generate(
        channel_id: Option<U256>,
        indexer: Address,
        consumer: Address,
        total: U256,
        expiration: U256,
        deployment_id: H256,
        callback: Vec<u8>,
        key: &impl Signer,
    ) -> Result<Self, Error> {
        let channel_id = if let Some(channel_id) = channel_id {
            channel_id
        } else {
            let mut rng = ChaChaRng::from_entropy();
            let mut id = [0u64; 4]; // u256
            id[0] = rng.next_u64();
            id[1] = rng.next_u64();
            id[2] = rng.next_u64();
            id[3] = rng.next_u64();
            U256(id)
        };
        let mut state = Self {
            channel_id,
            indexer,
            consumer,
            total,
            expiration,
            deployment_id,
            callback,
            consumer_sign: default_sign(),
            indexer_sign: default_sign(),
            price: U256::from(0u64),
        };
        state.sign(key, true).await?;
        Ok(state)
    }

    pub fn recover(&self) -> Result<(Address, Address), Error> {
        let payload = encode(&[
            self.channel_id.into_token(),
            self.indexer.into_token(),
            self.consumer.into_token(),
            self.total.into_token(),
            self.expiration.into_token(),
            self.deployment_id.into_token(),
            self.callback.clone().into_token(),
        ]);
        let hash = keccak256(payload);
        let indexer = self.indexer_sign.recover(&hash[..])?;
        let consumer = self.consumer_sign.recover(&hash[..])?;
        Ok((indexer, consumer))
    }

    pub async fn sign(&mut self, key: &impl Signer, is_consumer: bool) -> Result<(), Error> {
        let payload = encode(&[
            self.channel_id.into_token(),
            self.indexer.into_token(),
            self.consumer.into_token(),
            self.total.into_token(),
            self.expiration.into_token(),
            self.deployment_id.into_token(),
            self.callback.clone().into_token(),
        ]);
        let hash = keccak256(payload);
        let sign = key.sign_message(hash).await.map_err(|_| Error::InvalidSignature)?;
        if is_consumer {
            self.consumer_sign = sign;
        } else {
            self.indexer_sign = sign;
        }
        Ok(())
    }

    pub fn from_json(params: &Value) -> Result<Self, Error> {
        let channel_id: U256 = params["channelId"]
            .as_str()
            .ok_or(Error::InvalidSerialize)?
            .parse()
            .map_err(|_e| Error::InvalidSerialize)?;
        let indexer: Address = params["indexer"]
            .as_str()
            .ok_or(Error::InvalidSerialize)?
            .parse()
            .map_err(|_e| Error::InvalidSerialize)?;
        let consumer: Address = params["consumer"]
            .as_str()
            .ok_or(Error::InvalidSerialize)?
            .parse()
            .map_err(|_e| Error::InvalidSerialize)?;
        let total = U256::from_dec_str(params["total"].as_str().ok_or(Error::InvalidSerialize)?)
            .map_err(|_e| Error::InvalidSerialize)?;
        let expiration = U256::from_dec_str(params["expiration"].as_str().ok_or(Error::InvalidSerialize)?)
            .map_err(|_e| Error::InvalidSerialize)?;
        let deployment_id = cid_deployment(params["deploymentId"].as_str().ok_or(Error::InvalidSerialize)?);
        if deployment_id == H256::zero() {
            return Err(Error::InvalidSerialize);
        }
        let callback = hex::decode(params["callback"].as_str().ok_or(Error::InvalidSerialize)?)
            .map_err(|_e| Error::InvalidSerialize)?;
        let indexer_sign: Signature =
            convert_string_to_sign(params["indexerSign"].as_str().ok_or(Error::InvalidSerialize)?);
        let consumer_sign: Signature =
            convert_string_to_sign(params["consumerSign"].as_str().ok_or(Error::InvalidSerialize)?);
        let price = U256::from_dec_str(params["price"].as_str().ok_or(Error::InvalidSerialize)?)
            .map_err(|_e| Error::InvalidSerialize)?;
        Ok(Self {
            channel_id,
            indexer,
            consumer,
            total,
            expiration,
            deployment_id,
            callback,
            indexer_sign,
            consumer_sign,
            price,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "channelId": format!("{:#X}", self.channel_id),
            "indexer": format!("{:?}", self.indexer),
            "consumer": format!("{:?}", self.consumer),
            "total": self.total.to_string(),
            "expiration": self.expiration.to_string(),
            "deploymentId": deployment_cid(&self.deployment_id),
            "callback": hex::encode(&self.callback),
            "indexerSign": convert_sign_to_string(&self.indexer_sign),
            "consumerSign": convert_sign_to_string(&self.consumer_sign),
            "price": self.price.to_string(),
        })
    }
}

pub struct QueryState {
    pub channel_id: U256,
    pub indexer: Address,
    pub consumer: Address,
    pub spent: U256,
    pub remote: U256,
    pub is_final: bool,
    pub indexer_sign: Signature,
    pub consumer_sign: Signature,
}

impl QueryState {
    pub async fn consumer_generate(
        channel_id: U256,
        indexer: Address,
        consumer: Address,
        spent: U256,
        is_final: bool,
        key: &impl Signer,
    ) -> Result<Self, Error> {
        let mut state = Self {
            channel_id,
            indexer,
            consumer,
            spent,
            is_final,
            remote: spent,
            consumer_sign: default_sign(),
            indexer_sign: default_sign(),
        };
        state.sign(key, true).await?;
        Ok(state)
    }

    pub fn recover(&self) -> Result<(Address, Address), Error> {
        let payload = encode(&[
            self.channel_id.into_token(),
            self.spent.into_token(),
            self.is_final.into_token(),
        ]);
        let hash = keccak256(payload);
        let indexer = self.indexer_sign.recover(&hash[..])?;
        let consumer = self.consumer_sign.recover(&hash[..])?;
        Ok((indexer, consumer))
    }

    pub async fn sign(&mut self, key: &impl Signer, is_consumer: bool) -> Result<(), Error> {
        let payload = encode(&[
            self.channel_id.into_token(),
            self.spent.into_token(),
            self.is_final.into_token(),
        ]);
        let hash = keccak256(payload);
        let sign = key.sign_message(hash).await.map_err(|_| Error::InvalidSignature)?;
        if is_consumer {
            self.consumer_sign = sign;
        } else {
            self.indexer_sign = sign;
        }
        Ok(())
    }

    pub fn from_json(params: &Value) -> Result<Self, Error> {
        let channel_id: U256 = params["channelId"]
            .as_str()
            .ok_or(Error::InvalidSerialize)?
            .parse()
            .map_err(|_e| Error::InvalidSerialize)?;
        let indexer: Address = params["indexer"]
            .as_str()
            .ok_or(Error::InvalidSerialize)?
            .parse()
            .map_err(|_e| Error::InvalidSerialize)?;
        let consumer: Address = params["consumer"]
            .as_str()
            .ok_or(Error::InvalidSerialize)?
            .parse()
            .map_err(|_e| Error::InvalidSerialize)?;
        let spent = U256::from_dec_str(params["spent"].as_str().ok_or(Error::InvalidSerialize)?)
            .map_err(|_e| Error::InvalidSerialize)?;
        let remote = U256::from_dec_str(params["remote"].as_str().ok_or(Error::InvalidSerialize)?)
            .map_err(|_e| Error::InvalidSerialize)?;
        let is_final = params["isFinal"].as_bool().ok_or(Error::InvalidSerialize)?;
        let indexer_sign: Signature =
            convert_string_to_sign(params["indexerSign"].as_str().ok_or(Error::InvalidSerialize)?);
        let consumer_sign: Signature =
            convert_string_to_sign(params["consumerSign"].as_str().ok_or(Error::InvalidSerialize)?);
        Ok(Self {
            channel_id,
            indexer,
            consumer,
            spent,
            remote,
            is_final,
            indexer_sign,
            consumer_sign,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "channelId": format!("{:#X}", self.channel_id),
            "indexer": format!("{:?}", self.indexer),
            "consumer": format!("{:?}", self.consumer),
            "spent": self.spent.to_string(),
            "remote": self.remote.to_string(),
            "isFinal": self.is_final,
            "indexerSign": convert_sign_to_string(&self.indexer_sign),
            "consumerSign": convert_sign_to_string(&self.consumer_sign),
        })
    }
}

pub fn default_sign() -> Signature {
    Signature {
        v: 0,
        r: U256::from(0),
        s: U256::from(0),
    }
}

/// Convert eth signature to string.
pub fn convert_sign_to_string(sign: &Signature) -> String {
    let bytes = convert_sign_to_bytes(sign);
    hex::encode(&bytes)
}

/// Convert string to eth signature.
pub fn convert_string_to_sign(s: &str) -> Signature {
    let mut bytes = hex::decode(s).unwrap_or(vec![0u8; 65]); // 32 + 32 + 1

    if bytes.len() < 65 {
        bytes.extend(vec![0u8; 65 - bytes.len()]);
    }

    let r = U256::from_big_endian(&bytes[0..32]);
    let s = U256::from_big_endian(&bytes[32..64]);
    let v = bytes[64] as u64;
    Signature { r, s, v }
}

/// Convert eth signature to bytes.
pub fn convert_sign_to_bytes(sign: &Signature) -> [u8; 65] {
    let mut bytes = <[u8; 65]>::from(sign);
    let mut recovery_id = match sign.v {
        27 => 0,
        28 => 1,
        v if v >= 35 => ((v - 1) % 2) as u8,
        _ => sign.v as u8,
    };
    recovery_id += 27; // Because in ETH.
    bytes[64] = recovery_id;
    bytes
}
