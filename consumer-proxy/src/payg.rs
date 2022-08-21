use once_cell::sync::Lazy;
use std::collections::HashMap;
use subql_proxy_utils::{
    error::Error,
    payg::{convert_sign_to_string, convert_string_to_sign, default_sign, OpenState, QueryState},
};
use tokio::sync::RwLock;
use web3::{
    signing::{SecretKeyRef, Signature},
    types::{Address, U256},
};

pub static CHANNELS: Lazy<RwLock<HashMap<String, StateChannel>>> = Lazy::new(|| RwLock::new(HashMap::new()));

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum ChannelStatus {
    Finalized,
    Open,
    Challenge,
}

pub struct StateChannel {
    pub id: U256,
    status: ChannelStatus,
    indexer: Address,
    consumer: Address,
    total: U256,
    spent: U256,
    onchain: U256,
    remote: U256,
    price: U256,
    expiration_at: U256,
    challenge_at: U256,
    deployment_id: [u8; 32],
    last_final: bool,
    last_indexer_sign: Signature,
    last_consumer_sign: Signature,
}

impl StateChannel {
    pub async fn get(deployment: &str) -> Result<StateChannel, Error> {
        let deployment_id = if let Some(bytes) = deployment.strip_prefix("0x") {
            hex::decode(bytes).map_err(|_| Error::InvalidRequest)?
        } else {
            // default is bs58
            bs58::decode(deployment).into_vec().map_err(|_| Error::InvalidRequest)?
        };
        let id = hex::encode(deployment_id);
        let channel = CHANNELS.read().await.get(&id).cloned().ok_or(Error::InvalidRequest)?;
        Ok(channel)
    }

    pub async fn add(state: OpenState) {
        let id = hex::encode(&state.deployment_id);

        let channel = StateChannel {
            id: state.channel_id,
            indexer: state.indexer,
            consumer: state.consumer,
            total: state.total,
            expiration_at: state.expiration,
            status: ChannelStatus::Open,
            spent: U256::from(0u64),
            onchain: U256::from(0u64),
            remote: U256::from(0u64),
            price: state.price,
            challenge_at: U256::from(0u64),
            deployment_id: state.deployment_id,
            last_final: false,
            last_indexer_sign: default_sign(),
            last_consumer_sign: default_sign(),
        };

        CHANNELS.write().await.insert(id, channel);
    }

    pub fn next_query(self, sk: SecretKeyRef) -> Result<QueryState, Error> {
        let is_final = false; // TODO more
        let spent = self.spent + self.price;

        QueryState::consumer_generate(self.id, self.indexer, self.consumer, spent, is_final, sk)
    }

    pub async fn renew(cid: U256, state: QueryState) {
        let channels = CHANNELS.write().await;
        let mut id = String::new();
        for (k, v) in channels.iter() {
            if v.id == cid {
                id = k.clone();
            }
        }
        drop(channels);

        if let Some(channel) = CHANNELS.write().await.get_mut(&id) {
            // TODO if spent != old spent, checkpoint chain.
            // TODO adjust the count number if spent != remote.

            channel.spent = state.spent;
            channel.remote = state.spent;
            channel.last_final = state.is_final;
            channel.last_indexer_sign = state.indexer_sign;
            channel.last_consumer_sign = state.consumer_sign;
        }
    }
}

impl Clone for StateChannel {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            status: self.status,
            indexer: self.indexer,
            consumer: self.consumer,
            total: self.total,
            spent: self.spent,
            onchain: self.onchain,
            remote: self.remote,
            price: self.price,
            expiration_at: self.expiration_at,
            challenge_at: self.challenge_at,
            deployment_id: self.deployment_id,
            last_final: self.last_final,
            last_indexer_sign: convert_string_to_sign(&convert_sign_to_string(&self.last_indexer_sign)),
            last_consumer_sign: convert_string_to_sign(&convert_sign_to_string(&self.last_consumer_sign)),
        }
    }
}
