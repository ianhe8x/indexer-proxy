use serde::{Deserialize, Serialize};

/// "SubQuery" hash to group id as root group id.
pub const ROOT_GROUP_ID: u64 = 12408845626691334533;

#[derive(Serialize, Deserialize, Debug)]
pub struct JoinData(pub Vec<String>);

#[derive(Serialize, Deserialize, Debug)]
pub enum Event {
    /// group join
    GroupJoin(u64),
    /// group join info response
    GroupInfo,
    /// group leave
    Leave,
    /// payg request
    PaygInfo(Option<String>),
    /// payg price response
    PaygPrice(String),
    /// open state
    PaygOpen(u64, String),
    /// open state
    PaygOpenRes(u64, String),
    /// query, state
    PaygQuery(u64, String, String),
    /// data, state
    PaygQueryRes(u64, String, String),
}

impl Event {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or(vec![])
    }

    pub fn from_bytes(data: &[u8]) -> std::io::Result<Self> {
        bincode::deserialize(data).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "P2P Event deserialize failure")
        })
    }
}
