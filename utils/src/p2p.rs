use serde::{Deserialize, Serialize};

/// "SubQuery" hash to group id as root group id.
pub const ROOT_GROUP_ID: u64 = 12408845626691334533;

/// Root name for projects
pub const ROOT_NAME: &str = "SubQuery";

#[derive(Serialize, Deserialize, Debug)]
pub struct JoinData(pub Vec<String>);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Event {
    /// Project join
    ProjectJoin(u64),
    /// Project join response
    ProjectJoinRes,
    /// Project leave
    ProjectLeave,
    /// Report project healthy
    /// params: metadata
    ProjectHealthy(String),
    /// Request the project info
    /// params: project
    ProjectInfo(Option<String>),
    /// Response project price and info,
    /// params: project info
    ProjectInfoRes(String),
    /// Open the state channel channel,
    /// params: uid, open state
    PaygOpen(u64, String),
    /// Response the channel open,
    /// params: uid, open state
    PaygOpenRes(u64, String),
    /// Query data the by channel,
    /// params: uid, query, state
    PaygQuery(u64, String, String),
    /// Response the channel query,
    /// params: uid, data, state
    PaygQueryRes(u64, String, String),
    /// Query the close agreement limit,
    /// params: uid, agreement id
    CloseAgreementLimit(u64, String),
    /// Response the close agreement limit
    /// params: uid, agreement info
    CloseAgreementLimitRes(u64, String),
    /// Query data by close agreement,
    /// params: uid, agreement, query
    CloseAgreementQuery(u64, String, String),
    /// Response the close agreement query,
    /// params: uid, data
    CloseAgreementQueryRes(u64, String),
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
