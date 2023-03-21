pub fn poi_with_block(mut block: String) -> String {
    if block.starts_with("0x") {
        block = block.split_off(2);
    }

    if block.starts_with("\\x") {
        block = block.split_off(3);
    }

    format!(
        r#"{{
  _poiByChainBlockHash(chainBlockHash:"\\x{}") {{
      nodeId
      id
      chainBlockHash
      hash
      parentHash
      operationHashRoot
      mmrRoot
      projectId
      createdAt
      updatedAt

 }}
}}"#,
        block
    )
}

pub const POI_LATEST: &str = r#"{
  _pois(last: 1) {
    nodes {
      nodeId
      id
      chainBlockHash
      hash
      parentHash
      operationHashRoot
      mmrRoot
      projectId
      createdAt
      updatedAt
    }
  }
}"#;

pub const METADATA_QUERY: &str = r#"query {
  _metadata {
    lastProcessedHeight
    lastProcessedTimestamp
    targetHeight
    chain
    specName
    genesisHash
    indexerHealthy
    indexerNodeVersion
    queryNodeVersion
    indexerHealthy
    chain
  }
}"#;

pub const ACCOUNT_QUERY: &str = "query { accountMetadata { indexer controller } }";

pub const PROJECT_QUERY: &str =
    "query { getAliveProjects { id queryEndpoint paygPrice paygExpiration paygOverflow } }";

pub const CHANNEL_QUERY: &str =
    "query { getAliveChannels { id consumer total spent remote price lastFinal expiredAt } }";
