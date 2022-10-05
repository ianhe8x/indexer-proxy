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

use ethers::{
    abi::Token,
    providers::{Http, Provider},
    types::{Address, U256},
};
use std::time::{SystemTime, UNIX_EPOCH};
use subql_contracts::service_agreement_registry;
use subql_utils::error::Error;

use crate::cli::COMMAND;

pub async fn check_agreement_and_consumer(signer: &str, aid: &str) -> Result<bool, Error> {
    let client = Provider::<Http>::try_from(COMMAND.network_endpoint()).map_err(|_| Error::ServiceException)?;

    let agreement = service_agreement_registry(client, COMMAND.network()).unwrap();
    let agreement_id = U256::from_dec_str(aid).map_err(|_| Error::InvalidSerialize)?;

    let info: Token = agreement
        .method::<_, Token>("getClosedServiceAgreement", (agreement_id,))
        .unwrap()
        .call()
        .await
        .unwrap();
    let infos = match info {
        Token::Tuple(infos) => infos,
        _ => vec![],
    };
    // ClosedServiceAgreementInfo(
    //  consumer, indexer, deploymentId, lockedAmount, startDate, period, planId, plainTemplateId
    // )
    if infos.len() < 6 {
        return Err(Error::InvalidSerialize);
    }
    let consumer = infos[0].clone().into_address().ok_or(Error::InvalidSerialize)?;
    let start = infos[4].clone().into_uint().ok_or(Error::InvalidSerialize)?.as_u64();
    let period = infos[5].clone().into_uint().ok_or(Error::InvalidSerialize)?.as_u64();
    let chain_consumer = format!("{:?}", consumer).to_lowercase();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|s| s.as_secs())
        .unwrap_or(0);

    // check allowlist
    let allow = if chain_consumer != signer {
        let signer_address: Address = signer.parse().unwrap();
        let allow_res: Token = agreement
            .method::<_, Token>("consumerAuthAllows", (consumer, signer_address))
            .unwrap()
            .call()
            .await
            .unwrap();
        allow_res.into_bool().ok_or(Error::InvalidSerialize)?
    } else {
        true
    };

    Ok(start <= now && now <= (start + period) && allow)
}
