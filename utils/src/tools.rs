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

use crate::traits::Hash;

impl Hash for String {
    fn hash(&self) -> String {
        blake3::hash(self.as_bytes()).to_string()
    }
}

pub fn deployment_cid(deployment: &[u8]) -> String {
    if deployment.len() != 32 {
        return "".to_owned();
    }
    // Add our default ipfs values for first 2 bytes:
    // function:0x12=sha2, size:0x20=256 bits
    // and cut off leading "0x"
    let mut bytes = [0u8; 34];
    bytes[0] = 18;
    bytes[1] = 32;
    bytes[2..].copy_from_slice(deployment);
    bs58::encode(&bytes).into_string()
}

pub fn cid_deployment(cid: &str) -> [u8; 32] {
    if let Ok(raw) = bs58::decode(&cid).into_vec() {
        let mut bytes = [0u8; 32];
        if raw.len() != 34 {
            return [0u8; 32];
        }
        bytes.copy_from_slice(&raw[2..]);
        bytes
    } else {
        [0u8; 32]
    }
}
