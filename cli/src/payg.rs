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

use async_trait::async_trait;
use rustyline::{error::ReadlineError, Editor};
use secp256k1::SecretKey;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env::args;
use std::sync::Arc;
use subql_contracts::{sqtoken, state_channel, Network};
use subql_proxy_utils::{
    error::Error,
    p2p::{channel_rpc_channel, libp2p::identity::Keypair, server::server, GroupId, P2pHandler, PeerId, Response},
    payg::{convert_sign_to_bytes, default_sign, OpenState, QueryState},
    request::{jsonrpc_params, jsonrpc_response, proxy_request},
    tools::{cid_deployment, deployment_cid},
};
use tokio::sync::RwLock;
use web3::{
    contract::{
        tokens::{Tokenizable, Tokenize},
        Contract, Options,
    },
    ethabi::{encode, Token},
    signing::{keccak256, Key, SecretKeyRef, Signature},
    transports::Http,
    types::{Address, Bytes, TransactionParameters, U256},
    Web3,
};

const TESTNET_ENDPOINT: &str = "https://sqtn.api.onfinality.io/public";
const MOONBEAM_ENDPOINT: &str = "https://moonbeam-alpha.api.onfinality.io/public";
const CONSUMER: &str = "de9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0";
const P2P_KEY: &str = "0801124021220100bdf8d7da7c51e1e76724bb0f1001d4dbf621662d4fab121a908868bbfe37eab62abbd576faabe024d0a19566a20108a4a29c8bc25184c4d5a6e05782";

fn help() {
    println!("Commands:");
    println!("  help");
    println!("  show");
    println!("  indexers");
    println!("  connect [multiaddr]");
    println!("    eg. connect /ip4/127.0.0.1/tcp/7000");
    println!("  search [deployment]");
    println!("    eg. search xxxxxxxxxxxxxxx");
    println!("  indexer [indexer]");
    println!("    eg. indexer 0x2546bcd3c84621e976d8185a91a922ae77ecec30");
    println!("  set web3 [web3 endpoint address]");
    println!("    eg. set web3 https://sqtn.api.onfinality.io/public");
    println!("  set channel [channel uid]");
    println!("  state-channel open [amount] [expired-seconds]");
    println!("    eg. state-channel open 100 86400");
    println!("  state-channel checkpoint");
    println!("  state-channel challenge");
    println!("  state-channel claim");
    println!("  state-channel show");
    println!("  state-channel add [channel-id]");
    println!("  query [query]");
    println!("    eg. query query {{ _metadata {{ indexerHealthy chain }} }}");
}

#[allow(dead_code)]
struct StateChannel {
    id: U256,
    indexer: Address,
    consumer: Address,
    deployment: [u8; 32],
    expiration: U256,
    total: U256,
    spent: U256,
    onchain: U256,
    remote: U256,
    price: U256,
    last_final: bool,
    last_indexer_sign: Signature,
    last_consumer_sign: Signature,
}

#[allow(dead_code)]
struct Indexer {
    endpoint: String,
    token: String,
    peer: PeerId,
    indexer: Address,
    controller: Address,
    price: U256,
    deployment: [u8; 32],
}

async fn send_state(
    web3: &Web3<Http>,
    cotract: &Contract<Http>,
    state: &StateChannel,
    method: &str,
    secret: &SecretKey,
) {
    let msg = encode(&[
        state.id.into_token(),
        state.spent.into_token(),
        state.last_final.into_token(),
    ]);
    let mut bytes = "\x19Ethereum Signed Message:\n32".as_bytes().to_vec();
    bytes.extend(keccak256(&msg));
    let _payload = keccak256(&bytes);

    let call_params = Token::Tuple(vec![
        state.id.into_token(),
        state.last_final.into_token(),
        state.spent.into_token(),
        convert_sign_to_bytes(&state.last_indexer_sign).into_token(),
        convert_sign_to_bytes(&state.last_consumer_sign).into_token(),
    ]);
    let call_tokens = (call_params.clone(),).into_tokens();
    let fn_data = cotract
        .abi()
        .function(method)
        .and_then(|function| function.encode_input(&call_tokens))
        .unwrap();
    let gas = cotract
        .estimate_gas(method, (call_params,), state.consumer, Default::default())
        .await
        .unwrap();

    let tx = TransactionParameters {
        to: Some(cotract.address()),
        data: Bytes(fn_data),
        gas: gas,
        ..Default::default()
    };
    let signed = web3.accounts().sign_transaction(tx, secret).await.unwrap();
    let tx_hash = web3.eth().send_raw_transaction(signed.raw_transaction).await.unwrap();
    println!("\x1b[94m>>> TxHash: {:?}\x1b[00m", tx_hash);
}

#[allow(dead_code)]
async fn token_approve(web3: &Web3<Http>, contract: &Contract<Http>, sk: &SecretKey, address: Address, amount: u128) {
    println!("Approve SQT to: {:?} ...", address);
    let fn_data = contract
        .abi()
        .function("increaseAllowance")
        .and_then(|function| function.encode_input(&(address, U256::from(amount)).into_tokens()))
        .unwrap();
    let tx = TransactionParameters {
        to: Some(contract.address()),
        data: Bytes(fn_data),
        ..Default::default()
    };
    let signed = web3.accounts().sign_transaction(tx, sk).await.unwrap();
    let _tx_hash = web3.eth().send_raw_transaction(signed.raw_transaction).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    let result: U256 = contract
        .query(
            "allowance",
            (SecretKeyRef::new(sk).address(), address),
            None,
            Options::default(),
            None,
        )
        .await
        .unwrap();
    println!("Approved SQT {:?}", result);
}

/// Prepare the consumer account and evm status.
/// Run `cargo run --bin subql-cli-payg [moonbeam|testnet] [proxy|p2p]` default is local and p2p.
#[tokio::main]
async fn main() {
    let (mut web3_endpoint, net, is_p2p) = if args().len() == 1 {
        (TESTNET_ENDPOINT.to_owned(), Network::Testnet, true)
    } else {
        if args().len() != 3 {
            println!("cargo run --bin subql-cli-payg [moonbeam|testnet] [proxy|p2p]");
            return;
        }
        let (endpoint, net) = match args().nth(1).unwrap().as_str() {
            "moonbeam" => (MOONBEAM_ENDPOINT.to_owned(), Network::Moonbeam),
            "testnet" => (TESTNET_ENDPOINT.to_owned(), Network::Testnet),
            _ => (TESTNET_ENDPOINT.to_owned(), Network::Testnet),
        };

        let is_p2p = if args().nth(2).unwrap() == "proxy".to_owned() {
            false
        } else {
            true
        };
        (endpoint, net, is_p2p)
    };

    // consumer/controller eth account (PROD need Keystore).
    let consumer_sk = SecretKey::from_slice(&hex::decode(CONSUMER).unwrap()).unwrap();
    let consumer_ref = SecretKeyRef::new(&consumer_sk);
    let consumer = consumer_ref.address();

    // init web3
    let http = Http::new(&web3_endpoint).unwrap();
    let mut web3 = Web3::new(http);
    let state_channel = state_channel(web3.eth(), net).unwrap();
    let token = sqtoken(web3.eth(), net).unwrap();

    // !IMPORTANT, only first time uncomment it to run.
    // token_approve(&web3, &token, &consumer_sk, state_channel.address(), u128::MAX).await;

    // cid => StateChannel
    let mut channels: Vec<StateChannel> = vec![];
    let mut cid: usize = 0;
    let mut choose_indexer = Address::default();
    let indexers: Arc<RwLock<HashMap<Address, Indexer>>> = Arc::new(RwLock::new(HashMap::new()));

    // local p2p rpc bind.
    let key_bytes = hex::decode(P2P_KEY).unwrap();
    let p2p_key = Keypair::from_protobuf_encoding(&key_bytes).unwrap();
    let (out_send, mut out_recv, p2p_send, p2p_recv) = channel_rpc_channel();

    tokio::spawn(async move {
        server::<ConsumerP2p>(
            "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            None,
            None,
            Some((out_send, p2p_recv)),
            None,
            p2p_key,
        )
        .await
        .unwrap();
    });
    let indexers_ref = indexers.clone();
    tokio::spawn(async move {
        while let Some(msg) = out_recv.recv().await {
            let method = msg["method"].as_str().unwrap();
            if method == "deployment" {
                let result_str = msg["result"].as_str();
                if result_str.is_none() {
                    continue;
                }
                let values: Value = serde_json::from_str(result_str.unwrap()).unwrap();
                let mut indexers = indexers_ref.write().await;
                let indexer: Address = values["indexer"].as_str().unwrap().parse().unwrap();
                let controller: Address = values["controller"].as_str().unwrap().parse().unwrap();
                let endpoint = values["endpoint"].as_str().unwrap().to_owned();
                let peer = values["peer"].as_str().unwrap().parse().unwrap();
                for value in values["deployments"].as_array().unwrap() {
                    let project = value.as_array().unwrap();
                    let deployment = cid_deployment(project[0].as_str().unwrap());
                    let price = U256::from_dec_str(project[1].as_str().unwrap()).unwrap();
                    let new_indexer = Indexer {
                        endpoint: endpoint.clone(),
                        peer,
                        indexer,
                        controller,
                        deployment,
                        price,
                        token: "".to_owned(),
                    };
                    indexers.insert(indexer, new_indexer);
                }

                drop(indexers);
            }
        }
    });

    println!("START QUERY, please input indexer's PeerId!");
    help();

    // Read full lines from stdin
    let mut rl = Editor::<()>::new();
    if rl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }
    loop {
        println!("\x1b[92m------------------------------------\x1b[00m");
        let readline = rl.readline(">> ");
        let line = match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                line
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        };
        let method_params = line.trim().split_once(" ");
        if method_params.is_none() {
            match line.as_str() {
                "help" => help(),
                "show" => {
                    println!("Account Consumer:       {:?}", consumer);
                    //println!("Account Controller:     {:?}", controller.address());
                    println!("State Channel Contract: {:?}", state_channel.address());
                    println!("Web3 Endpoint:          {}", web3_endpoint);
                    println!("");
                    if channels.len() == 0 {
                        println!("Current Channel: None");
                    } else {
                        println!("Current Channel: {} {:#X}", cid, channels[cid].id);
                        println!("Current Channel indexer: {:?}", channels[cid].indexer);
                        println!(
                            "Current Channel deployment: {}",
                            deployment_cid(&channels[cid].deployment)
                        );
                    }
                    let result: U256 = token
                        .query("balanceOf", (consumer,), None, Options::default(), None)
                        .await
                        .unwrap();
                    println!("SQT Balance: {:?}", result);
                }
                "indexers" => {
                    let indexers_ref = indexers.read().await;
                    for (_, indexer) in indexers_ref.iter() {
                        println!("\x1b[93m>>> Indexer: {:?}\x1b[00m", indexer.indexer);
                        println!(
                            "\x1b[93m>>> Deployment: {}\x1b[00m",
                            deployment_cid(&indexer.deployment)
                        );
                        println!("\x1b[93m>>> Price: {}\x1b[00m", indexer.price);
                        println!("\x1b[93m>>> Endpoint: {}\x1b[00m", indexer.endpoint);
                        println!("\x1b[93m>>> Peer: {}\x1b[00m", indexer.peer);
                        println!("-----------------------------------------");
                    }
                    drop(indexers_ref);
                }
                _ => println!("\x1b[91mInvalid, type again!\x1b[00m"),
            }
            continue;
        }
        let (method, params) = method_params.unwrap();
        let params = params.trim().to_owned();
        match method {
            "connect" => {
                if !is_p2p {
                    println!("\x1b[91m>>> Only P2P supported\x1b[00m");
                }
                p2p_send
                    .send(jsonrpc_params(0, "connect", vec![Value::from(params.clone())]))
                    .await;
                println!("\x1b[93m>>> Start connect to: {}\x1b[00m", params);
            }
            "search" => {
                p2p_send
                    .send(jsonrpc_params(0, "group-join", vec![json!(params)]))
                    .await;
                println!("waiting a moment...");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                p2p_send
                    .send(jsonrpc_params(0, "group-deployment", vec![json!(params)]))
                    .await;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            "indexer" => {
                choose_indexer = params.parse().unwrap();
                let indexers_ref = indexers.read().await;
                let indexer = indexers_ref.get(&choose_indexer).unwrap();
                println!("\x1b[93m>>> Indexer changed to: {:?}\x1b[00m", indexer.indexer);
                println!(
                    "\x1b[93m>>> Deployment: {}\x1b[00m",
                    deployment_cid(&indexer.deployment)
                );
                println!("\x1b[93m>>> Price: {}\x1b[00m", indexer.price);
                println!("\x1b[93m>>> Endpoint: {}\x1b[00m", indexer.endpoint);
                println!("\x1b[93m>>> Peer: {}\x1b[00m", indexer.peer);
                drop(indexers_ref);
            }
            "set" => {
                let method_params = params.split_once(" ");
                if method_params.is_none() {
                    println!("\x1b[91mInvalid, type again!\x1b[00m");
                    continue;
                }
                let (method, params) = method_params.unwrap();
                let params = params.trim().to_owned();
                match method {
                    "web3" => match Http::new(&params) {
                        Ok(http) => {
                            web3_endpoint = params;
                            web3 = Web3::new(http);
                            println!("\x1b[93m>>> Web3 changed to: {}\x1b[00m", web3_endpoint);
                        }
                        Err(err) => {
                            println!("\x1b[91m>>> Error: {}\x1b[00m", err);
                        }
                    },
                    "channel" => {
                        cid = params.parse().unwrap();
                        println!(
                            "\x1b[93m>>> Channel changed to: {} {:#X}\x1b[00m",
                            cid, channels[cid].id,
                        );
                    }
                    _ => println!("\x1b[91mInvalid, type again!\x1b[00m"),
                }
            }
            "state-channel" => {
                let method_params = params.split_once(" ");
                let (method, params) = if method_params.is_none() {
                    (params.as_str(), "".to_owned())
                } else {
                    let (method, params) = method_params.unwrap();
                    let params = params.trim().to_owned();
                    (method, params)
                };
                if channels.len() == 0 && method != "open" && method != "add" {
                    println!("\x1b[91mNo Channel, please open or add!\x1b[00m");
                    continue;
                }
                match method {
                    "open" => {
                        let mut next_params = params.split(" ");
                        let amount = U256::from_dec_str(next_params.next().unwrap()).unwrap();
                        let expiration = U256::from_dec_str(next_params.next().unwrap()).unwrap();
                        let indexers_ref = indexers.read().await;
                        let choose = indexers_ref.get(&choose_indexer).unwrap();
                        let indexer = choose.indexer.clone();
                        let deployment = choose.deployment.clone();
                        let peer = choose.peer.clone();
                        let endpoint = choose.endpoint.clone();
                        let token = choose.token.clone();
                        drop(indexers_ref);

                        let state = OpenState::consumer_generate(
                            None,
                            indexer,
                            consumer,
                            amount,
                            expiration,
                            deployment,
                            vec![],
                            SecretKeyRef::new(&consumer_sk),
                        )
                        .unwrap();
                        let raw_state = serde_json::to_string(&state.to_json()).unwrap();

                        let res = if is_p2p {
                            let query = vec![Value::from(peer.to_base58()), Value::from(raw_state)];
                            let res = p2p_send
                                .sync_send(jsonrpc_params(0, "state-channel", query))
                                .await
                                .map_err(|e| {
                                    println!("{:?}", e);
                                    Error::ServiceException
                                });
                            jsonrpc_response(res)
                        } else {
                            proxy_request("post", &endpoint, "open", &token, raw_state, vec![]).await
                        };

                        match res {
                            Ok(data) => {
                                let state = OpenState::from_json(&data).unwrap();
                                println!("channelId:  {:#X}", state.channel_id);
                                println!("total:     {}", state.total);
                                println!("expiration: {}", state.expiration);
                                println!("indexer:    {:?}", state.indexer);
                                println!("consumer:   {:?}", state.consumer);

                                cid = channels.len();
                                channels.push(StateChannel {
                                    id: state.channel_id,
                                    indexer: state.indexer,
                                    consumer: state.consumer,
                                    deployment: deployment,
                                    expiration: state.expiration,
                                    total: state.total,
                                    spent: U256::from(0u64),
                                    onchain: U256::from(0u64),
                                    remote: U256::from(0u64),
                                    price: state.price,
                                    last_final: false,
                                    last_indexer_sign: state.indexer_sign,
                                    last_consumer_sign: state.consumer_sign,
                                });
                            }
                            Err(err) => println!("\x1b[91m>>> Error: {}\x1b[00m", err),
                        }
                    }
                    "checkpoint" => {
                        send_state(&web3, &state_channel, &channels[cid], "checkpoint", &consumer_sk).await;
                    }
                    "challenge" => {
                        send_state(&web3, &state_channel, &channels[cid], "challenge", &consumer_sk).await;
                    }
                    "respond" => {
                        send_state(&web3, &state_channel, &channels[cid], "respond", &consumer_sk).await;
                    }
                    "claim" => {
                        let channel_id = channels[cid].id;
                        let fn_data = state_channel
                            .abi()
                            .function("claim")
                            .and_then(|function| function.encode_input(&(channel_id,).into_tokens()))
                            .unwrap();
                        let gas = state_channel
                            .estimate_gas("claim", (channel_id,), channels[cid].consumer, Default::default())
                            .await;
                        if gas.is_err() {
                            println!("Channel not expired");
                            continue;
                        }
                        let gas = gas.unwrap();
                        let tx = TransactionParameters {
                            to: Some(state_channel.address()),
                            data: Bytes(fn_data),
                            gas: gas,
                            ..Default::default()
                        };
                        let signed = web3.accounts().sign_transaction(tx, &consumer_sk).await.unwrap();
                        let tx_hash = web3.eth().send_raw_transaction(signed.raw_transaction).await.unwrap();
                        println!("\x1b[94m>>> TxHash: {:?}\x1b[00m", tx_hash);
                    }
                    "show" => {
                        let result: (Token,) = state_channel
                            .query("channel", (channels[cid].id,), None, Options::default(), None)
                            .await
                            .unwrap();
                        match result.0 {
                            Token::Tuple(data) => {
                                let total: U256 = data[3].clone().into_uint().unwrap().into();
                                let spent: U256 = data[4].clone().into_uint().unwrap().into();
                                let expiration: U256 = data[5].clone().into_uint().unwrap().into();
                                println!("State Channel Status: {}", data[0]);
                                println!(" Indexer:  0x{}", data[1]);
                                println!(" Consumer: 0x{}", data[2]);
                                println!(" Count On-chain: {:?}, Now: {}", spent, channels[cid].spent);
                                println!(" Total:         {:?}", total);
                                println!(" Expiration:     {:?}", expiration);
                            }
                            _ => {}
                        }
                    }
                    "add" => {
                        let channel_id: U256 = params.parse().unwrap();
                        let result: (Token,) = state_channel
                            .query("channel", (channel_id,), None, Options::default(), None)
                            .await
                            .unwrap();
                        match result.0 {
                            Token::Tuple(data) => {
                                let total: U256 = data[3].clone().into_uint().unwrap().into();
                                let spent: U256 = data[4].clone().into_uint().unwrap().into();
                                let expiration: U256 = data[5].clone().into_uint().unwrap().into();
                                let deployment_vec = data[7].clone().into_fixed_bytes().unwrap();
                                let mut deployment = [0u8; 32];
                                deployment.copy_from_slice(&deployment_vec);
                                println!("State Channel Status: {}", data[0]);
                                println!(" Indexer:  0x{}", data[1]);
                                println!(" Consumer: 0x{}", data[2]);
                                println!(" On-chain Count:  {}", spent);
                                println!(" Total:          {}", total);
                                println!(" Expiration:      {}", expiration);
                                cid = channels.len();
                                channels.push(StateChannel {
                                    id: channel_id,
                                    indexer: data[1].clone().into_address().unwrap(),
                                    consumer: data[2].clone().into_address().unwrap(),
                                    deployment: deployment,
                                    total: total,
                                    spent: spent,
                                    onchain: spent,
                                    remote: spent,
                                    expiration: expiration,
                                    price: U256::from(10u64), // TODO need query to indexer
                                    last_final: false,
                                    last_indexer_sign: default_sign(),
                                    last_consumer_sign: default_sign(),
                                });
                            }
                            _ => {}
                        }
                    }
                    _ => println!("\x1b[91mInvalid, type again!\x1b[00m"),
                }
            }
            "query" => {
                let mut data = HashMap::new();
                data.insert("query", params);

                if channels.len() == 0 {
                    println!("\x1b[91mNo Channel, please open or add Channel!\x1b[00m");
                    continue;
                }

                let indexers_ref = indexers.read().await;
                let choose = indexers_ref.get(&channels[cid].indexer).unwrap();
                let peer = choose.peer.clone();
                let endpoint = choose.endpoint.clone();
                let token = choose.token.clone();
                drop(indexers_ref);

                let is_final = channels[cid].spent + channels[cid].price >= channels[cid].total;
                let next_spent = channels[cid].spent + channels[cid].price;
                println!("Next spent: {}", next_spent);
                let state = QueryState::consumer_generate(
                    channels[cid].id,
                    channels[cid].indexer,
                    channels[cid].consumer,
                    next_spent,
                    is_final,
                    SecretKeyRef::new(&consumer_sk),
                )
                .unwrap();
                let raw_query = serde_json::to_string(&data).unwrap();
                let raw_state = serde_json::to_string(&state.to_json()).unwrap();
                let res = if is_p2p {
                    let query = vec![
                        Value::from(peer.to_base58()),
                        Value::from(deployment_cid(&channels[cid].deployment)),
                        Value::from(raw_query),
                        Value::from(raw_state),
                    ];

                    let res = p2p_send
                        .sync_send(jsonrpc_params(0, "payg-sync", query))
                        .await
                        .map_err(|_| Error::ServiceException);
                    jsonrpc_response(res)
                } else {
                    proxy_request(
                        "post",
                        &endpoint,
                        &format!("payg/{}", deployment_cid(&channels[cid].deployment)),
                        &token,
                        raw_query,
                        vec![("Authorization".to_owned(), raw_state)],
                    )
                    .await
                };
                match res {
                    Ok(fulldata) => {
                        let (query, data) = (&fulldata[0], &fulldata[1]);
                        println!("\x1b[94m>>> Result: {}\x1b[00m", query);
                        let state = QueryState::from_json(&data).unwrap();

                        let check = (state.spent - channels[cid].spent) / channels[cid].price > 5i32.into();

                        channels[cid].spent = state.spent;
                        channels[cid].remote = state.remote;
                        channels[cid].last_final = state.is_final;
                        channels[cid].last_indexer_sign = state.indexer_sign;
                        channels[cid].last_consumer_sign = state.consumer_sign;

                        if check {
                            println!("Every 5 times will auto checkpoint...");
                            send_state(&web3, &state_channel, &channels[cid], "checkpoint", &consumer_sk).await;
                        }
                    }
                    Err(err) => println!("\x1b[91m>>> Error: {}\x1b[00m", err),
                }
            }
            _ => {
                println!("\x1b[91mInvalid, type again!\x1b[00m");
            }
        }
    }
    rl.save_history("history.txt").unwrap();
}

pub struct ConsumerP2p;

#[async_trait]
impl P2pHandler for ConsumerP2p {
    async fn channel_handle(_info: &str) -> Response {
        Response::None
    }

    async fn info_handle(_: Option<GroupId>) -> String {
        "".to_owned()
    }

    async fn event() {
        todo!()
    }
}
