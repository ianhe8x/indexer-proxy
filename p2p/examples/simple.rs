use subql_p2p::{
    libp2p::{identity::Keypair, Multiaddr},
    primitives::DEFAULT_P2P_ADDR,
    rpc::{channel_rpc_channel, helper::RpcParam},
    server::server as p2p_server,
    GroupId, P2pHandler, PeerId, Request, Response,
};
use tokio::sync::mpsc::Receiver;

use async_trait::async_trait;

pub struct ConsumerP2p;

#[async_trait]
impl P2pHandler for ConsumerP2p {
    async fn address(addr: Multiaddr) {
        println!("PUBLIC ADDRESS: {}", addr);
    }

    async fn channel_handle(info: &str) -> Response {
        println!("CHANNEL HANDLE: {}", info);
        Response::None
    }

    async fn info_handle(group: Option<GroupId>) -> String {
        println!("INFO HANDLE: {:?}", group);
        "".to_owned()
    }

    async fn event() {
        println!("EVENT");
    }

    async fn group_join(peer: PeerId, group: GroupId) -> Option<Request> {
        println!("GROUP JOIN: {} - {}", peer, group);
        Some(Request::Info)
    }

    async fn group_leave(peer: PeerId, group: GroupId) {
        println!("GROUP LEAVE: {} - {}", peer, group);
    }
}

async fn handle_channel(mut out_recv: Receiver<RpcParam>) {
    while let Some(msg) = out_recv.recv().await {
        // Do nothings
        println!("{}", msg);
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).init();

    // setup the endpoint bind
    let p2p_addr = std::env::var("P2P").unwrap_or(DEFAULT_P2P_ADDR.to_owned());
    let p2p_bind: Multiaddr = p2p_addr.parse().unwrap();
    println!("P2P bind: {}", p2p_bind);

    // listen message channel
    let (out_send, out_recv, _inner_send, inner_recv) = channel_rpc_channel();
    tokio::spawn(async move { handle_channel(out_recv).await });
    let channel = (out_send, inner_recv);

    // generate the key
    let key = Keypair::generate_ed25519();

    // start p2p service
    p2p_server::<ConsumerP2p>(p2p_bind, None, None, Some(channel), None, key)
        .await
        .unwrap();
}
