use ethers::{
    abi::{Token, Tokenizable},
    prelude::*,
};
use std::env::args;
use subql_contracts::{plan_manager, service_agreement_registry, sqtoken, Network};
use subql_utils::{
    error::Error,
    tools::{cid_deployment, deployment_cid},
};

// Hardhat default account. just for padding when account missing.
const ACCOUNT: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const GAS_PRICE: u64 = 1_000_000_000;
const ENDPOINT: &str = "https://moonbeam-alpha.api.onfinality.io/public";

async fn init_client(sk: &str) -> (SignerMiddleware<Provider<Http>, LocalWallet>, U256, Address) {
    let endpoint = std::env::var("ENDPOINT_HTTP").unwrap_or(ENDPOINT.to_owned());
    let account = sk.parse::<LocalWallet>().unwrap();
    let address = account.address();
    let provider = Provider::<Http>::try_from(endpoint)
        .unwrap()
        .with_sender(account.address());

    let gas_price = provider.get_gas_price().await.unwrap_or(GAS_PRICE.into());

    let client = SignerMiddleware::new_with_provider_chain(provider, account)
        .await
        .unwrap();
    (client, gas_price, address)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    std::env::set_var("RUST_LOG", "info");
    tracing_subscriber::fmt::init();

    if let Some(subcommand) = args().nth(1) {
        match subcommand.as_str() {
            "show-templates" => {
                let (client, _, _) = init_client(ACCOUNT).await;
                let plan_contract = plan_manager(client.clone(), Network::Moonbase).unwrap();
                let result: U256 = plan_contract
                    .method::<_, U256>("planTemplateIds", ())
                    .unwrap()
                    .call()
                    .await
                    .unwrap();
                for i in 0..result.as_u32() - 1 {
                    let result: Token = plan_contract
                        .method::<_, Token>("planTemplates", (i,))
                        .unwrap()
                        .call()
                        .await
                        .unwrap();
                    let tokens = result.into_tuple().unwrap();
                    let period = U256::from_token(tokens[0].clone()).unwrap();
                    let daily = U256::from_token(tokens[1].clone()).unwrap();
                    let rate = U256::from_token(tokens[2].clone()).unwrap();
                    println!(
                        "Templates: {} {} period: {}s, daily limit: {}/day, rate limit: {}/min",
                        i, tokens[4], period, daily, rate
                    );
                }
            }
            "show-plans" => {
                if args().len() != 3 {
                    println!("cargo run --example mock-open show-plans 0xindexeraddress");
                    return Ok(());
                }
                let indexer: Address = args().nth(2).unwrap().parse().unwrap();

                let (client, _, _) = init_client(ACCOUNT).await;
                let plan_contract = plan_manager(client.clone(), Network::Moonbase).unwrap();
                let result: U256 = plan_contract
                    .method::<_, U256>("nextPlanId", (indexer,))
                    .unwrap()
                    .call()
                    .await
                    .unwrap();
                println!(
                    "Plan contract: {:?}, total plan: {}",
                    plan_contract.address(),
                    result
                );
                if result == U256::zero() {
                    return Ok(());
                }
                for i in 1..result.as_u32() + 1 {
                    let result: Token = plan_contract
                        .method::<_, Token>("plans", (indexer, i))
                        .unwrap()
                        .call()
                        .await
                        .unwrap();
                    let tokens = result.into_tuple().unwrap();
                    let deployment = deployment_cid(&H256::from_token(tokens[2].clone()).unwrap());
                    let price = U256::from_token(tokens[0].clone()).unwrap();
                    println!(
                        "Plans: {} {} - template: {}, deployment: {}, price: {}",
                        i, tokens[3], tokens[1], deployment, price,
                    );
                }
            }
            "show-close-agreements" => {
                if args().len() != 3 {
                    println!(
                        "cargo run --example mock-open show-close-agreements 0xindexeraddress"
                    );
                    return Ok(());
                }
                let indexer: Address = args().nth(2).unwrap().parse().unwrap();

                let (client, _, _) = init_client(ACCOUNT).await;
                let contract =
                    service_agreement_registry(client.clone(), Network::Moonbase).unwrap();
                println!("Service agreement contract: {:?}", contract.address());
                let result: U256 = contract
                    .method::<_, U256>("indexerCsaLength", (indexer,))
                    .unwrap()
                    .call()
                    .await
                    .unwrap();
                for i in 0..result.as_u32() {
                    let aid: U256 = contract
                        .method::<_, U256>("closedServiceAgreementIds", (indexer, i))
                        .unwrap()
                        .call()
                        .await
                        .unwrap();
                    let result: Token = contract
                        .method::<_, Token>("getClosedServiceAgreement", (aid,))
                        .unwrap()
                        .call()
                        .await
                        .unwrap();
                    let tokens = result.into_tuple().unwrap();
                    let deployment = deployment_cid(&H256::from_token(tokens[2].clone()).unwrap());
                    println!(
                        "Agreement: {}, plan: {}, consumer: 0x{}, deployment: {}",
                        aid, tokens[6], tokens[0], deployment
                    );
                }
            }
            "create-plan" => {
                if args().len() != 6 {
                    println!("cargo run --example mock-open create-plan indexersk price template deployment");
                    return Ok(());
                }
                let price = U256::from_dec_str(&args().nth(3).unwrap()).unwrap();
                let template = U256::from_dec_str(&args().nth(4).unwrap()).unwrap();
                let deployment = cid_deployment(&args().nth(5).unwrap());
                println!("price: {} template: {}", price, template);

                let (client, gas_price, _) = init_client(&args().nth(2).unwrap()).await;
                let contract = plan_manager(client.clone(), Network::Moonbase).unwrap();
                println!("Plan contract: {:?}", contract.address());

                let tx = contract
                    .method::<_, ()>("createPlan", (price, template, deployment))
                    .unwrap()
                    .gas_price(gas_price);
                let pending_tx = tx.send().await.unwrap();
                println!("waiting tx confirmation...");
                let _receipt = pending_tx.confirmations(1).await.unwrap();
            }
            "open-close-agreement" => {
                if args().len() != 7 && args().len() != 6 {
                    println!("cargo run --example mock-open open-close-agreement consumersk 0xindexeraddress deployment plan_id need_allowance");
                    return Ok(());
                }
                let indexer: Address = args().nth(3).unwrap().parse().unwrap();
                let deployment = cid_deployment(&args().nth(4).unwrap());
                let plan = U256::from_dec_str(&args().nth(5).unwrap()).unwrap();
                let need_allowance: bool = if args().len() == 7 {
                    args().nth(6).unwrap().parse().unwrap()
                } else {
                    false
                };

                let (client, gas_price, _) = init_client(&args().nth(2).unwrap()).await;
                let contract = plan_manager(client.clone(), Network::Moonbase).unwrap();
                println!("Plan contract: {:?}", contract.address());

                if need_allowance {
                    let sqtoken = sqtoken(client, Network::Moonbase).unwrap();
                    let amount: U256 = U256::from(100) * U256::from(1000000000000000000u64); // 18-decimal
                    let tx = sqtoken
                        .method::<_, ()>("increaseAllowance", (contract.address(), amount))
                        .unwrap()
                        .gas_price(gas_price);
                    let pending_tx = tx.send().await.unwrap();
                    println!("waiting increase allowance tx confirmation...",);
                    let _receipt = pending_tx.confirmations(1).await.unwrap();
                }

                let tx = contract
                    .method::<_, ()>("acceptPlan", (indexer, deployment, plan))
                    .unwrap()
                    .gas_price(gas_price);
                let pending_tx = tx.send().await.unwrap();
                println!("waiting close agreement tx confirmation...");
                let _receipt = pending_tx.confirmations(1).await.unwrap();
            }
            _ => {
                println!("Invalid subcommand!");
            }
        }
    }

    Ok(())
}
