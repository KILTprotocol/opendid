use sp_runtime::traits::{IdentifyAccount, Verify};

use subxt::{config::polkadot::PolkadotExtrinsicParams, config::Config, OnlineClient};

#[subxt::subxt(runtime_metadata_path = "./metadata.scale")]
pub mod kilt {}

// re-export all the auto generated code
pub use kilt::*;

pub type ProxyType = kilt::runtime_types::spiritnet_runtime::ProxyType;
pub type RuntimeCall = kilt::runtime_types::spiritnet_runtime::RuntimeCall;
pub type RuntimeEvent = kilt::runtime_types::spiritnet_runtime::RuntimeEvent;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KiltConfig;
impl Config for KiltConfig {
    type Hash = sp_core::H256;
    type Hasher = <subxt::config::SubstrateConfig as Config>::Hasher;
    type AccountId = <<Self::Signature as Verify>::Signer as IdentifyAccount>::AccountId;
    type Address = sp_runtime::MultiAddress<Self::AccountId, ()>;
    type Header = subxt::config::substrate::SubstrateHeader<u64, Self::Hasher>;
    type Signature = sp_runtime::MultiSignature;
    type ExtrinsicParams = PolkadotExtrinsicParams<Self>;
}

pub async fn connect(
    endpoint: &str,
) -> Result<OnlineClient<KiltConfig>, Box<dyn std::error::Error>> {
    let endpoint_url = match endpoint {
        "spiritnet" => "wss://spiritnet.kilt.io:443",
        "peregrine" => "wss://peregrine.kilt.io:443/parachain-public-ws",
        _ => endpoint,
    };
    Ok(OnlineClient::<KiltConfig>::from_url(endpoint_url).await?)
}
