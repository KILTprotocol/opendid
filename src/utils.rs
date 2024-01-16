pub fn get_endpoint_url(endpoint: &str) -> &str {
    match endpoint {
        "spiritnet" => "wss://spiritnet.kilt.io:443",
        "peregrine" => "wss://peregrine.kilt.io:443/parachain-public-ws",
        _ => endpoint,
    }
}
