use crate::{config::EtcdConfig, routes::error::Error, AppState};
use actix_web::web;
use std::sync::Mutex;

// ConfigUpdater is responsible for fetching client configurations from etcd and
// updating the app state with the latest configurations.
pub struct ConfigUpdater {
    app_state: web::Data<Mutex<AppState>>,
    cli: etcd_client::Client,
}

impl ConfigUpdater {
    // new creates a new ConfigUpdater.
    // it takes a protected reference to the app state and the etcd config.
    pub async fn new(
        app_state: web::Data<Mutex<AppState>>,
        config: EtcdConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // first we need to assemble the etcd client options
        let mut opts = etcd_client::ConnectOptions::new();

        // we support user/password
        if let Some(user_auth) = config.user_auth {
            opts = opts.with_user(user_auth.username, user_auth.password);
        }

        if let Some(tls_auth) = config.tls_auth {
            let mut tls_options = etcd_client::TlsOptions::new()
                .domain_name(tls_auth.domain_name)
                .ca_certificate(etcd_client::Certificate::from_pem(
                    tls_auth.ca_cert,
                ));
            if let Some(client_auth) = tls_auth.client_auth {
                let identity = etcd_client::Identity::from_pem(
                    client_auth.client_cert,
                    client_auth.client_key,
                );
                tls_options = tls_options.identity(identity);
            }
            opts = opts.with_tls(tls_options);
        }

        // now we can create the client
        let cli = etcd_client::Client::connect(config.endpoints, Some(opts)).await?;

        Ok(Self { app_state, cli })
    }

    // read_initial_config reads the initial client configurations from etcd.
    pub async fn read_initial_config(&mut self) -> Result<(), Box<dyn std::error::Error + '_>> {
        // we start from the client configs in the current app state
        let mut client_configs = {
            let app_state = self.app_state.lock()?;
            app_state.client_configs.clone()
        };

        // we fetch all the client configs from etcd prefixed by "/sara/clients"
        let resp = self
            .cli
            .get(
                "/sara/clients",
                Some(etcd_client::GetOptions::new().with_prefix()),
            )
            .await?;

        // we iterate over the results and parse the client configs
        for kv in resp.kvs() {
            let client_id = kv
                .key_str()?
                .to_string()
                .trim_start_matches("/sara/clients/")
                .to_string();
            let client_config: crate::config::ClientConfig = serde_json::from_slice(kv.value())?;
            log::info!("Loaded client config for {}", &client_id);
            client_configs.insert(client_id, client_config);
        }

        // we update the app state with the latest client configs
        let mut app_state = self.app_state.lock()?;
        app_state.client_configs = client_configs.clone();
        Ok(())
    }

    // watch_for_updates watches for changes in the client configurations.
    pub async fn watch_for_updates(&mut self) -> Result<(), Box<dyn std::error::Error + '_>> {
        // we start from the client configs in the current app state
        let mut client_configs = {
            let app_state = self.app_state.lock()?;
            app_state.client_configs.clone()
        };

        // we watch for changes in "/sara/clients"
        let (_, mut stream) = self
            .cli
            .watch(
                "/sara/clients",
                Some(etcd_client::WatchOptions::new().with_prefix()),
            )
            .await?;
        log::info!("Watching for changes in /sara/clients");

        // we iterate over the stream of events
        while let Some(resp) = stream.message().await? {
            for event in resp.events() {
                // we parse the client id from the event key
                let client_id = event
                    .kv()
                    .ok_or(Error::OauthInvalidClientId)?
                    .key_str()?
                    .to_string()
                    .trim_start_matches("/sara/clients/")
                    .to_string();
                log::info!("Received event for client {}", client_id);
                match event.event_type() {
                    // if the event is a PUT, we parse the client config and add it to the map
                    etcd_client::EventType::Put => {
                        log::info!("Received PUT event for client {}", client_id);
                        let client_config: crate::config::ClientConfig = serde_json::from_slice(
                            event.kv().ok_or(Error::FailedToParseMessage)?.value(),
                        )?;
                        client_configs.insert(client_id, client_config);
                    }
                    // if the event is a DELETE, we remove the client config from the map
                    etcd_client::EventType::Delete => {
                        log::info!("Received DELETE event for client {}", client_id);
                        client_configs.remove(&client_id);
                    }
                }
            }

            // we update the app state with the latest client configs
            let mut app_state = self.app_state.lock()?;
            app_state.client_configs = client_configs.clone();
        }

        Ok(())
    }
}
