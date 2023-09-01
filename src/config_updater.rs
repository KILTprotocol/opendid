use std::{collections::HashMap, sync::Mutex};

use actix_web::web;

use crate::{config::EtcdConfig, routes::error::Error, AppState};

pub struct ConfigUpdater {
    app_state: web::Data<Mutex<AppState>>,
    cli: etcd_client::Client,
}

impl ConfigUpdater {
    pub async fn new(
        app_state: web::Data<Mutex<AppState>>,
        config: EtcdConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut opts = etcd_client::ConnectOptions::new();
        if config.user.is_some() && config.password.is_some() {
            opts = opts.with_user(config.user.unwrap(), config.password.unwrap());
        }
        if config.tls_ca_cert.is_some()
            || config.tls_domain_name.is_some()
            || (config.tls_client_cert.is_some() && config.tls_client_key.is_some())
        {
            let mut tls_options = etcd_client::TlsOptions::new();
            if let Some(ca_cert) = config.tls_ca_cert {
                let cert = etcd_client::Certificate::from_pem(ca_cert);
                tls_options = tls_options.ca_certificate(cert);
            }
            if let Some(domain_name) = config.tls_domain_name {
                tls_options = tls_options.domain_name(domain_name);
            }
            if let Some(client_cert) = config.tls_client_cert {
                if let Some(client_key) = config.tls_client_key {
                    let identity = etcd_client::Identity::from_pem(client_cert, client_key);
                    tls_options = tls_options.identity(identity);
                }
            }
            opts = opts.with_tls(tls_options);
        }

        let cli = etcd_client::Client::connect(config.endpoints, Some(opts)).await?;
        Ok(Self { app_state, cli })
    }

    pub async fn read_initial_config(&mut self) -> Result<(), Box<dyn std::error::Error + '_>> {
        let mut client_configs = {
            let app_state = self.app_state.lock()?;
            app_state.client_configs.clone()
        };
        let resp = self
            .cli
            .get(
                "/sara/clients",
                Some(etcd_client::GetOptions::new().with_prefix()),
            )
            .await?;
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
        let mut app_state = self.app_state.lock()?;
        app_state.client_configs = client_configs.clone();
        Ok(())
    }

    pub async fn watch_for_updates(&mut self) -> Result<(), Box<dyn std::error::Error + '_>> {
        let mut client_configs = {
            let app_state = self.app_state.lock()?;
            app_state.client_configs.clone()
        };
        // watch for changes
        let (_, mut stream) = self
            .cli
            .watch(
                "/sara/clients",
                Some(etcd_client::WatchOptions::new().with_prefix()),
            )
            .await?;
        log::info!("Watching for changes in /sara/clients");
        while let Some(resp) = stream.message().await? {
            for event in resp.events() {
                let client_id = event
                    .kv()
                    .ok_or(Error::OauthInvalidClientId)?
                    .key_str()?
                    .to_string()
                    .trim_start_matches("/sara/clients/")
                    .to_string();
                log::info!("Received event for client {}", client_id);
                match event.event_type() {
                    etcd_client::EventType::Put => {
                        log::info!("Received PUT event for client {}", client_id);
                        let client_config: crate::config::ClientConfig = serde_json::from_slice(
                            event.kv().ok_or(Error::FailedToParseMessage)?.value(),
                        )?;
                        client_configs.insert(client_id, client_config);
                    }
                    etcd_client::EventType::Delete => {
                        log::info!("Received DELETE event for client {}", client_id);
                        client_configs.remove(&client_id);
                    }
                }
            }
            let mut app_state = self.app_state.lock()?;
            app_state.client_configs = client_configs.clone();
        }

        Ok(())
    }
}
