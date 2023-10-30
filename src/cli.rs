use anyhow::Context;
use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use std::path::PathBuf;

use crate::config::Config;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE", env)]
    config: PathBuf,

    #[command(flatten)]
    pub verbose: Verbosity<InfoLevel>,
}

impl Cli {
    pub fn get_config(&self) -> anyhow::Result<Config> {
        let config_file =
            std::fs::File::open(&self.config).context("Error opening the config file")?;
        let config: Config =
            serde_yaml::from_reader(config_file).context("Error parsing the config file")?;
        Ok(config)
    }
}
