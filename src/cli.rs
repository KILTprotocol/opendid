use clap::Parser;
use std::path::PathBuf;
use clap_verbosity_flag::{Verbosity, InfoLevel};

use crate::config::Config;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    #[command(flatten)]
    pub verbose: Verbosity<InfoLevel>,
}

impl Cli {
    pub fn get_config(&self) -> Result<Config, Box<dyn std::error::Error>> {
        let config_file = std::fs::File::open(&self.config)?;
        let config: Config = serde_yaml::from_reader(config_file)?;
        Ok(config)
    }
}
