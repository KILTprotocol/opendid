use clap::Parser;
use std::path::PathBuf;

use crate::config::Config;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,
}

impl Cli {
    pub fn get_config(&self) -> Result<Config, Box<dyn std::error::Error>> {
        let config_file = std::fs::File::open(&self.config)?;
        let config: Config = serde_yaml::from_reader(config_file)?;
        Ok(config)
    }

    pub fn set_log_level(&self) {
        match self.debug {
            0 => log::set_max_level(log::LevelFilter::Info),
            1 => log::set_max_level(log::LevelFilter::Debug),
            _ => log::set_max_level(log::LevelFilter::Trace),
        }
    }
}
