use std::{collections::HashMap, sync::Arc};

use base64::{alphabet, engine::general_purpose, Engine as Base64Engine};

use rhai::{Engine, EvalAltResult, AST};

use crate::constants::ID_TOKEN_VARIABLE_NAME;

#[derive(Debug)]
pub struct RhaiChecker {
    engine: Engine,
    checks: Vec<AST>,
}

impl RhaiChecker {
    pub fn new(check_directory: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut engine = Engine::new();
        engine.register_fn("parse_id_token", parse_id_token);
        let mut checks = Vec::new();
        for entry in std::fs::read_dir(check_directory)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let script = std::fs::read_to_string(&path)?;
                log::info!("Compiling script: {}", path.display());
                let ast = engine.compile(&script)?;
                checks.push(ast);
            }
        }
        Ok(Self { engine, checks })
    }

    pub fn check(&self, data: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut scope = rhai::Scope::new();
        scope.push(ID_TOKEN_VARIABLE_NAME, data.to_owned());
        for ast in &self.checks {
            log::info!("Running check");
            let result: Result<bool, Box<EvalAltResult>> =
                self.engine.eval_ast_with_scope(&mut scope, ast);
            match result {
                Err(e) => return Err(e.to_string().into()),
                Ok(false) => return Err("Check failed".into()),
                Ok(true) => {}
            }
        }
        Ok(())
    }
}

// This struct holds a RhaiChecker for each client
// The RhaiChecker is created on demand when a client_id is first seen and cached afterwards
#[derive(Clone, Debug)]
pub struct RhaiCheckerMap {
    map: HashMap<String, Arc<RhaiChecker>>,
}

impl RhaiCheckerMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get_or_create(
        &mut self,
        client_id: &str,
        checks_directory: &str,
    ) -> Result<&RhaiChecker, Box<dyn std::error::Error>> {
        if !self.map.contains_key(client_id) {
            self.map.insert(
                client_id.to_string(),
                Arc::new(RhaiChecker::new(checks_directory)?),
            );
        }
        Ok(self.map.get(client_id).unwrap())
    }
}

fn parse_id_token(token: &str) -> Result<rhai::Dynamic, Box<EvalAltResult>> {
    // parse the jwt token into a json object
    let parts = token.split('.').collect::<Vec<&str>>();
    if parts.len() != 3 {
        return Err("Invalid token".into());
    }
    let payload = parts[1];
    let engine = base64::engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    let payload = engine
        .decode(payload)
        .map_err(|_| "Failed to decode payload")?;
    let payload =
        std::str::from_utf8(&payload).map_err(|_| "Failed to convert payload to string")?;
    serde_json::from_str(payload).map_err(|_| "Failed to parse payload as json".into())
}
