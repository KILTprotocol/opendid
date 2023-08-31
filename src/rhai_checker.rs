use std::{collections::HashMap, sync::Mutex};

use base64::{alphabet, engine::general_purpose, Engine as Base64Engine};
use once_cell::sync::Lazy;
use rhai::{Engine, EvalAltResult, AST};

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
                log::info!("Compiling script: {} {}", path.display(), &script);
                let ast = engine.compile(&script)?;
                checks.push(ast);
            }
        }
        Ok(Self { engine, checks })
    }

    pub fn check(&self, data: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut scope = rhai::Scope::new();
        scope.push("ID_TOKEN", data.to_owned());
        for ast in &self.checks {
            log::info!("Running check");
            let result: Result<bool, Box<EvalAltResult>> =
                self.engine.eval_ast_with_scope(&mut scope, ast);
            if let Err(e) = result {
                return Err(e.to_string().into());
            }
            if !result.unwrap() {
                return Err("Check failed".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RhaiCheckerMap {
    map: HashMap<String, RhaiChecker>,
}

impl RhaiCheckerMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get(
        &mut self,
        client_id: &str,
        checks_directory: &str,
    ) -> Result<&RhaiChecker, Box<dyn std::error::Error>> {
        if !self.map.contains_key(client_id) {
            self.map
                .insert(client_id.to_string(), RhaiChecker::new(checks_directory)?);
        }
        Ok(self.map.get(client_id).unwrap())
    }
}

// setup a global variable for the checker map that can be accessed from all threads safely and is stored on the heap
// do it this way to avoid having to pass the map around everywhere
static CHECKER_MAP: Lazy<Mutex<RhaiCheckerMap>> = Lazy::new(|| Mutex::new(RhaiCheckerMap::new()));

pub fn check(
    client_id: &str,
    checks_directory: &str,
    data: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut checker_map = CHECKER_MAP.lock().unwrap();
    let checker = checker_map.get(client_id, checks_directory)?;
    checker.check(data)
}

fn parse_id_token(token: &str) -> Result<rhai::Dynamic, Box<EvalAltResult>> {
    // parse the jwt token into a json object
    let parts = token.split('.').collect::<Vec<&str>>();
    let payload = parts[1];
    let engine = base64::engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    let payload = match engine.decode(payload) {
        Ok(payload) => payload,
        Err(_) => return Err("Failed to decode payload".into()),
    };
    let payload = match std::str::from_utf8(&payload) {
        Ok(payload) => payload,
        Err(_) => return Err("Failed to convert payload to string".into()),
    };
    let payload: rhai::Dynamic = match serde_json::from_str(payload) {
        Ok(payload) => payload,
        Err(_) => return Err("Failed to parse payload as json".into()),
    };
    Ok(payload)
}
