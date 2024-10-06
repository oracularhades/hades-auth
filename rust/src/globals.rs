use regex::Regex;
use url::Url;
use crate::structs::{Creds, Keypair};
use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;
use frank_jwt::{Algorithm, decode, ValidationOptions};
use std::process::Command;
use openssl::ec::{EcGroup, EcKey};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn VerifyJWT(jwt_token: &str, publickey: &str) -> Result<String, String> {
    // Decode the JWT with the public key and the ES512 algorithm
    // You can also specify some validation options, such as leeway, issuer, audience, etc.
    let res = decode(&jwt_token, &publickey, Algorithm::ES512, &ValidationOptions::default());

    // Check the result
    match res {
        Ok((header, payload)) => {
            // // The JWT is valid, print the header and payload as JSON
            // println!("Header:\n{}", serde_json::to_string_pretty(&header).unwrap());
            // println!("Payload:\n{}", serde_json::to_string_pretty(&payload).unwrap());

            return Ok(serde_json::to_string_pretty(&payload).unwrap());
        }
        Err(err) => {
            // The JWT is invalid, print the error
            println!("Error: {}", err);

            return Err(format!("fail"));
        }
    }
}

pub fn is_null_or_whitespace(str: &str) -> bool {
    str.trim().is_empty()
}

pub fn generate_random_id() -> String {
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut random_string = String::new();

    for _ in 0..100 {
        let random_index = rand::random::<usize>() % characters.len();
        random_string.push(characters.chars().nth(random_index).unwrap());
    }

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    random_string.push_str(&timestamp.to_string());
    random_string
}

pub fn value_to_hashmap(value: Value) -> Option<HashMap<String, String>> {
    match value {
        Value::Object(obj) => {
            let mut hashmap = HashMap::new();
            for (key, val) in obj.iter() {
                if let Some(val_str) = val.as_str() {
                    hashmap.insert(key.clone(), val_str.to_string());
                }
            }
            Some(hashmap)
        }
        _ => None,
    }
}