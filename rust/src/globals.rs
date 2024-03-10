use regex::Regex;
use url::Url;
use crate::structs::{Creds, Keypair};
use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;
use oracularhades_mirror_frank_jwt::{Algorithm, decode, ValidationOptions};
use std::process::Command;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn matches_characters(input_string: &str, regex_string: &str) -> bool {
    let re = Regex::new(regex_string).unwrap();

    let is_valid = re.is_match(input_string);

    return is_valid;
}

pub async fn resolve_txt_promise(domain: &str) -> Result<Vec<String>, String> {
    // Restricting what characters can be used here is extremely important to help prevent command line injection.
    if (matches_characters(domain, r"^[A-Za-z0-9.-]+$") != true) {
        return Err("Invalid domain. Domain must only include characters that match ^[A-Za-z0-9.-]+$".to_string());
    }
    let output = Command::new("nslookup")
        .arg("-q=TXT")
        .arg(domain)
        .output()
        .expect("Failed to run nslookup");

    // Convert the output to a string
    let output_str = String::from_utf8(output.stdout).expect("Invalid UTF-8");

    // Split the output by lines and collect them into a vector
    let lines: Vec<&str> = output_str.split('\n').collect();

    // Create an empty vector to store the TXT records
    let mut txt_records: Vec<String> = Vec::new();

    // Loop through the lines and find the ones that start with "example.com"
    for line in lines {
        if line.starts_with(domain) {
            let line_new = line.replace("\" \"", "");
            // Split the line by spaces and get the last element, which is the TXT record
            let txt_record = line_new.split(' ').last().expect("Invalid line format");

            // Remove the double quotes from the TXT record and push it to the vector
            let txt_record = txt_record.trim_matches('"').to_string();
            txt_records.push(txt_record);
        }
    }

    // Return the vector of TXT records
    Ok(txt_records)
}

pub fn is_valid_hostname(hostname: &str) -> bool {
    let regex = Regex::new(r"^[a-zA-Z0-9]+$").unwrap();
    
    // Test the input fails regex test
    if !regex.is_match(hostname) {
        return false;
    }

    match Url::parse(&format!("https://{}", hostname)) {
        Ok(url) => {
            // Check if the URL consists of only scheme and host
            // If it has pathname, search, hash, or credentials, it's not just a hostname
            url.path() == "/" && url.query().is_none() && url.fragment().is_none() && url.username().is_empty() && url.password().is_none()
        },
        Err(_) => false, // If parsing fails, it's not a valid hostname
    }
}

pub fn url_sanitize(data: &str) -> String {
    let sanitized_data = data.chars()
        .filter(|&c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        .collect::<String>();
    sanitized_data
}

pub fn get_creds(creds: Option<Creds>) -> Option<Creds> {
    match creds {
        Some(creds) => {
            // Access the entire Creds object if creds is Some(creds)
            Some(creds)
        },
        None => {
            // Handle the None case here if needed
            // For now, returning None if input is None
            None
        }
    }
}

fn get_jwt_payload(jwt: String) -> Result<Value, String> {
    // Split the token into three parts
    let parts: Vec<&str> = jwt.split('.').collect();
    // Check if the token has three parts
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }
    let engine = general_purpose::STANDARD_NO_PAD;
    // Decode the second part, which is the payload
    let payload = engine.decode(parts[1]).unwrap();
    // Parse the payload as a JSON value
    let json = serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
    // Return the JSON value
    Ok(json)
}

pub fn unsafe_noverification_jwt_payload_decode(jwt_token: String) -> Result<Value, String> {
    let payload = get_jwt_payload(jwt_token);
    // Deserialize the JSON payload into your struct
    match payload {
        Ok(json) => {
            // println!("Incoming JWT Payload: {}", json);
            Ok(json)
        }
        Err(_) => {
            return Err("Failed to decode JSON from JWT payload".to_string())
        },
    }
}

pub fn VerifyJWT(jwt_token: String, publickey: String) -> Result<String, String> {
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

// pub fn is_null_or_whitespace(s: String) -> bool {
//     match s {
//         string if string == "null" || string == "undefined" => true,
//         string => string.trim().is_empty(),
//     }
// }

pub fn is_null_or_whitespace(str: &str) -> bool {
    str.trim().is_empty()
}

pub fn generate_random_id() -> String {
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut random_string = String::new();

    for _ in 0..20 {
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