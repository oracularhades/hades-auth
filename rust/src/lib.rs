use oracularhades_mirror_frank_jwt::{Algorithm, encode, decode};
use serde_json::{json, Value};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use std::collections::HashMap;
use std::error::Error;
use sha2::{Sha256, Sha512, Digest};

mod globals;
mod structs;

use crate::globals::{get_creds, resolve_txt_promise, url_sanitize, is_valid_hostname, unsafe_noverification_jwt_payload_decode, VerifyJWT, is_null_or_whitespace, generate_random_id};
use crate::structs::*;

pub async fn Sign(params: Value, body: Option<&str>, private_key: &str, only_use_field_for_body: Option<&str>) -> Result<Sign_output, String> {
    // Create an unsorted_data variable. This is used to store params data that is not yet in alphabetical order. It's important for params to be in alphabetical order, as params could be jumbled during transit, for the signature to be correct, it needs to be the exact same as when it was signed.
    let mut unsorted_data: HashMap<String, String> = HashMap::new();

    // Create params_as_hashmap. This takes serde::Value and converts it to a HashMap. I originally made "params" be a HashMap<Value, Value> before realising Serde was better. It's future-proofing to just convert to HashMap<String, String>. Some people might complain about using Serde, but that day is not today.
    let mut params_as_hashmap: HashMap<String, String> = HashMap::new();
    if let Some(array) = params.as_array() {
        for item in array {
            if let Some(obj) = item.as_object() {
                for (key, value) in obj {
                    if let Some(value_str) = value.as_str() {
                        params_as_hashmap.insert(key.to_string(), value_str.to_string());
                    }
                }
            }
        }
    }

    // Drain params_as_hashmap into unsorted_data.
    unsorted_data.extend(params_as_hashmap.into_iter());

    // If there is a body, we need to hash it and later include that hash in the signed JWT.
    if let Some(body_str) = body {
        let hash_hex: String;
        // let mut hash_hex_file: Option<String> = None;

        let mut hasher = Sha512::new(); // Create instance of Sha512 hasher.
        hasher.update(body_str); // Add body string to the hasher.
        let result = hasher.finalize(); // Output the hash, however, doesn't output the hash as hex.
        hash_hex = hex::encode(Sha512::digest(result.clone())); // Digest the hash and encode to hex.
        println!("{:?}", hash_hex.clone());

        // # If the data is formdata and "only_use_field" is specified, we need to make a unique hash using that data in that formdata field. This is because some web-servers are absolutely painful trying to get a complete form-data output (looking at you express.js) and sometimes only req.body["file"] works, thus we cannot get the full formdata without an overhaul, and I do not expect developers to overhaul their code because of something that stupid. Instead, by creating a hash of a specific field (e.g one that contains an image) alongside the existing formdata hash, you can still authenticate a field. However, this needs to be re-vamped in the future, "only_use_field" is such a dumb name (because we're still keeping the formdata hash as well), it's so painful it's just limited to a single field. Instead, I should add a true/false "unique_hashes" and when set to true, should output a JSON object containing the field name and it's hash, so that can be included in the signed JWT. This is literally making me nauseous because I HATE it when something isn't perfect, but I have other things to do right now.
        // # This is incomplete until I find a good multi-part form-data parse for Rust.
        // if let Some(only_use_field) = only_use_field_for_body {
        //     let form_data = FormData::new().unwrap();
        //     form_data.append_with_str(only_use_field, body_str).unwrap();
        //     let hash_field = get_formdata_field_hash(&form_data, only_use_field).await?;
        //     hash_hex_file = Some(hash_field);
        // }

        // Update unsorted_data to include the body sha512 hash.
        unsorted_data.insert("body_sha512".to_string(), hash_hex);

        // Update unsorted_data to include the specific field sha512 hash.
        // note to self: josh get your fucking brain-fog variable naming scheme shit together. One second it's "params" and the next it's "metadata", then elsewhere it's "specific field" and here it's "file". Sincerely, Josh.
        // # This goes un-used for now.
        // if let Some(hash_hex_file) = hash_hex_file {
        //     unsorted_data.insert("just_file_sha512".to_string(), hash_hex_file);
        // }
    }

    let mut keys: Vec<String> = Vec::new(); // Create a keys Vec. This is referring to object/JSON keys.

    keys.extend(unsorted_data.keys().cloned()); // Drain unsorted_data into keys.
    keys.sort(); // Sort keys so they are in alphabetical order.

    // Create a new HashMap<String, String> with all our params, excluding certain keys.
    // TODO: josh why is this even here - josh.
    let mut data: HashMap<String, String> = HashMap::new();
    for key in keys.iter() {
        if key != "authenticator_JWT_Token" { // Excluded keys.
            if let Some(value) = unsorted_data.get(key) {
                data.insert(key.clone(), value.clone());
            }
        }
    }

    // Serialize as JSON using Serde.
    let data_json = serde_json::to_string(&data).expect("Fail");

    // Get the Sha512 hash of our data.
    let mut hasher = Sha512::new(); // Create new sha512 hash.
    hasher.update(data_json); // Add data to hasher.
    let output_sha512_checksum = hasher.finalize(); // Finalize the hash.
    let output_sha512_checksum_hex = output_sha512_checksum.iter().map(|byte| format!("{:02x}", byte)).collect::<String>();
    // Tf is this hex shit?? todo: fix this.

    // Create signed JWT.
    let jwt_data = json!({
        "checksum": output_sha512_checksum_hex,
        "body_checksum": data.get("body_sha512").unwrap_or(&"".to_string()),
        "just_file_sha512": data.get("just_file_sha512").unwrap_or(&"".to_string())
    });

    // Format private key (TODO: Make it so any existing header/footer is removed so the key can be formatted with or without header/footer and still work).
    let private_key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        private_key
    );

    let mut header = json!({});
    let jwt = encode(header, &private_key_pem, &jwt_data, Algorithm::ES512).expect("JWT signing failed."); // Sign the JWT.

    let mut params_clone = params.clone(); // Create a clone of params, since we don't want to mess up the original params.
    params_clone["authenticator_JWT_Token"] = Value::from(jwt.clone()); // Add the signed JWT to params output.

    let output_params = serde_urlencoded::to_string(json!(params_clone)).expect("Failed to encode URL parameters"); // Convert parmas_clone from Serde::Value to url-encoded string.

    Ok(Sign_output {
        params: output_params, // For the end-developer's convenience, output the new params as URL params so they can just throw it onto the end of their request.
        params_as_value: params_clone, // Params as serde::Value
        jwt: jwt // Pass back signed JWT.
    })
}

pub async fn authenticate(
    body: Option<String>,
    params: Value,
    jwt: &str,
    public_key: &str,
    pathname: &str,
    use_cropped_body: bool,
) -> Result<bool, String> {
    let mut keys: Vec<String> = Vec::new();

    // Create an unsorted_data variable. This is used to store params data that is not yet in alphabetical order. It's important for params to be in alphabetical order, as params could be jumbled during transit, for the signature to be correct, it needs to be the exact same as when it was signed.
    let mut unsorted_data: HashMap<String, String> = HashMap::new();

    // Create params_as_hashmap. This takes serde::Value and converts it to a HashMap. I originally made "params" be a HashMap<Value, Value> before realising Serde was better. It's future-proofing to just convert to HashMap<String, String>. Some people might complain about using Serde, but that day is not today.
    let mut params_as_hashmap: HashMap<String, String> = HashMap::new();
    if let Some(array) = params.as_array() {
        for item in array {
            if let Some(obj) = item.as_object() {
                for (key, value) in obj {
                    if let Some(value_str) = value.as_str() {
                        params_as_hashmap.insert(key.to_string(), value_str.to_string());
                    }
                }
            }
        }
    }

    // Drain params_as_hashmap into unsorted_data.
    unsorted_data.extend(params_as_hashmap.into_iter());

    keys.extend(unsorted_data.keys().cloned()); // Drain unsorted_data into keys.
    keys.sort(); // Sort keys so they are in alphabetical order.

    // Create a new HashMap<String, String> with all our params, excluding certain keys.
    let mut data: HashMap<String, String> = HashMap::new();
    for key in keys.iter() {
        if key != "authenticator_JWT_Token" { // Exclude certain keys.
            if let Some(value) = unsorted_data.get(key) {
                data.insert(key.clone(), value.clone());
            }
        }
    }

    // Check the pathname inside the signed-object.
    if let Some(data_pathname) = data.get("authenticator_pathname") {
        if !is_null_or_whitespace(data_pathname) {
            if data_pathname != pathname {
                return Err(format!(
                    "Signed URL is \"{}\" and does not match \"{}\"",
                    data_pathname,
                    pathname
                ));
            }
        }
    }

    // Format public key (TODO: Make it so any existing header/footer is removed so the key can be formatted with or without header/footer and still work).
    let public_key_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        public_key
    );

    // Verify signed JWT against end-developer provided public-key.
    let verify_jwt_status_value = VerifyJWT(jwt.to_string(), public_key_pem.to_string()).expect("Failed to verify jwt");
    
    // We've verified the signed JWT matches the end-developer provided public-key. Now we need to make sure the data is authenticated.

    // Get parse "Signed_data" (information about the request, like hashes) data from signed JWT.
    let verify_jwt_status: Signed_data = serde_json::from_str(&verify_jwt_status_value).unwrap();

    let mut params_sha512_authed_checksum = verify_jwt_status.checksum.expect("");
    let mut body_sha512_authed_checksum: Option<String> = verify_jwt_status.body_checksum;

    // If "use_cropped_body" is specified and the body is form-data, authenticate() will verified the specific form-data field. This integrates with "use_cropped_body" in sign(). This implementation is terrible and will be removed in future versions. Please refer to "use_cropped_body" code comments in sign() for more details.
    if use_cropped_body {
        if let Some(just_file_sha512) = verify_jwt_status.just_file_sha512 {
            body_sha512_authed_checksum = Some(just_file_sha512);
        } else {
            return Err(
                "use_cropped_body is true - however, jwt.just_file_sha512 is null."
                    .to_string(),
            );
        }
    }

    println!("data {:?}", data.clone());

    let data_new = serde_json::to_string(&data).unwrap();
    println!("data_new {}", data_new.clone());

    // todo: there isn't anything checking for null with values like the checksum, so they could be null, you probably won't get very far, but is a good thing to implement.

    // Verify params match hash in signed JWT.
    let mut hasher = Sha512::new(); // Create new sha512 hash.
    hasher.update(data_new); // Add data to hasher.
    let result = hasher.finalize(); // Finalize the hash.
    if params_sha512_authed_checksum != hex::encode(Sha512::digest(result.clone())) { // Ensure params matches hash in signed JWT.
        return Err("Incoming data does not match checksum in JWT packet.".to_string());
    }

    // If there is a body, make sure it matches the checksum in signed JWT.
    if let Some(body) = body {
        let mut hasher = Sha256::new(); // Create new sha512 hash.
        hasher.update(serde_json::to_string(&body.as_bytes()).unwrap().as_bytes()); // Add data to hasher.
        let result = hasher.finalize(); // Finalize the hash.

        let unverified_body_hash_as_hex: String = hex::encode(Sha512::digest(result.clone())); // Digest and convert hash to hex.
        println!("body {:?}", unverified_body_hash_as_hex);

        if body_sha512_authed_checksum.expect("Body provided but no body hash was provided in incoming signed JWT.") != unverified_body_hash_as_hex { // Ensure body matches hash in signed JWT.
            return Err(
                "Incoming body data does not match checksum in JWT packet.".to_string(),
            );
        }
    }

    Ok(true) // Authentication complete!
}

pub fn GenerateKeyPair() -> Keypair {
    // Create a new Elliptic Curve group using the P-521 curve (NIST curve)
    let ec_group = EcGroup::from_curve_name(Nid::SECP521R1).expect("Failed to create EC group");

    // Generate a new private key
    let private_key = EcKey::generate(&ec_group).expect("Failed to generate private key");

    // Get private key in PEM format
    let private_key_pem = private_key
        .private_key_to_pem()
        .expect("Failed to convert private key to PEM format");

    // Get public key in PEM format
    let public_key_pem = private_key
        .public_key_to_pem()
        .expect("Failed to convert public key to PEM format");

    // // Print private and public keys
    // println!("ES512 Private Key:");
    // println!("{}", String::from_utf8_lossy(&private_key_pem));
    // println!("ES512 Public Key:");
    // println!("{}", String::from_utf8_lossy(&public_key_pem));

    let keys = Keypair {
        private_key: String::from_utf8_lossy(&private_key_pem).to_string(),
        public_key: String::from_utf8_lossy(&public_key_pem).to_string()
    };
    
    return keys;
}

pub async fn onboard_new_device(public_key: &str) -> Result<DeviceDetails, Box<dyn Error>> {
    if public_key.trim().is_empty() {
        return Err("public_key is null or whitespace.".into());
    }

    let device_id = generate_random_id();

    // let public_key_import = import_elliptic_public_key(&format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", public_key)).await?;
    // if public_key_import.usages()[0] != "verify" || public_key_import.usages().len() != 1 {
    //     return Err("Public key usages array must be [\"sign\", \"verify\"]".into());
    // }
    // if public_key_import.algorithm().name() != "ECDSA" {
    //     return Err("Algorithm name must be ECDSA".into());
    // }
    // // if public_key_import.algorithm().named_curve() != "P-521" {
    // //     return Err("namedCurve must be P-521.".into());
    // // }
    // if public_key_import.key_type() != "public" {
    //     return Err("Key type MUST be public key. It is extremely insecure to surrender your private authentication key. You should consider the provided RSA key compromised, please generate a new key.".into());
    // }

    Ok(DeviceDetails { ok: true, device_id })
}