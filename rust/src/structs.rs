use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Deserialize, Clone)]
pub struct Keypair {
    pub public_key: String,
    pub private_key: String
}

#[derive(Debug, Deserialize, Clone)]
pub struct DeviceDetails {
    pub ok: bool,
    pub device_id: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Signed_data {
    pub checksum: Option<String>,
    pub body_checksum: Option<String>,
    pub just_file_sha512: Option<String>
}

#[derive(Debug, Deserialize, Clone)]
pub struct Sign_output {
    pub params: String,
    pub params_as_value: Value,
    pub jwt: String
}