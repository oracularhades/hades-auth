use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Deserialize, Clone)]
pub struct Creds {
    pub whoami: WhoAmI,
    pub acceptable_registries: Vec<AcceptedRegistryObject>
}

#[derive(Debug, Deserialize, Clone)]
pub struct WhoAmI {
    pub id: String,
    pub capability: String,
    pub registry: String,
    pub privatekey: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AcceptedRegistryObject {
    pub url: String,
    pub cache: u32,
    pub publickey: String
}

#[derive(Debug, Deserialize, Clone)]
pub struct SignedObject {
    pub regionmeta: RegionMeta,
    pub data: Value,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegionMeta {
    pub id: String,
    pub capability: String,
    pub registry: String
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegionObject {
    pub active: bool,
    pub id: String,
    pub alias: String,
    pub created: u128,
    pub updated: u128
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegistryResponseData {
    pub regions: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegistryHttpsResponseData {
    pub region: String,
    pub capability: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VerificationResponseObject {
    pub ok: bool,
    pub capability: String,
    pub body: Value
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegionCreds {
    pub region_object: RegionObject,
    pub public_key: String,
    pub private_key: String,
    pub jwt: String
}

#[derive(Debug, Deserialize, Clone)]
pub struct CapabilityCreds {
    pub capability_object: CapabilityObject,
    pub public_key: String,
    pub private_key: String,
    pub jwt: String
}

#[derive(Debug, Deserialize, Clone)]
pub struct CapabilityObject {
    pub active: bool,
    pub region_id: String,
    pub capability: String,
    pub publickey: String,
    pub created: u128,
    pub updated: u128,
    pub exp: u128
}

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