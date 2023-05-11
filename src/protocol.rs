use anyhow::{anyhow, Result};
use mojang_api::{ProfileProperty, ServerAuthResponse};
use openssl::rsa::Padding;
use serde_json::Value;
use uuid::Uuid;

use crate::RSA_KEY_PAIR;

// TODO: clear difference between clientbound and serverbound packets

pub struct Reader<'a> {
    bytes: &'a [u8],
    index: usize,
}
impl Reader<'_> {
    pub fn new(bytes: &[u8]) -> Reader {
        Reader { bytes, index: 0 }
    }

    pub fn read_varint(&mut self) -> Result<i32> {
        let mut read = 0;
        let mut result = 0;
        loop {
            let read_value = self.bytes[self.index];
            let value = read_value & 0b0111_1111;
            result |= (value as i32) << (7 * read);
            read += 1;
            if read > 5 {
                return Err(anyhow!("VarInt is too big"));
            }
            self.index += 1;
            if (read_value & 0b1000_0000) == 0 {
                return Ok(result);
            }
        }
    }

    pub fn read_string(&mut self) -> Result<String> {
        let length = self.read_varint()? as usize;
        let string = String::from_utf8(self.bytes[self.index..self.index + length].to_vec())?;
        self.index += length;
        Ok(string)
    }

    pub fn read_byte_array(&mut self) -> Result<Vec<u8>> {
        let length = self.read_varint()? as usize;
        let array = self.bytes[self.index..self.index + length].to_vec();
        self.index += length;
        Ok(array)
    }

    pub fn read_bool(&mut self) -> Result<bool> {
        let value = self.bytes[self.index] != 0;
        self.index += 1;
        Ok(value)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let value = u16::from_be_bytes(self.bytes[self.index..self.index + 2].try_into()?);
        self.index += 2;
        Ok(value)
    }
    pub fn read_i64(&mut self) -> Result<i64> {
        let value = i64::from_be_bytes(self.bytes[self.index..self.index + 8].try_into()?);
        self.index += 8;
        Ok(value)
    }

    pub fn read_uuid(&mut self) -> Result<Uuid> {
        let value = Uuid::from_slice(&self.bytes[self.index..self.index + 16])?;
        self.index += 16;
        Ok(value)
    }

    pub fn get_leftover_bytes(&self) -> &[u8] {
        &self.bytes[self.index..]
    }
}

pub struct Writer {
    bytes: Vec<u8>,
}
impl Writer {
    pub fn new() -> Writer {
        Writer { bytes: Vec::new() }
    }

    pub fn write_varint(&mut self, value: i32) {
        let mut value = value;
        loop {
            let mut temp = (value & 0b0111_1111) as u8;
            value >>= 7;
            if value != 0 {
                temp |= 0b1000_0000;
            }
            self.bytes.push(temp);
            if value == 0 {
                break;
            }
        }
    }

    pub fn write_string(&mut self, string: &str) {
        self.write_varint(string.len() as i32);
        self.bytes.extend_from_slice(string.as_bytes());
    }

    pub fn write_uuid(&mut self, uuid: &Uuid) {
        self.bytes.extend_from_slice(uuid.as_bytes());
    }

    pub fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    pub fn write_i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_bool(&mut self, value: bool) {
        self.bytes.push(value as u8);
    }

    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}
impl From<Writer> for Vec<u8> {
    fn from(val: Writer) -> Self {
        val.bytes
    }
}

#[derive(Debug)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: ConnectionState,
}
impl TryFrom<Vec<u8>> for Handshake {
    type Error = anyhow::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Reader::new(&bytes);
        let protocol_version = cursor.read_varint()?;
        let server_address = cursor.read_string()?;
        let server_port = cursor.read_u16()?;
        let next_state = match cursor.read_varint()? {
            1 => ConnectionState::Status,
            2 => ConnectionState::Login,
            _ => return Err(anyhow!("Invalid next state")),
        };
        Ok(Handshake {
            protocol_version,
            server_address,
            server_port,
            next_state,
        })
    }
}

#[derive(Debug)]
pub struct StatusRequest;
impl TryFrom<Vec<u8>> for StatusRequest {
    type Error = anyhow::Error;

    fn try_from(_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(StatusRequest)
    }
}

#[derive(Debug)]
pub struct StatusResponse {
    pub json: Value,
}
impl StatusResponse {
    pub fn new(json: Value) -> StatusResponse {
        StatusResponse { json }
    }
}
impl TryInto<Vec<u8>> for StatusResponse {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut writer = Writer::new();

        let json = serde_json::to_string(&self.json)?;
        writer.write_string(&json);

        Ok(writer.into())
    }
}

#[derive(Debug)]
pub struct StatusPing {
    pub payload: i64,
}
impl TryFrom<Vec<u8>> for StatusPing {
    type Error = anyhow::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Reader::new(&bytes);
        let payload = cursor.read_i64()?;
        Ok(StatusPing { payload })
    }
}

#[derive(Debug)]
pub struct StatusPong {
    pub payload: i64,
}
impl From<StatusPing> for StatusPong {
    fn from(ping: StatusPing) -> Self {
        StatusPong {
            payload: ping.payload,
        }
    }
}
impl TryInto<Vec<u8>> for StatusPong {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut writer = Writer::new();
        writer.write_i64(self.payload);
        Ok(writer.into())
    }
}

#[derive(Debug)]
pub struct LoginStart {
    pub username: String,
    pub uuid: Option<Uuid>,
}
impl TryFrom<Vec<u8>> for LoginStart {
    type Error = anyhow::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Reader::new(&bytes);
        let username = cursor.read_string()?;
        let uuid = if cursor.read_bool()? {
            let uuid = cursor.read_uuid()?;
            Some(uuid)
        } else {
            None
        };
        Ok(LoginStart { username, uuid })
    }
}

#[derive(Debug)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: [u8; 4],
}
impl EncryptionRequest {
    pub fn new(public_key: Vec<u8>, verify_token: [u8; 4]) -> EncryptionRequest {
        EncryptionRequest {
            server_id: String::from(""),
            public_key,
            verify_token,
        }
    }
}
impl TryInto<Vec<u8>> for EncryptionRequest {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut writer = Writer::new();
        writer.write_string(&self.server_id);
        writer.write_varint(self.public_key.len() as i32);
        writer.write_raw(&self.public_key);
        writer.write_varint(self.verify_token.len() as i32);
        writer.write_raw(&self.verify_token);
        Ok(writer.into())
    }
}

#[derive(Debug)]
pub struct EncryptionResponse {
    pub shared_secret: Vec<u8>,
    pub verify_token: Vec<u8>,
}
impl TryFrom<Vec<u8>> for EncryptionResponse {
    type Error = anyhow::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Reader::new(&bytes);
        let shared_secret = cursor.read_byte_array()?;
        let verify_token = cursor.read_byte_array()?;

        Ok(EncryptionResponse {
            shared_secret,
            verify_token,
        })
    }
}
impl EncryptionResponse {
    pub fn decrypt_shared_secret(&self) -> Result<[u8; 16], anyhow::Error> {
        let mut shared_secret = [0; 128];
        RSA_KEY_PAIR.private_decrypt(&self.shared_secret, &mut shared_secret, Padding::PKCS1)?;
        Ok(shared_secret[..16].try_into()?)
    }

    pub fn decrypt_verify_token(&self) -> Result<[u8; 4], anyhow::Error> {
        let mut verify_token = [0; 128];
        RSA_KEY_PAIR.private_decrypt(&self.verify_token, &mut verify_token, Padding::PKCS1)?;
        Ok(verify_token[..4].try_into()?)
    }
}

#[derive(Debug)]
pub struct LoginSuccess {
    pub uuid: Uuid,
    pub username: String,
    pub properties: Vec<ProfileProperty>,
}
impl From<ServerAuthResponse> for LoginSuccess {
    fn from(server_auth_response: ServerAuthResponse) -> Self {
        LoginSuccess {
            uuid: Uuid::from_bytes(*server_auth_response.id.as_bytes()),
            username: server_auth_response.name,
            properties: server_auth_response.properties,
        }
    }
}
impl From<LoginSuccess> for Vec<u8> {
    fn from(login_success: LoginSuccess) -> Self {
        let mut writer = Writer::new();
        writer.write_uuid(&login_success.uuid);
        writer.write_string(&login_success.username);
        writer.write_varint(login_success.properties.len() as i32);
        for property in login_success.properties {
            writer.write_string(&property.name);
            writer.write_string(&property.value);
            writer.write_bool(true);
            writer.write_string(&property.signature);
        }
        writer.into()
    }
}

#[derive(Debug)]
pub struct LoginDisconnect {
    pub reason: Value,
}
impl LoginDisconnect {
    pub fn new(reason: Value) -> LoginDisconnect {
        LoginDisconnect { reason }
    }
}
impl TryInto<Vec<u8>> for LoginDisconnect {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut writer = Writer::new();

        let json = serde_json::to_string(&self.reason)?;
        writer.write_string(&json);

        Ok(writer.into())
    }
}

#[derive(Debug)]
pub enum ConnectionState {
    Handshaking,
    Status,
    Login,
    Play,
    Done,
}
