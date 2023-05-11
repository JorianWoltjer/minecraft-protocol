use aes::{
    cipher::{AsyncStreamCipher, NewCipher},
    Aes128,
};
use anyhow::{anyhow, Result};
use cfb8::Cfb8;
use mojang_api::ServerAuthResponse;
use rand::{RngCore, SeedableRng};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    player::Player,
    protocol::{
        ConnectionState, EncryptionRequest, EncryptionResponse, Handshake, LoginStart,
        LoginSuccess, Reader, StatusPing, StatusPong, StatusRequest, StatusResponse, Writer,
    },
    RSA_KEY_PAIR,
};

type AesCfb8 = Cfb8<Aes128>;

#[derive(Debug)]
pub struct Packet {
    pub id: i32,
    pub data: Vec<u8>,
}
impl TryFrom<Vec<u8>> for Packet {
    type Error = anyhow::Error;

    fn try_from(data: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        let mut cursor = Reader::new(&data);
        let id = cursor.read_varint()?;
        Ok(Packet {
            id,
            data: cursor.get_leftover_bytes().to_vec(),
        })
    }
}
impl From<Packet> for Vec<u8> {
    fn from(packet: Packet) -> Self {
        let mut buffer = Writer::new();
        buffer.write_varint(packet.id);
        buffer.write_raw(&packet.data);
        buffer.into()
    }
}

pub struct Connection {
    stream: TcpStream,
    state: ConnectionState,
    player: Option<Player>,
    verify_token: [u8; 4],
    shared_secret: Option<[u8; 16]>,
    cipher: Option<AesCfb8>,
}
impl Connection {
    pub async fn new(stream: TcpStream) -> Self {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut verify_token = [0; 4];
        rng.fill_bytes(&mut verify_token);

        Connection {
            stream,
            state: ConnectionState::Handshaking,
            player: None,
            verify_token,
            shared_secret: None,
            cipher: None,
        }
    }

    async fn read_varint(&mut self) -> Result<usize> {
        let mut read = 0;
        let mut result = 0;
        loop {
            let read_value = self.stream.read_u8().await?;
            let value = read_value & 0b0111_1111;
            result |= (value as usize) << (7 * read);
            read += 1;
            if read > 5 {
                return Err(anyhow!("VarInt is too big"));
            }
            if (read_value & 0b1000_0000) == 0 {
                return Ok(result);
            }
        }
    }

    async fn read_packet(&mut self) -> Result<Packet> {
        let size = self.read_varint().await?;
        let mut buffer = vec![0; size];
        self.stream.read_exact(&mut buffer).await?;

        let buffer = &mut buffer[..];
        if let Some(cipher) = &mut self.cipher {
            cipher.decrypt(buffer);
        }

        Packet::try_from(buffer.to_vec())
    }

    async fn write_packet(&mut self, packet: Packet) -> Result<()> {
        let mut writer = Writer::new();
        writer.write_varint(packet.id);
        writer.write_raw(&packet.data);

        let mut writer2 = Writer::new();
        writer2.write_varint(writer.len() as i32);
        writer2.write_raw(Vec::from(writer).as_slice());

        let buffer = &mut Vec::from(writer2)[..];
        if let Some(cipher) = &mut self.cipher {
            cipher.encrypt(buffer);
        }

        self.stream.write_all(buffer).await?;
        Ok(())
    }

    pub async fn handle(&mut self) -> Result<()> {
        loop {
            match self.state {
                ConnectionState::Handshaking => self.handle_handshaking().await?,
                ConnectionState::Status => self.handle_status().await?,
                ConnectionState::Login => self.handle_login().await?,
                ConnectionState::Play => self.handle_play().await?,
                ConnectionState::Done => return Ok(()),
            }
        }
    }

    async fn handle_handshaking(&mut self) -> Result<()> {
        let packet = self.read_packet().await?;

        let handshake = match packet.id {
            0x00 => Handshake::try_from(packet.data)?,
            _ => return Err(anyhow!("Invalid packet id")),
        };

        println!("< {handshake:?}");
        self.state = handshake.next_state;

        Ok(())
    }

    async fn handle_status(&mut self) -> Result<()> {
        let packet = self.read_packet().await?;
        match packet.id {
            0x00 => {
                self.handle_status_request(StatusRequest::try_from(packet.data)?)
                    .await?
            }
            0x01 => {
                self.handle_status_ping(StatusPing::try_from(packet.data)?)
                    .await?
            }
            _ => return Err(anyhow!("Invalid packet id")),
        };
        Ok(())
    }

    async fn handle_status_request(&mut self, request: StatusRequest) -> Result<()> {
        println!("< {request:?}");

        let response = StatusResponse::new(json!({
                "version": {
                    "name": "1.19.4",
                    "protocol": 762
                },
                "players": {
                    "max": 42,
                    "online": 1,
                    "sample": [
                        {
                            "name": "Player",
                            "id": "4566e69f-c907-48ee-8d71-d7ba5aa00d20",
                        }
                    ]
                },
                "description": {
                    "text": "Hello, world!"
                },
            }
        ));
        println!("> {response:?}");
        let packet = Packet {
            id: 0x00,
            data: response.try_into()?,
        };
        self.write_packet(packet).await?;

        Ok(())
    }

    async fn handle_status_ping(&mut self, ping: StatusPing) -> Result<()> {
        println!("< {ping:?}");

        let response: StatusPong = ping.into();
        println!("> {response:?}");

        let packet = Packet {
            id: 0x01,
            data: response.try_into()?,
        };
        self.write_packet(packet).await?;

        self.state = ConnectionState::Done;
        Ok(())
    }

    async fn handle_login(&mut self) -> Result<()> {
        let packet = self.read_packet().await?;

        match packet.id {
            0x00 => {
                self.handle_login_start(LoginStart::try_from(packet.data)?)
                    .await?
            }
            0x01 => {
                self.handle_encryption_response(EncryptionResponse::try_from(packet.data)?)
                    .await?
            }
            0x02 => unimplemented!("Login Plugin Response"),
            _ => return Err(anyhow!("Invalid packet id")),
        };
        Ok(())
    }

    async fn handle_login_start(&mut self, login_start: LoginStart) -> Result<()> {
        println!("< {login_start:?}");

        self.player = Some(login_start.into());
        println!("{:?}", self.player);

        let response = EncryptionRequest::new(RSA_KEY_PAIR.public_key_to_der()?, self.verify_token);
        println!("> {response:?}");

        let packet = Packet {
            id: 0x01,
            data: response.try_into()?,
        };
        self.write_packet(packet).await?;

        Ok(())
    }

    async fn authenticate_player(&mut self) -> Result<ServerAuthResponse> {
        let player = self.player.clone().unwrap();
        let username = player.username.clone();
        let server_hash = mojang_api::server_hash(
            "",
            self.shared_secret.ok_or(anyhow!("Missing shared secret"))?,
            &RSA_KEY_PAIR.public_key_to_der()?,
        );

        let client = reqwest::Client::new();
        let string = client
            .get("https://sessionserver.mojang.com/session/minecraft/hasJoined")
            .query(&[("username", username), ("serverId", server_hash)])
            .send()
            .await?
            .text()
            .await?;

        let response = serde_json::from_str(&string)?;

        Ok(response)
    }

    async fn handle_encryption_response(
        &mut self,
        encryption_response: EncryptionResponse,
    ) -> Result<()> {
        println!("< {encryption_response:?}");

        if encryption_response.decrypt_verify_token()? != self.verify_token {
            return Err(anyhow!("Invalid verify token"));
        }

        let shared_secret = encryption_response.decrypt_shared_secret()?;

        self.shared_secret = Some(shared_secret);
        self.cipher = Some(AesCfb8::new_from_slices(&shared_secret, &shared_secret).unwrap());

        let auth_response = self.authenticate_player().await?;
        println!("{auth_response:?}");

        let response: LoginSuccess = auth_response.into();
        println!("> {response:?}");

        let packet = Packet {
            id: 0x02,
            data: response.try_into()?,
        };
        self.write_packet(packet).await?;

        self.state = ConnectionState::Play;

        // TODO: send a valid Login (play) packet here

        Ok(())
    }

    async fn handle_play(&mut self) -> Result<()> {
        let packet = self.read_packet().await?;

        println!("{packet:?}");

        Ok(())
    }
}
