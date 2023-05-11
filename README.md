# Minecraft Server Protocol (1.19.4)

An implementation of *a few* packets in the Minecraft protocol. Starts a server on port `:25565` that responds to [Server List Ping](https://wiki.vg/Server_List_Ping), and performs the login protocol with encryption and Mojang authentication to verify the player. After this step the server just listens for more packets, and does not actually act as a real server. 

Includes some verbose logging for the packets going back and forth, for example:

```
Listening on 0.0.0.0:25565...
New connection from 127.0.0.1:3516
< Handshake { protocol_version: 762, server_address: "127.0.0.1", server_port: 25565, next_state: Status }
< StatusRequest
> StatusResponse { json: Object {"description": Object {"text": String("Hello, world!")}, "players": Object {"max": Number(42), "online": Number(1), "sample": Array [Object {"id": String("4566e69f-c907-48ee-8d71-d7ba5aa00d20"), "name": String("Player")}]}, "version": Object {"name": String("1.19.4"), "protocol": Number(762)}} }
< StatusPing { payload: 24088 }
> StatusPong { payload: 24088 }
New connection from 127.0.0.1:3518
< Handshake { protocol_version: 762, server_address: "127.0.0.1", server_port: 25565, next_state: Login }
< LoginStart { username: "Jorian", uuid: Some(4566e69f-c907-48ee-8d71-d7ba5aa00d20) }
> EncryptionRequest { server_id: "", public_key: [48, 129, ..., 0, 1], verify_token: [229, 204, 211, 87] }
< EncryptionResponse { shared_secret: [128, 62, ..., 69, 207], verify_token: [59, 216, ..., 152, 131] }
ServerAuthResponse { id: 4566e69f-c907-48ee-8d71-d7ba5aa00d20, name: "Jorian", properties: [ProfileProperty { name: "textures", value: "ewo...jv8=" }] }
> LoginSuccess { uuid: 4566e69f-c907-48ee-8d71-d7ba5aa00d20, username: "Jorian", properties: [ProfileProperty { name: "textures", value: "ewo...KfQ==", signature: "AW7...jv8=" }] }
```

This project is likely not useful practically, but it is more meant as a reference. Some idiomatic Rust code with much expandability and a multi-threaded async server. It can help understand the Minecraft protocol and how to easily implement any other byte-level protocols. 

It can be used as a **honeypot** however, because it looks like a real server and all the responses and interactions can be set up exactly how you want. With the verbose logging you can find exactly what the conneting client is trying to do. 

* [`connection.rs`](src/connection.rs): The logic of receiving packets, and writing responses
* [`protocol.rs`](src/protocol.rs): Specific protocol details. Reading and writing the raw bytes
