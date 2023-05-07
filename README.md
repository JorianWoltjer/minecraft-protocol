# Minecraft Protocol

An implementation of *a few* packets in the Minecraft protocol. Starts a server on port `:25565` that responds to [Server List Ping](https://wiki.vg/Server_List_Ping), and disconnects the player with a message if they try to join.

Includes some logging for the packets going back and forth, for example:

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
< LoginStart { username: "Jorian", uuid: Some(3344777f-af00-4254-a6a9-caa0fb808f0e) }
> LoginDisconnect { reason: Object {"text": String("Goodbye, Jorian!")} }
```

This project is likely not useful practically, but it is more meant as a reference. Some idiomatic Rust code with much expandability and a multi-threaded async server. It can help understand the Minecraft protocol and how to easily implement any other byte-level protocols. 

* [`connection.rs`](src/connection.rs): The logic of receiving packets, and writing responses
* [`protocol.rs`](src/protocol.rs): Specific protocol details. Reading and writing the raw bytes
