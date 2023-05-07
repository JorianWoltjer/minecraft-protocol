use tokio::net::TcpListener;

use minecraft_protocol::connection::Connection;

const ADDRESS: &str = "0.0.0.0:25565";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = TcpListener::bind(ADDRESS).await.unwrap();

    println!("Listening on {ADDRESS}...");

    while let Ok((stream, address)) = listener.accept().await {
        println!("New connection from {address}");
        tokio::spawn(async move {
            let mut connection = Connection::new(stream).await;
            connection.handle().await.unwrap();
        });
    }
}
