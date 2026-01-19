mod authorization_server;
mod client;
mod resource_server;

use authorization_server::AuthorizationServer;

use tokio::join;

use crate::resource_server::ResourceServer;

#[tokio::main]
async fn main() {
    const SCOPE: &str = "default-scope";
    const CLIENT_PORT: u16 = 8080;
    const CLIENT_ID: &str = "local_client_id";
    const CLIENT_SECRET: &str = "local_client_secret";
    const AUTH_SERVER_PORT: u16 = 8081;
    const RESOURCE_SERVER_PORT: u16 = 8082;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Create the authorization server
    let authorization_server = AuthorizationServer::new(AUTH_SERVER_PORT);
    let authorization_endpoint = authorization_server.authorization_endpoint();
    let token_endpoint = authorization_server.token_endpoint();

    // Create the resource server
    let issuer = authorization_server.issuer();
    let resource_server = ResourceServer::builder()
        .port(RESOURCE_SERVER_PORT)
        .issuer(issuer)
        .scope(SCOPE)
        .build();
    let protected_resource_endpoint = resource_server.protected_resource_endpoint();

    // Create the client
    let client = client::Client::builder()
        .id(CLIENT_ID)
        .secret(CLIENT_SECRET)
        .port(CLIENT_PORT)
        .scope(SCOPE)
        .authorization_endpoint(&authorization_endpoint)
        .token_endpoint(&token_endpoint)
        .protected_resource_endpoint(protected_resource_endpoint)
        .build();

    // Register the client with the authorization server
    authorization_server.register_client(client.clone().into());

    let authorization_server_handle = tokio::spawn(async move {
        authorization_server.start().await;
    });

    let resource_server_handle = tokio::spawn(async move {
        resource_server.start().await;
    });

    let client_handle = tokio::spawn(async move {
        client.start().await;
    });

    let (authorization_server, resource_server, client) =
        join!(authorization_server_handle, resource_server_handle, client_handle);

    authorization_server.unwrap();
    resource_server.unwrap();
    client.unwrap();
}
