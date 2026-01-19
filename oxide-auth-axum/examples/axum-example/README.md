# Axum OAuth2 Example

This example demonstrates a OAuth2 server implementation using the `oxide-auth` library with the `axum` web framework. It showcases a three-server OAuth2 architecture with an authorization server, resource server, and client.

## Architecture

The example implements a complete OAuth2 flow with three separate services:

### Authorization Server (Port 8081)
Handles the OAuth2 authorization and token endpoints. It:
- Manages client registration
- Issues authorization codes
- Generates access and refresh tokens
- Uses in-memory stores for clients, authorization codes, and tokens

### Resource Server (Port 8082)
Protects resources that require valid OAuth2 access tokens. It:
- Validates incoming access tokens
- Provides protected resource endpoints
- Verifies the correct scopes are present

### Client (Port 8080)
A web-based OAuth2 client that:
- Initiates the OAuth2 authorization code flow
- Handles authorization callbacks
- Exchanges authorization codes for tokens
- Accesses protected resources on behalf of the user
- Provides a user interface for testing the flow

## Running the Example

### Starting the Server

From the `oxide-auth-axum` directory, run:

```bash
cargo run --example axum-example
```

This will start all three servers:
- Authorization Server: http://localhost:8081
- Resource Server: http://localhost:8082
- Client: http://localhost:8080

### Testing the OAuth2 Flow

1. Open your browser and navigate to http://localhost:8080
2. Click the "Authorize" link to initiate the authorization flow
3. You'll be redirected to the authorization server
4. Authorize the client application
5. You'll be redirected back to the client with an authorization code
6. The client automatically exchanges the code for tokens
7. Once authenticated, you can access protected resources

## Configuration

Default configuration in `main.rs`:
- **Scope**: "default-scope"
- **Client ID**: "local_client_id"
- **Client Secret**: "local_client_secret"
- **Client Port**: 8080
- **Authorization Server Port**: 8081
- **Resource Server Port**: 8082

You can modify these constants in `main.rs` to customize the example.