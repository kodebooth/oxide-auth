use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use bon::bon;
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    EndpointNotSet, EndpointSet, RedirectUrl, RefreshToken, RevocationErrorResponseType, Scope,
    StandardErrorResponse, StandardRevocableToken, StandardTokenIntrospectionResponse,
    StandardTokenResponse, TokenResponse, TokenUrl,
    basic::{BasicClient, BasicErrorResponseType, BasicTokenType},
};
use oxide_auth::primitives::registrar;
use reqwest::Url;
use registrar::Client as RegistrarClient;
use tracing::{error, info, instrument};

#[derive(Clone)]
pub struct Client {
    id: String,
    secret: Option<String>,
    port: u16,
    scope: String,
    http_client: oauth2::reqwest::Client,
    protected_resource_endpoint: String,
    inner: oauth2::Client<
        StandardErrorResponse<BasicErrorResponseType>,
        StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
        StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
        StandardRevocableToken,
        StandardErrorResponse<RevocationErrorResponseType>,
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointSet,
    >,
}

#[derive(serde::Deserialize)]
struct RedirectQuery {
    error: Option<String>,
    error_description: Option<String>,
    code: Option<String>,
    state: Option<String>,
}

pub struct ClientStateInner {
    code_grant_state: Mutex<Option<CsrfToken>>,
    access_token: Mutex<Option<AccessToken>>,
    refresh_token: Mutex<Option<RefreshToken>>,
    client: Client,
}

#[derive(Clone)]
pub struct ClientState {
    inner: Arc<ClientStateInner>,
}

impl Deref for ClientState {
    type Target = ClientStateInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[bon]
impl Client {
    #[builder(on(String, into))]
    pub fn new(
        id: String, secret: Option<String>, port: u16, scope: String, authorization_endpoint: String,
        token_endpoint: String, protected_resource_endpoint: String,
    ) -> Self {
        let client_id = ClientId::new(id.clone());
        let client_secret = secret
            .as_ref()
            .and_then(|secret| Some(ClientSecret::new(secret.clone())));
        let client_redirect_uri = RedirectUrl::new(Self::redirect_uri_with_port(port)).unwrap();
        let client_authorization_endpoint = AuthUrl::new(authorization_endpoint.clone()).unwrap();
        let client_token_endpoint = TokenUrl::new(token_endpoint.clone()).unwrap();
        let client = BasicClient::new(client_id)
            .set_redirect_uri(client_redirect_uri)
            .set_auth_uri(client_authorization_endpoint)
            .set_token_uri(client_token_endpoint);
        let client = if let Some(secret) = client_secret {
            client.set_client_secret(secret)
        } else {
            client
        };

        let http_client = oauth2::reqwest::Client::new();

        Self {
            id,
            secret,
            port,
            scope,
            http_client,
            protected_resource_endpoint,
            inner: client,
        }
    }

    pub fn redirect_uri_with_port(port: u16) -> String {
        format!("http://localhost:{}/redirect", port)
    }

    pub fn redirect_uri(&self) -> String {
        Self::redirect_uri_with_port(self.port)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn secret(&self) -> Option<&str> {
        self.secret.as_deref()
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    #[instrument(skip(state))]
    async fn get_index(State(state): State<ClientState>) -> Html<String> {
        let client = state.client.clone();

        let (code_grant_authorization_url, csrf_token) = client
            .inner
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(client.scope.to_string()))
            .url();
        state.code_grant_state.lock().unwrap().replace(csrf_token);

        let client_id = client.id();
        let client_secret = client.secret().unwrap_or("[no secret]");
        let client_redirect_uri = client.redirect_uri();
        let client_scope = client.scope();

        Html(format!(
            "<html>
                <h1>Oxide Auth Example Client</h1>
                <p>This is a simple OAuth2 client example to help demonstrate the usage of oxide-auth.</p>
                <p>
                    The client is registered with the following details:
                    <list>
                        <li>Client ID: <code>{client_id}</code></li>
                        <li>Client Secret: <code>{client_secret}</code></li>
                        <li>Redirect URI: <code>{client_redirect_uri}</code></li>
                        <li>Scope: <code>{client_scope}</code></li>
                    </list>
                </p>
                <h2>Authorization Code Grant</h2>
                <p>This example demonstrates the authorization code grant flow.</p>
                <p>
                    The client will redirect to the authorization server to
                    obtain an authorization code, then exchange that code for an
                    access token, and finally use that access token to access a
                    protected resource on the resource server.
                </p>
                <p>Start an authorization code grant by clicking <a href=\"{code_grant_authorization_url}\">here</a>.</p>
            </html>"
        ))
    }

    #[instrument(skip(state))]
    async fn get_home(State(state): State<ClientState>) -> Html<String> {
        let access_token = {
            let lock = state.access_token.lock().unwrap();
            let access_token = lock.as_ref().unwrap().secret().to_string();
            access_token
        };

        let refresh_token = {
            let lock = state.refresh_token.lock().unwrap();
            match lock.as_ref() {
                Some(token) => token.secret().to_string(),
                None => "[no refresh token]".to_string(),
            }
        };

        let client = state.client.clone();

        let protected_resource_endpoint = client.protected_resource_endpoint.as_str();

        let resource = client
            .http_client
            .get(protected_resource_endpoint)
            .bearer_auth(&access_token)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        Html(format!(
            "<html>
                <h1>Protected Resource Accessed</h1>
                <p>The client has successfully accessed the protected resource using the access token.</p>
                <p>
                    The access token and resource details are as follows:
                    <list>
                        <li>Access Token: <code>{access_token}</code></li>
                        <li>Refresh Token: <code>{refresh_token}</code></li>
                        <li>Protected Resource Endpoint: <code>{protected_resource_endpoint}</code></li>
                        <li>Resource Content: <code>{resource}</code></li>
                    </list>
                </p>
                <form action=\"refresh\" method=\"post\">
                    <button>Refresh token</button>
                </form>
                <p>Return to <a href=\"/\">home</a>.</p>
            </html>"
        ))
    }

    #[instrument(skip(state, query))]
    async fn get_redirect(
        Query(query): Query<RedirectQuery>, State(state): State<ClientState>,
    ) -> Response {
        fn error_response(message: String) -> Response {
            error!(message);
            Html(format!(
                "<html>
                    <h1>Error During Authorization</h1>
                    <p>{}</p>
                    <p>Return to <a href=\"/\">home</a>.</p>
                </html>",
                message
            ))
            .into_response()
        }

        if let Some(error) = query.error {
            let mut message = format!("Authorization error: {}", error);
            if let Some(error_description) = query.error_description {
                message.push_str(&format!("({})", error_description));
            }

            return error_response(format!("Authorization server returned an error: {message}"));
        }

        let Some(code) = query.code else {
            return error_response("Authorization server returned no code".to_string());
        };

        let Some(redirect_state) = query.state else {
            return error_response("Authorization server returned no state".to_string());
        };

        let code_grant_state = {
            let code_grant_state = state.code_grant_state.lock().unwrap();
            let Some(code_grant_state) = code_grant_state.as_ref() else {
                return error_response("Client is missing state information".to_string());
            };

            code_grant_state.secret().clone()
        };

        if redirect_state != code_grant_state {
            return error_response(format!(
                "Client and Authorization server state mismatch: expected {code_grant_state}, got {redirect_state}",
            ));
        }

        let code = AuthorizationCode::new(code);

        info!("Authorization code received: {}", code.secret());

        let token = state
            .client
            .inner
            .exchange_code(code)
            .request_async(&state.client.http_client)
            .await;

        let token = match token {
            Err(err) => return error_response(format!("Token exchange error: {}", err)),
            Ok(ref token) => token,
        };

        info!("Authorization code exchanged for token: {:?}", token);

        state
            .access_token
            .lock()
            .unwrap()
            .replace(token.access_token().clone());
        if let Some(refresh_token) = token.refresh_token() {
            state.refresh_token.lock().unwrap().replace(refresh_token.clone());
        }

        Redirect::to("/home").into_response()
    }

    #[instrument(skip(state))]
    async fn post_refresh(State(state): State<ClientState>) -> impl IntoResponse {
        let refresh_token = state.refresh_token.lock().unwrap().as_ref().cloned().unwrap();

        let token = state
            .client
            .inner
            .exchange_refresh_token(&refresh_token)
            .request_async(&state.client.http_client)
            .await;

        let token = match token {
            Err(err) => return Err((StatusCode::BAD_REQUEST, format!("Token refresh error: {}", err))),
            Ok(ref token) => token,
        };

        info!("Refresh token exchanged for new token: {:?}", token);

        state
            .access_token
            .lock()
            .unwrap()
            .replace(token.access_token().clone());

        let mut refresh_token = state.refresh_token.lock().unwrap();
        *refresh_token = token.refresh_token().cloned();

        Ok(Redirect::to("/home"))
    }

    pub async fn start(&self) {
        let state = ClientState {
            inner: Arc::new(ClientStateInner {
                code_grant_state: Mutex::new(None),
                access_token: Mutex::new(None),
                refresh_token: Mutex::new(None),
                client: self.clone(),
            }),
        };

        let app = axum::Router::new()
            .route("/", get(Self::get_index))
            .route("/redirect", get(Self::get_redirect))
            .route("/home", get(Self::get_home))
            .route("/refresh", post(Self::post_refresh))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(format!("localhost:{}", self.port))
            .await
            .unwrap();

        let url = format!("http://localhost:{}/", self.port);

        if let Err(err) = open::that(&url) {
            error!("Failed to open browser automatically: {err}");
            error!("Open this URL in your browser:\n{url}\n");
        }

        axum::serve(listener, app).await.unwrap();
    }
}

impl Into<RegistrarClient> for Client {
    fn into(self) -> RegistrarClient {
        match self.secret() {
            Some(secret) => RegistrarClient::confidential(
                self.id(),
                self.redirect_uri().parse::<Url>().unwrap().into(),
                self.scope().parse().unwrap(),
                secret.as_bytes(),
            ),

            None => RegistrarClient::public(
                self.id(),
                self.redirect_uri().parse::<Url>().unwrap().into(),
                self.scope().parse().unwrap(),
            ),
        }
    }
}
