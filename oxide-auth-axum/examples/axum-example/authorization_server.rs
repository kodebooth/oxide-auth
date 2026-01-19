use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use oxide_auth::{
    endpoint::{
        Authorizer, Issuer, OAuthError, OwnerConsent, OwnerSolicitor, QueryParameter, Registrar,
        Solicitation,
    },
    frontends::simple::endpoint::{FnSolicitor, Generic, Vacant},
    primitives::{
        issuer::TokenMap,
        prelude::{AuthMap, Client, ClientMap, RandomGenerator},
    },
};
use oxide_auth_axum::{OAuthRequest, OAuthResponse, WebError};

#[derive(Clone)]
struct ServerState {
    registrar: Arc<Mutex<ClientMap>>,
    authorizer: Arc<Mutex<AuthMap<RandomGenerator>>>,
    issuer: Arc<Mutex<TokenMap<RandomGenerator>>>,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            registrar: Arc::new(Mutex::new(ClientMap::new())),
            authorizer: Arc::new(Mutex::new(AuthMap::new(RandomGenerator::new(16)))),
            issuer: Arc::new(Mutex::new(TokenMap::new(RandomGenerator::new(16)))),
        }
    }
}

impl ServerState {
    pub fn endpoint(&self) -> Generic<impl Registrar + '_, impl Authorizer + '_, impl Issuer + '_> {
        Generic {
            registrar: self.registrar.lock().unwrap(),
            authorizer: self.authorizer.lock().unwrap(),
            issuer: self.issuer.lock().unwrap(),
            solicitor: Vacant,
            scopes: Vacant,
            response: Vacant,
        }
    }
}

pub struct AuthorizationServer {
    port: u16,
    state: ServerState,
}

impl AuthorizationServer {
    fn consent_solicitor(
        _: &mut OAuthRequest, solicitation: Solicitation,
    ) -> OwnerConsent<OAuthResponse> {
        let grant = solicitation.pre_grant();
        let state = solicitation.state();

        let route = "/consent";
        let client_id = grant.client_id.as_str();
        let redirect_uri = grant.redirect_uri.as_str();
        let scope = grant.scope.to_string();
        let query = {
            let mut extra = vec![
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
            ];

            if let Some(state) = state {
                extra.push(("state", state));
            }

            serde_urlencoded::to_string(extra).unwrap()
        };
        let state = state.unwrap_or("[no state]");

        let body = format!(
            "<html>
            <h1>Resource Owner Consent</h1>
            <p>A client is requesting your permission to access a protected resource:
                <list>
                    <li>Client ID: <code>{client_id}</code></li>
                    <li>Redirect URI: <code>{redirect_uri}</code></li>
                    <li>Requested Scope: <code>{scope}</code></li>
                    <li>State: <code>{state}</code></li>
                </list>
            </p>
            <form method=\"post\">
                <input type=\"submit\" value=\"Accept\" formaction=\"{route}?{query}&allow=true\">
                <input type=\"submit\" value=\"Deny\" formaction=\"{route}?{query}&deny=true\">
            </form>
        </html>",
        );

        OwnerConsent::InProgress(
            OAuthResponse::default()
                .content_type("text/html")
                .unwrap()
                .body(&body),
        )
    }

    // Handler for the authorization code flow. This handler initiates the
    // authorization code flow by requesting owner consent.
    async fn authorize_code<N>(
        state: ServerState, request: OAuthRequest, solicitor: N,
    ) -> Result<impl IntoResponse, WebError>
    where
        N: OwnerSolicitor<OAuthRequest>,
    {
        return state
            .endpoint()
            .with_solicitor(solicitor)
            .authorization_flow()
            .execute(request)
            .map_err(|e| e.into());
    }

    // Handler for the authorization endpoint. This handler processes authorization
    // requests from clients, initiating the authorization code flow.
    async fn get_authorize(
        State(state): State<ServerState>, request: OAuthRequest,
    ) -> Result<impl IntoResponse, WebError> {
        let solicitor = FnSolicitor(AuthorizationServer::consent_solicitor);
        if let Some(params) = request.body() {
            if let Some(response_type) = params.unique_value("response_type") {
                if response_type == "code" {
                    return AuthorizationServer::authorize_code(state, request, solicitor).await;
                }
            }
        }

        Err(WebError::Endpoint(OAuthError::BadRequest))
    }

    // Handler for the token endpoint. This handler processes token requests
    // from clients, including authorization code exchanges and refresh token requests.
    async fn post_token(
        State(state): State<ServerState>, request: OAuthRequest,
    ) -> Result<impl IntoResponse, WebError> {
        if let Some(params) = request.body() {
            if let Some(grant_type) = params.unique_value("grant_type") {
                if grant_type == "authorization_code" {
                    return state
                        .endpoint()
                        .access_token_flow()
                        .execute(request)
                        .map_err(|e| e.into());
                } else if grant_type == "refresh_token" {
                    return state
                        .endpoint()
                        .refresh_flow()
                        .execute(request)
                        .map_err(|e| e.into());
                }
            }
        }

        Err(WebError::Endpoint(OAuthError::BadRequest))
    }

    // Handler for the consent indication endpoint. This handler is called when
    // the resource owner indicates their consent.
    async fn post_consent(
        State(state): State<ServerState>, request: OAuthRequest,
    ) -> Result<impl IntoResponse, WebError> {
        state
            .endpoint()
            .with_solicitor(FnSolicitor(|request: &mut OAuthRequest, _: Solicitation| {
                if request.query().is_some_and(|q| q.unique_value("allow").is_some()) {
                    OwnerConsent::Authorized("user".into())
                } else {
                    OwnerConsent::Denied
                }
            }))
            .authorization_flow()
            .execute(request)
            .map_err(|e| e.into())
    }

    pub async fn start(&self) {
        let app = axum::Router::new()
            .route("/authorize", get(Self::get_authorize))
            .route("/token", post(Self::post_token))
            .route("/consent", post(Self::post_consent))
            .with_state(self.state.clone());

        let listener = tokio::net::TcpListener::bind(format!("localhost:{}", self.port))
            .await
            .unwrap();

        axum::serve(listener, app).await.unwrap();
    }

    pub fn new(port: u16) -> Self {
        AuthorizationServer {
            port,
            state: ServerState::default(),
        }
    }

    pub fn register_client(&self, client: Client) {
        self.state.registrar.lock().unwrap().register_client(client);
    }

    pub fn issuer(&self) -> Arc<Mutex<TokenMap<RandomGenerator>>> {
        Arc::clone(&self.state.issuer)
    }

    pub fn authorization_endpoint(&self) -> String {
        format!("http://localhost:{}/authorize", self.port)
    }

    pub fn token_endpoint(&self) -> String {
        format!("http://localhost:{}/token", self.port)
    }
}
