use std::sync::{Arc, Mutex};

use axum::{extract::State, http::StatusCode, routing::get};
use bon::Builder;
use oxide_auth::{
    endpoint::Issuer,
    frontends::simple::endpoint::{Generic, Vacant},
    primitives::{issuer::TokenMap, prelude::RandomGenerator},
};
use oxide_auth_axum::OAuthRequest;

#[derive(Builder)]
#[builder(on(String, into))]
pub struct ResourceServer {
    port: u16,
    issuer: Arc<Mutex<TokenMap<RandomGenerator>>>,
    scope: String,
}

#[derive(Clone)]
struct ServerState {
    issuer: Arc<Mutex<TokenMap<RandomGenerator>>>,
    scope: String,
}

impl ServerState {
    pub fn endpoint(&self) -> Generic<Vacant, Vacant, impl Issuer + '_> {
        Generic {
            registrar: Vacant,
            authorizer: Vacant,
            issuer: self.issuer.lock().unwrap(),
            solicitor: Vacant,
            scopes: Vacant,
            response: Vacant,
        }
    }
}

impl ResourceServer {
    async fn resource(
        State(state): State<ServerState>, request: OAuthRequest,
    ) -> Result<&'static str, StatusCode> {
        let grant = state
            .endpoint()
            .with_scopes(vec![state.scope.parse().unwrap()])
            .resource_flow()
            .execute(request);

        let Ok(_) = grant else {
            return Err(StatusCode::UNAUTHORIZED);
        };

        Ok("Super secret resource data")
    }

    pub fn protected_resource_endpoint(&self) -> String {
        format!("http://localhost:{}/resource", self.port)
    }

    pub async fn start(&self) {
        let state = ServerState {
            issuer: Arc::clone(&self.issuer),
            scope: self.scope.clone(),
        };
        let app = axum::Router::new()
            .route("/resource", get(Self::resource))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(format!("localhost:{}", self.port))
            .await
            .unwrap();

        axum::serve(listener, app).await.unwrap();
    }
}
