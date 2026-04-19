mod nft;
mod routes;
mod state;

use axum::{Router, routing::{delete, get, post}, response::Response, http::header};
use std::sync::Arc;
use tokio::net::TcpListener;

static CM_BUNDLE: &[u8] = include_bytes!("../static/cm-bundle.js");

async fn serve_cm_bundle() -> Response<axum::body::Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/javascript; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(CM_BUNDLE))
        .unwrap()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = state::Config::from_env();
    let port = config.port;
    nft::cleanup_stale_breakpoints();
    let app_state = Arc::new(state::AppState::new(config));

    let app = Router::new()
        .route("/", get(routes::index))
        .route("/static/cm-bundle.js", get(serve_cm_bundle))
        .route("/stage", post(routes::stage))
        .route("/promote", post(routes::promote))
        .route("/acknowledge", post(routes::acknowledge))
        .route("/clear", post(routes::clear))
        .route("/validate", post(routes::validate))
        .route("/save-config", post(routes::save_config))
        .route("/breakpoint", post(routes::breakpoint_set))
        .route("/breakpoint/{line}", delete(routes::breakpoint_clear))
        .route("/breakpoints", get(routes::breakpoints_list))
        .route("/log-stream", get(routes::log_stream))
        .with_state(app_state);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    tracing::info!("listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await.unwrap();
}
