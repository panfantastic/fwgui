mod graph;
mod nft;
mod routes;
mod state;

use axum::{Router, routing::{delete, get, post}, response::Response, http::header};
use std::sync::Arc;
use tokio::net::TcpListener;

static INDEX_HTML:     &[u8] = include_bytes!("../static/index.html");
static GRAPH_HTML:     &[u8] = include_bytes!("../static/graph.html");
static EDITOR_BUNDLE:  &[u8] = include_bytes!("../static/editor-bundle.js");
static GRAPH_BUNDLE:   &[u8] = include_bytes!("../static/graph-bundle.js");

fn html_response(body: &'static [u8]) -> Response<axum::body::Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(axum::body::Body::from(body))
        .unwrap()
}

fn js_response(body: &'static [u8]) -> Response<axum::body::Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/javascript; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn serve_index()         -> Response<axum::body::Body> { html_response(INDEX_HTML) }
async fn serve_graph_page()    -> Response<axum::body::Body> { html_response(GRAPH_HTML) }
async fn serve_editor_bundle() -> Response<axum::body::Body> { js_response(EDITOR_BUNDLE) }
async fn serve_graph_bundle()  -> Response<axum::body::Body> { js_response(GRAPH_BUNDLE) }

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = state::Config::from_env();
    let port = config.port;
    nft::cleanup_stale_breakpoints();
    let app_state = Arc::new(state::AppState::new(config));

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/graph", get(serve_graph_page))
        .route("/api/graph/dot", get(routes::graph_dot))
        .route("/static/editor-bundle.js", get(serve_editor_bundle))
        .route("/static/graph-bundle.js", get(serve_graph_bundle))
        .route("/stage", post(routes::stage))
        .route("/promote", post(routes::promote))
        .route("/acknowledge", post(routes::acknowledge))
        .route("/clear", post(routes::clear))
        .route("/validate", post(routes::validate))
        .route("/save-config", post(routes::save_config))
        .route("/api/state", get(routes::api_state))
        .route("/breakpoint", post(routes::breakpoint_set))
        .route("/breakpoint/{line}", delete(routes::breakpoint_clear))
        .route("/breakpoints", get(routes::breakpoints_list))
        .route("/log-stream", get(routes::log_stream))
        .with_state(app_state);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    tracing::info!("listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await.unwrap();
}
