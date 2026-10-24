//! The HTTP side (WebSocket `/ws`, `GET /health`, `/stats`, `/tags`) and the server that ties the hub and the PLC
//! workers together.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use axum::Router;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use indexmap::IndexMap;
use serde_json::{Map, Value as Json, json};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tower_http::cors::{Any, CorsLayer};

use crate::config::{Config, py_repr};
use crate::hub::{FEATURES, Hub, Msg, Outbox, PROTOCOL, Shared};
use crate::plc::Factory;
use crate::rules::Rules;
use crate::worker::{PlcWorker, WorkerOptions};

#[derive(Clone)]
struct AppState {
    shared: Arc<Shared>,
    tx: mpsc::UnboundedSender<Msg>,
    next_id: Arc<AtomicU64>,
    closing: watch::Receiver<bool>,
}

/// The shared state of a server on this config: its rules and a (not yet started) worker per PLC, whose events go
/// to `tx`.
pub(crate) fn build(
    config: Config,
    factory: Factory,
    tx: &mpsc::UnboundedSender<Msg>,
) -> Result<Arc<Shared>, String> {
    let config = Arc::new(config);
    let rules = Arc::new(Rules::new(&config)?);
    let options = WorkerOptions {
        cycle: config.cycle_ms as f64 / 1000.0,
        tier2_period: config.tier2_period_s,
        grace_s: config.grace_s,
        planner: config.planner,
        whole_max_bytes: config.whole_max_bytes,
    };
    let workers: IndexMap<String, Arc<PlcWorker>> = config
        .plcs
        .iter()
        .map(|(name, cfg)| {
            let events = tx.clone();
            let on_event = Arc::new(move |event| {
                let _ = events.send(Msg::Worker(event));
            });
            let worker = PlcWorker::new(
                cfg.clone(),
                Arc::clone(&factory),
                options.clone(),
                Arc::clone(&rules),
                on_event,
            );
            (name.clone(), Arc::new(worker))
        })
        .collect();
    Ok(Arc::new(Shared {
        config,
        rules,
        workers,
        sessions: AtomicUsize::new(0),
        writes: AtomicU64::new(0),
        write_rejects: AtomicU64::new(0),
        momentary_timeouts: AtomicU64::new(0),
    }))
}

/// Serves on `listener` until `shutdown` completes, then closes the WebSockets, releases every pressed button,
/// stops the PLC workers (their queued writes still go out) and flushes the audit log.
pub async fn serve(
    config: Config,
    factory: Factory,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let (tx, rx) = mpsc::unbounded_channel();
    let shared = build(config, factory, &tx)?;
    serve_built(shared, tx, rx, listener, shutdown).await
}

async fn serve_built(
    shared: Arc<Shared>,
    tx: mpsc::UnboundedSender<Msg>,
    rx: mpsc::UnboundedReceiver<Msg>,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let hub = Hub::new(Arc::clone(&shared), tx.clone());
    let hub_task = tokio::spawn(hub.run(rx));

    let (closing_tx, closing) = watch::channel(false);
    let state = AppState {
        shared,
        tx: tx.clone(),
        next_id: Arc::new(AtomicU64::new(1)),
        closing,
    };
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET])
        .allow_headers([header::AUTHORIZATION]);
    let app = Router::new()
        .route("/health", get(health))
        .route("/stats", get(stats))
        .route("/tags", get(tags))
        .route("/ws", get(ws))
        .layer(cors)
        .with_state(state);
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.await;
            let _ = closing_tx.send(true); // the WebSockets close, so the graceful shutdown can finish
        })
        .await
        .map_err(|e| e.to_string());
    let (done_tx, done_rx) = oneshot::channel();
    if tx.send(Msg::Stop(done_tx)).is_ok() {
        let _ = done_rx.await;
    }
    let _ = hub_task.await;
    result
}

/// Binds the config's host and port and serves until Ctrl+C.
pub async fn run(config: Config, factory: Factory) -> Result<(), String> {
    let listener = TcpListener::bind((config.host.as_str(), config.port))
        .await
        .map_err(|e| format!("cannot listen on {}:{}: {e}", config.host, config.port))?;
    log::info!(
        "serving on http://{}",
        listener
            .local_addr()
            .map_or_else(|_| "?".into(), |a| a.to_string())
    );
    serve(config, factory, listener, async {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("stopping");
    })
    .await
}

/// A server running on its own threads, for embedding (bindings, tests).
pub struct ServerHandle {
    addr: SocketAddr,
    shared: Arc<Shared>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}

impl ServerHandle {
    /// Starts a server with its own runtime; returns once it listens. Port 0 picks a free port.
    pub fn start(config: Config, factory: Factory) -> Result<Self, String> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = build(config, factory, &tx)?;
        let server = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("ciplink-server".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                runtime.block_on(async move {
                    let (host, port) = (server.config.host.clone(), server.config.port);
                    let listener = match TcpListener::bind((host.as_str(), port)).await {
                        Ok(l) => l,
                        Err(e) => {
                            let error = format!("cannot listen on {host}:{port}: {e}");
                            let _ = ready_tx.send(Err(error.clone()));
                            return Err(error);
                        }
                    };
                    let _ = ready_tx.send(listener.local_addr().map_err(|e| e.to_string()));
                    serve_built(server, tx, rx, listener, async {
                        let _ = stop_rx.await;
                    })
                    .await
                })
            })
            .map_err(|e| e.to_string())?;
        let addr = ready_rx
            .recv()
            .map_err(|_| "the server thread ended".to_owned())??;
        Ok(ServerHandle {
            addr,
            shared,
            stop: Some(stop_tx),
            thread: Some(thread),
        })
    }

    /// The server's shared state (config, rules, workers, counters).
    #[doc(hidden)]
    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// The address the server listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops the server (releasing pressed buttons, flushing the audit log) and waits for it.
    pub fn stop(mut self) -> Result<(), String> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| "the server thread panicked".to_owned())?,
            None => Ok(()),
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

// ------------------------------------------------------------------------------------------------ HTTP

fn detail(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(json!({"detail": message}))).into_response()
}

async fn health(State(state): State<AppState>) -> axum::Json<Json> {
    let plcs: Map<String, Json> = state
        .shared
        .workers
        .iter()
        .map(|(name, w)| {
            let stats = w.stats();
            (
                name.clone(),
                json!({
                    "state": w.state(),
                    "last_cycle_ms": stats.last_cycle_ms,
                    "last_ok_ts": stats.last_ok_ts,
                    "reconnects": stats.reconnects,
                    "reloads": stats.reloads,
                }),
            )
        })
        .collect();
    axum::Json(json!({"plcs": plcs}))
}

async fn stats(State(state): State<AppState>) -> axum::Json<Json> {
    let shared = &state.shared;
    let plcs: Map<String, Json> = shared
        .workers
        .iter()
        .map(|(name, w)| {
            let stats = w.stats();
            let mut entry = Map::new();
            entry.insert("reads_per_cycle".into(), json!(stats.reads_per_cycle));
            entry.insert("tags_per_cycle".into(), json!(stats.tags_per_cycle));
            entry.insert("last_cycle_ms".into(), json!(stats.last_cycle_ms));
            entry.insert("cycle_ms".into(), json!(shared.config.cycle_ms));
            entry.insert("overruns".into(), json!(stats.overruns));
            entry.insert("subscriptions".into(), json!(w.subscriptions()));
            entry.extend(w.tier_counts());
            entry.insert("group_fallbacks".into(), json!(stats.group_fallbacks));
            entry.insert("groups".into(), Json::Object(w.group_stats()));
            (name.clone(), Json::Object(entry))
        })
        .collect();
    axum::Json(json!({
        "sessions": shared.sessions.load(Ordering::Relaxed),
        "writes": shared.writes.load(Ordering::Relaxed),
        "write_rejects": shared.write_rejects.load(Ordering::Relaxed),
        "momentary_timeouts": shared.momentary_timeouts.load(Ordering::Relaxed),
        "plcs": plcs,
    }))
}

async fn tags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let shared = &state.shared;
    let secret = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if shared
        .authenticate(secret.map(|s| Json::String(s.to_owned())).as_ref())
        .is_none()
    {
        return detail(StatusCode::UNAUTHORIZED, "invalid token");
    }
    let plc = match query.get("plc") {
        Some(plc) => plc.clone(),
        None if shared.workers.len() == 1 => {
            shared.workers.keys().next().cloned().unwrap_or_default()
        }
        None => return detail(StatusCode::NOT_FOUND, "unknown PLC None"),
    };
    let (Some(worker), Some(cfg)) = (shared.workers.get(&plc), shared.config.plcs.get(&plc)) else {
        return detail(
            StatusCode::NOT_FOUND,
            &format!("unknown PLC {}", py_repr(&plc)),
        );
    };
    let structure = worker.structure();
    let rows = |tables: &[Map<String, Json>]| {
        Json::Array(tables.iter().cloned().map(Json::Object).collect())
    };
    axum::Json(json!({
        "plc": plc,
        "state": worker.state(),
        "version": worker.version(),
        "tags": structure.tag_list,
        "types": structure.types,
        "rules": rows(&cfg.rules),
        "groups": rows(&cfg.groups),
        "decorators": shared.config.decorators,
        "udt": cfg.udt,
        "tag_settings": cfg.tags,
    }))
    .into_response()
}

// ------------------------------------------------------------------------------------------------ WebSocket

/// Completes once the server is closing.
async fn closed(mut closing: watch::Receiver<bool>) {
    while !*closing.borrow_and_update() {
        if closing.changed().await.is_err() {
            return;
        }
    }
}

async fn ws(State(state): State<AppState>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| session(socket, state))
}

/// One client: `hello` first (else closed with 4401), then messages to the hub and the outbox to the client.
async fn session(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();
    let hello = loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => break serde_json::from_str::<Json>(&text).ok(),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(Message::Binary(_))) => break None,
            _ => return,
        }
    };
    let token = hello
        .filter(|h| h.get("op").and_then(Json::as_str) == Some("hello"))
        .filter(|h| h.get("v").and_then(Json::as_u64) == Some(PROTOCOL))
        .and_then(|h| state.shared.authenticate(h.get("token")));
    let Some(token) = token else {
        let frame = CloseFrame {
            code: 4401,
            reason: "".into(),
        };
        let _ = sink.send(Message::Close(Some(frame))).await;
        return;
    };
    let id = state.next_id.fetch_add(1, Ordering::Relaxed);
    let outbox = Arc::new(Outbox::default());
    outbox.send(json!({
        "op": "welcome",
        "v": PROTOCOL,
        "plcs": state.shared.states(),
        "write": !token.write.is_empty(),
        "features": FEATURES,
    }));
    if state
        .tx
        .send(Msg::Open(id, token, Arc::clone(&outbox)))
        .is_err()
    {
        return;
    }
    let mut closing = Box::pin(closed(state.closing.clone()));
    let sender = tokio::spawn(async move {
        loop {
            tokio::select! {
                messages = outbox.next() => {
                    for message in messages {
                        if sink.send(Message::Text(message.to_string().into())).await.is_err() {
                            return;
                        }
                    }
                }
                () = &mut closing => {
                    let frame = CloseFrame { code: 1001, reason: "server stopping".into() };
                    let _ = sink.send(Message::Close(Some(frame))).await;
                    return;
                }
            }
        }
    });
    let mut closing = Box::pin(closed(state.closing.clone()));
    loop {
        tokio::select! {
            message = stream.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    let _ = state.tx.send(Msg::Text(id, text.to_string()));
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            () = &mut closing => break,
        }
    }
    let _ = state.tx.send(Msg::Close(id));
    if *state.closing.borrow() {
        let _ = sender.await; // it sends the close frame
    } else {
        sender.abort();
    }
}
