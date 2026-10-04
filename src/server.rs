use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes, HttpBody},
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http_body::{Frame, SizeHint};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
};

use crate::{App, config::Limits};

/// Bound sockets before spawning tasks. HTTP/1 is the same transport exposed by
/// the original Axum server; HTTPS/HTTP/2 terminate at the reverse proxy.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    let (stop, _) = watch::channel(());
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        // Reap finished tasks even when the accept queue stays continuously busy.
        while tasks.try_join_next().is_some() {}
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    // Back off on accept errors rather than spinning at the FD limit.
                    tokio::select! {
                        _ = &mut shutdown => break,
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                    }
                    continue;
                };
                let Ok(permit) = connections.clone().try_acquire_owned() else {
                    // Excess sockets are closed immediately, with no waiting tasks.
                    drop(stream);
                    continue;
                };
                let app = app.clone();
                let mut stopping = stop.subscribe();
                let timeout = Duration::from_secs(limits.header_timeout_seconds);
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut builder = http1::Builder::new();
                    builder.timer(TokioTimer::new())
                        .header_read_timeout(timeout)
                        .max_buf_size(32 * 1024);
                    let connection = builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(app));
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = stopping.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        },
                    }
                });
            },
        }
    }
    drop(listener);
    let _ = stop.send(());
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub(crate) async fn admit(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let Ok(permit) = app.requests.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (header::RETRY_AFTER, "1"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            "Too many active requests; try again later\n",
        )
            .into_response();
    };
    let oauth_body = request.method() == Method::POST
        && ["/oauth/register", "/oauth/authorize", "/oauth/token"]
            .iter()
            .any(|path| request.uri().path() == app.config.endpoint_path(path));
    let response = if oauth_body {
        match tokio::time::timeout(
            Duration::from_secs(app.config.limits.oauth_body_timeout_seconds),
            next.run(request),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => (
                StatusCode::REQUEST_TIMEOUT,
                [
                    (header::CONNECTION, "close"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                "OAuth request body timed out\n",
            )
                .into_response(),
        }
    } else {
        next.run(request).await
    };
    // Keep the permit through response EOF/drop, including indefinitely open SSE.
    response.map(|body| {
        Body::new(PermitBody {
            body,
            permit: Some(permit),
        })
    })
}

struct PermitBody {
    body: Body,
    permit: Option<OwnedSemaphorePermit>,
}

impl HttpBody for PermitBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let frame = Pin::new(&mut self.body).poll_frame(cx);
        if matches!(frame, Poll::Ready(None | Some(Err(_)))) || self.body.is_end_stream() {
            self.permit.take();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}
