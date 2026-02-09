use crate::cli::commands::ServeArgs;
use crate::errors::SekuraError;
use crate::api;
use tracing::info;

pub async fn handle_serve(args: ServeArgs) -> Result<(), SekuraError> {
    info!(host = %args.host, port = args.port, "Starting API server");

    let state = api::create_app_state(&args.db, args.workers).await?;
    let app = api::build_router(state);

    let addr = format!("{}:{}", args.host, args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Listening on {}", addr);

    axum::serve(listener, app)
        .await
        .map_err(|e| SekuraError::Internal(format!("Server error: {}", e)))?;

    Ok(())
}
