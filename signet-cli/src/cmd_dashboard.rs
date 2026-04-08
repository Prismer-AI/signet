use anyhow::Result;
use clap::Args;

use crate::dashboard;

#[derive(Args)]
pub struct DashboardArgs {
    /// Port to listen on
    #[arg(long, default_value = "9191")]
    pub port: u16,

    /// Open browser automatically
    #[arg(long)]
    pub open: bool,

    /// Serve static files from disk (dev mode)
    #[arg(long, hide = true)]
    pub dev: bool,
}

pub fn dashboard(args: DashboardArgs) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_server(args))
}

async fn run_server(args: DashboardArgs) -> Result<()> {
    let state = dashboard::AppState {
        signet_dir: signet_core::default_signet_dir(),
        dev: args.dev,
    };
    let app = dashboard::router(state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], args.port));
    eprintln!("Signet Dashboard: http://localhost:{}", args.port);

    if args.open {
        if let Err(e) = open::that(format!("http://localhost:{}", args.port)) {
            eprintln!("Warning: could not open browser: {e}");
        }
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.ok();
    eprintln!("\nShutting down dashboard...");
}
