//! Tracing initialization and configuration.
//!
//! Sets up the `tracing-subscriber` pipeline with configurable output formats
//! (human-readable, JSON structured), log levels, and filtering.

use serde::{Deserialize, Serialize};
use tracing_subscriber::{fmt, EnvFilter};

/// Output format for tracing events.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Human-readable, colored terminal output.
    #[default]
    Pretty,
    /// Compact single-line output.
    Compact,
    /// Machine-readable JSON output.
    Json,
}

/// Configuration for the tracing subsystem.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Default log level filter (e.g., "info", "rusk=debug,reqwest=warn").
    pub filter: String,
    /// Output format.
    pub format: OutputFormat,
    /// Whether to include span events (enter/exit).
    pub with_span_events: bool,
    /// Whether to include source code locations.
    pub with_file: bool,
    /// Whether to include thread names.
    pub with_thread_names: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            filter: "info".to_string(),
            format: OutputFormat::Pretty,
            with_span_events: false,
            with_file: false,
            with_thread_names: false,
        }
    }
}

/// Initialize the global tracing subscriber with the given configuration.
///
/// This should be called once at program startup. Subsequent calls will be ignored
/// by the tracing infrastructure.
pub fn init_tracing(config: &TracingConfig) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.filter));

    match config.format {
        OutputFormat::Pretty => {
            let subscriber = fmt::Subscriber::builder()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_file(config.with_file)
                .with_thread_names(config.with_thread_names)
                .pretty()
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        OutputFormat::Compact => {
            let subscriber = fmt::Subscriber::builder()
                .with_env_filter(env_filter)
                .with_target(true)
                .compact()
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        OutputFormat::Json => {
            let subscriber = fmt::Subscriber::builder()
                .with_env_filter(env_filter)
                .json()
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
    }
}
