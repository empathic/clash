use std::fs::OpenOptions;

use tracing::Level;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;

use crate::settings::ClashSettings;

pub fn init_tracing() {
    // Log path: CLASH_LOG env var > ~/.clash/clash.log > stderr fallback.
    let log_path = std::env::var("CLASH_LOG").ok().unwrap_or_else(|| {
        ClashSettings::settings_dir()
            .map(|d| d.join("clash.log"))
            .unwrap_or_else(|_| std::path::PathBuf::from("clash.log"))
            .to_string_lossy()
            .into_owned()
    });

    // Ensure parent directory exists.
    let log_file = std::path::Path::new(&log_path)
        .parent()
        .and_then(|parent| std::fs::create_dir_all(parent).ok())
        .and_then(|_| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .ok()
        });

    let layer: Box<dyn Layer<_> + Send + Sync> = match log_file {
        Some(file) => tracing_subscriber::fmt::layer()
            .with_writer(file)
            .pretty()
            .with_ansi(false)
            .with_filter(LevelFilter::from_level(Level::DEBUG))
            .boxed(),
        None => {
            // Fallback to stderr if log file can't be opened.
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .pretty()
                .with_ansi(false)
                .with_filter(LevelFilter::from_level(Level::INFO))
                .boxed()
        }
    };

    tracing_subscriber::registry().with(layer).init()
}
