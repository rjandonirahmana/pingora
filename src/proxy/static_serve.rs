//! static_serve — Serve file static + SPA fallback untuk Leptos.
//!
//! Ditempel di request_filter sebelum forward ke upstream.
//! Tidak perlu Nginx atau static-web-server di depan.

use pingora_core::prelude::*;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use std::path::PathBuf;
use tokio::fs;

use crate::proxy::transform::mime_from_path;

pub struct StaticServe {
    root: PathBuf,
}

impl StaticServe {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Serve file atau SPA fallback. Return Ok(true) kalau berhasil.
    pub async fn serve(&self, session: &mut Session, path: &str) -> Result<bool> {
        // Security: tolak path traversal
        if path.contains("..") {
            return Ok(false);
        }

        let clean = path.trim_start_matches('/');
        let requested = self.root.join(clean);

        // Tentukan file yang akan di-serve
        let (file_path, is_fallback) = if clean.is_empty() {
            (self.root.join("index.html"), true)
        } else if requested.is_file() {
            (requested, false)
        } else {
            // SPA fallback: semua route tidak dikenal → index.html
            (self.root.join("index.html"), true)
        };

        let body = match fs::read(&file_path).await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(
                    path = %file_path.display(),
                    "static file tidak ditemukan: {}", e
                );
                return Ok(false);
            }
        };

        let mime =
            mime_from_path(file_path.to_str().unwrap_or("")).unwrap_or("application/octet-stream");

        let mut resp = ResponseHeader::build(200, None)?;
        resp.insert_header("content-type", mime)?;
        resp.insert_header("content-length", body.len().to_string())?;

        if is_fallback {
            // index.html fallback: jangan cache agar deploy baru langsung terlihat
            resp.insert_header("cache-control", "no-cache, no-store, must-revalidate")?;
        } else {
            // Asset static (wasm, js, css, gambar): cache selamanya
            resp.insert_header("cache-control", "public, max-age=31536000, immutable")?;
        }

        // FIX: Pastikan WASM selalu application/wasm meski mime_from_path gagal
        if file_path.extension().map(|e| e == "wasm").unwrap_or(false) {
            resp.insert_header("content-type", "application/wasm")?;
        }

        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(bytes::Bytes::from(body)), true)
            .await?;
        Ok(true)
    }
}
