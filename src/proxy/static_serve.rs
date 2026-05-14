//! static_serve — Serve file static + SPA fallback untuk Leptos.
//!
//! FIX:
//!   - File static (.css, .js, .wasm, dll) yang tidak ada → 404, TIDAK fallback ke index.html
//!   - Hanya route SPA (tanpa ekstensi) yang fallback ke index.html
//!   - Canonicalize path saat startup
//!   - Support HEAD method
//!   - Proper MIME type untuk WASM

use pingora_core::prelude::*;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::proxy::transform::mime_from_path;

pub struct StaticServe {
    root: PathBuf,
    root_exists: bool,
}

impl StaticServe {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let root = if root.is_relative() {
            std::env::current_dir()
                .map(|cwd| cwd.join(&root))
                .unwrap_or(root)
        } else {
            root
        };

        let root = root.canonicalize().unwrap_or_else(|e| {
            tracing::warn!(path = %root.display(), "static root canonicalize gagal: {}", e);
            root
        });

        let root_exists = root.exists();
        if !root_exists {
            tracing::error!(
                path = %root.display(),
                "STATIC ROOT TIDAK DITEMUKAN — static serve akan skip, request di-proxy ke upstream"
            );
        } else {
            tracing::info!(path = %root.display(), "static serve ready");
        }

        Self { root, root_exists }
    }

    /// Serve file atau SPA fallback.
    /// Return Ok(true) = request selesai di-handle.
    /// Return Ok(false) = file tidak ada, biar caller handle 404 atau proxy.
    pub async fn serve(&self, session: &mut Session, path: &str) -> Result<bool> {
        if !self.root_exists {
            return Ok(false);
        }

        let method = session.req_header().method.as_str();
        if method != "GET" && method != "HEAD" {
            return Ok(false);
        }

        // Security: path traversal
        if path.contains("..") {
            tracing::warn!(path, "static serve: path traversal blocked");
            return Ok(false);
        }

        let clean = path.trim_start_matches('/');
        let requested = self.root.join(clean);

        // ── Tentukan apakah ini request file static atau route SPA ─────────────
        let is_file_request = Path::new(clean).extension().is_some();

        // ── Resolve file ─────────────────────────────────────────────────────────
        let (file_path, is_fallback) = if clean.is_empty() {
            // Root path → SPA fallback
            (self.root.join("index.html"), true)
        } else if let Ok(meta) = fs::metadata(&requested).await {
            if meta.is_file() {
                (requested.clone(), false)
            } else {
                // Directory → coba index.html
                (requested.join("index.html"), true)
            }
        } else {
            // File tidak ada di disk
            if is_file_request {
                // CRITICAL FIX: File static (.css, .js, .wasm, .png, dll) tidak ada → 404
                // JANGAN fallback ke index.html. Browser mobile reject HTML sebagai CSS/JS.
                tracing::debug!(
                    path = %requested.display(),
                    "static file tidak ditemukan (file request)"
                );
                return Ok(false);
            } else {
                // Route SPA (/explore, /pulse, /events) → fallback ke index.html
                (self.root.join("index.html"), true)
            }
        };

        // ── Baca file ──────────────────────────────────────────────────────────
        let body = match fs::read(&file_path).await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(
                    requested = %requested.display(),
                    fallback = %file_path.display(),
                    "static file tidak ditemukan: {}", e
                );
                return Ok(false);
            }
        };

        // ── Build response ─────────────────────────────────────────────────────
        let mut mime =
            mime_from_path(file_path.to_str().unwrap_or("")).unwrap_or("application/octet-stream");

        // WASM MUST have correct MIME type or browser refuses to instantiate
        if file_path.extension().map(|e| e == "wasm").unwrap_or(false) {
            mime = "application/wasm";
        }

        let mut resp = ResponseHeader::build(200, None)?;
        resp.insert_header("content-type", mime)?;
        resp.insert_header("content-length", body.len().to_string())?;

        if is_fallback {
            resp.insert_header("cache-control", "no-cache, no-store, must-revalidate")?;
        } else {
            resp.insert_header("cache-control", "public, max-age=31536000, immutable")?;
        }

        if method == "HEAD" {
            session.write_response_header(Box::new(resp), true).await?;
        } else {
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(bytes::Bytes::from(body.clone())), true)
                .await?;
        }

        tracing::debug!(
            path = %file_path.display(),
            fallback = is_fallback,
            bytes = body.len(),
            mime = mime,
            "static served"
        );

        Ok(true)
    }
}
