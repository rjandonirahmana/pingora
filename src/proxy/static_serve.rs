//! static_serve — Serve file static + SPA fallback untuk Leptos.
//!
//! FIX:
//!   - File static (.css, .js, .wasm, dll) yang tidak ada → 404, TIDAK fallback ke index.html
//!   - Hanya route SPA (tanpa ekstensi) yang fallback ke index.html
//!   - Canonicalize path saat startup
//!   - Support HEAD method
//!   - Proper MIME type untuk WASM
//!
//! FIX (brotli/gzip pre-compressed):
//!   - Cek Accept-Encoding dari client request
//!   - Serve .br atau .gz variant kalau tersedia di disk
//!   - Set Content-Encoding header yang sesuai
//!   - Set Vary: Accept-Encoding agar CDN tidak cache salah variant
//!   - Fallback ke file asli kalau compressed variant tidak ada atau error

use pingora_core::prelude::*;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use tokio::fs;
use tokio::io::AsyncReadExt;

// Ukuran chunk untuk streaming file besar (64 KB).
// Cegah single fs::read() mengalokasi seluruh WASM (5–20MB) per concurrent request.
const STREAM_CHUNK_SIZE: usize = 65_536;

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

        // ── Ekstrak semua data dari session sebagai owned types ───────────────
        // WAJIB dilakukan sebelum operasi async / mutable borrow session berikutnya.
        // Borrow checker Rust tidak izinkan &str dari session.req_header() hidup
        // bersamaan dengan &mut session yang dibutuhkan write_response_header().
        // Solusi: .to_string() / .to_owned() di sini, satu kali, zero runtime cost.
        let method: String = session.req_header().method.as_str().to_owned();
        let accept_encoding_raw: String = session
            .req_header()
            .headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        // Setelah baris ini, tidak ada lagi borrow aktif ke session dari &str di atas.

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
            // Security: symlink traversal — canonical path harus tetap di dalam root.
            // fs::metadata() mengikuti symlink; penyerang bisa buat symlink ke /etc/passwd.
            // canonicalize() resolve semua symlink dan ".." ke path nyata.
            let canonical = match tokio::fs::canonicalize(&requested).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(path = %requested.display(), "canonicalize gagal: {e}");
                    return Ok(false);
                }
            };
            if !canonical.starts_with(&self.root) {
                tracing::warn!(
                    path,
                    canonical = %canonical.display(),
                    "static serve: symlink traversal diblokir"
                );
                return Ok(false);
            }
            if meta.is_file() {
                (canonical, false)
            } else {
                // Directory → coba index.html
                (canonical.join("index.html"), true)
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

        // ── Cek dukungan encoding dari client ─────────────────────────────────
        // SPA fallback / index.html: jangan compress.
        // Alasan: index.html harus no-store, kecil, dan fresh setiap request.
        // Pre-compressed index.html tidak worth overhead kompleksitas.
        let accept_encoding = if !is_fallback {
            accept_encoding_raw.as_str()
        } else {
            ""
        };

        // Patch B: parsing Accept-Encoding yang robust + hormati q=0.
        // Tokenize per koma, ambil token sebelum ';', bandingkan exact (case-insensitive).
        // Menghindari false-match substring (mis. "unbr", "compressbr") dan
        // mendukung "br;q=0" yang berarti client justru men-disable brotli.
        let supports_br = accepts(accept_encoding, "br");
        let supports_gz = accepts(accept_encoding, "gzip");

        // ── Resolve pre-compressed variant ───────────────────────────────────
        // Prioritas: brotli > gzip > raw.
        // Hanya untuk file asli (bukan SPA fallback/index.html).
        //
        // Naming convention Trunk:
        //   /app_bg.wasm      → raw
        //   /app_bg.wasm.br   → brotli pre-compressed
        //   /app_bg.wasm.gz   → gzip pre-compressed
        //
        // CATATAN: path adalah path ke file asli (bukan .br/.gz).
        // MIME type selalu diambil dari file_path asli, bukan serve_path.
        let (serve_path, content_encoding): (PathBuf, Option<&'static str>) = if !is_fallback {
            if supports_br {
                let br_path = PathBuf::from(format!("{}.br", file_path.display()));
                if fs::metadata(&br_path)
                    .await
                    .map(|m| m.is_file())
                    .unwrap_or(false)
                {
                    tracing::debug!(path = %br_path.display(), "serving pre-compressed brotli");
                    (br_path, Some("br"))
                } else if supports_gz {
                    let gz_path = PathBuf::from(format!("{}.gz", file_path.display()));
                    if fs::metadata(&gz_path)
                        .await
                        .map(|m| m.is_file())
                        .unwrap_or(false)
                    {
                        tracing::debug!(path = %gz_path.display(), "serving pre-compressed gzip");
                        (gz_path, Some("gzip"))
                    } else {
                        (file_path.clone(), None)
                    }
                } else {
                    (file_path.clone(), None)
                }
            } else if supports_gz {
                let gz_path = PathBuf::from(format!("{}.gz", file_path.display()));
                if fs::metadata(&gz_path)
                    .await
                    .map(|m| m.is_file())
                    .unwrap_or(false)
                {
                    tracing::debug!(path = %gz_path.display(), "serving pre-compressed gzip");
                    (gz_path, Some("gzip"))
                } else {
                    (file_path.clone(), None)
                }
            } else {
                (file_path.clone(), None)
            }
        } else {
            // SPA fallback / index.html: selalu raw
            (file_path.clone(), None)
        };

        // ── Stream file ke client ─────────────────────────────────────────────
        // Kalau compressed variant error, fallback ke file asli.
        let result = self
            .write_response(session, &method, &file_path, &serve_path, content_encoding, is_fallback)
            .await;

        if let Err(ref e) = result {
            if content_encoding.is_some() && serve_path != file_path {
                tracing::warn!(
                    compressed = %serve_path.display(),
                    original   = %file_path.display(),
                    "compressed variant error, fallback ke file asli: {}", e
                );
                return self
                    .write_response(session, &method, &file_path, &file_path, None, is_fallback)
                    .await;
            }
        }
        result
    }

    /// Build + stream HTTP response ke session.
    /// `file_path`  = path file asli (MIME/ETag/Content-Length dari metadata ini).
    /// `serve_path` = file yang benar-benar dibaca (mungkin .br/.gz variant).
    ///
    /// FIX: ganti fs::read() (load seluruh file ke Vec<u8>) dengan streaming 64KB chunk.
    /// Untuk WASM 15MB × 1000 concurrent request = 15GB → sekarang cukup 64KB per request.
    async fn write_response(
        &self,
        session: &mut Session,
        method: &str,
        file_path: &Path,
        serve_path: &Path,
        content_encoding: Option<&'static str>,
        is_fallback: bool,
    ) -> Result<bool> {
        // ── Metadata file asli — untuk ETag dan content-length ───────────────
        // ETag: Weak ETag dari file asli (size + mtime), representasi-independen
        // (cocok lintas br/gz/raw). Skip untuk SPA fallback (no-store, percuma).
        let file_meta = if !is_fallback {
            fs::metadata(file_path).await.ok()
        } else {
            None
        };

        let etag: Option<String> = file_meta.as_ref().and_then(|m| {
            let size = m.len();
            let mtime = m
                .modified()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_secs();
            Some(format!(r#"W/"{size}-{mtime}""#))
        });

        // Content-Length dari file yang benar-benar di-serve (bisa .br/.gz).
        let serve_len: u64 = if serve_path == file_path {
            file_meta.as_ref().map(|m| m.len()).unwrap_or(0)
        } else {
            fs::metadata(serve_path).await.ok().map(|m| m.len()).unwrap_or(0)
        };

        // ── 304 Not Modified ──────────────────────────────────────────────────
        let if_none_match: Option<String> = session
            .req_header()
            .headers
            .get("if-none-match")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        let etag_matches = match (&etag, &if_none_match) {
            (Some(tag), Some(inm)) => {
                inm.trim() == "*" || inm.split(',').any(|t| t.trim() == tag.as_str())
            }
            _ => false,
        };

        if etag_matches {
            let mut resp = ResponseHeader::build(304, None)?;
            if let Some(ref tag) = etag {
                resp.insert_header("etag", tag.as_str())?;
            }
            resp.insert_header(
                "cache-control",
                "public, max-age=31536000, immutable, stale-while-revalidate=86400",
            )?;
            if let Some(enc) = content_encoding {
                resp.insert_header("content-encoding", enc)?;
                resp.insert_header("vary", "accept-encoding")?;
            }
            session.write_response_header(Box::new(resp), true).await?;
            tracing::debug!(path = %file_path.display(), "304 Not Modified (etag match)");
            return Ok(true);
        }

        // ── MIME type (selalu dari file asli) ─────────────────────────────────
        let mut mime =
            mime_from_path(file_path.to_str().unwrap_or("")).unwrap_or("application/octet-stream");
        if file_path.extension().map(|e| e == "wasm").unwrap_or(false) {
            mime = "application/wasm";
        }

        // ── Build response header ─────────────────────────────────────────────
        let mut resp = ResponseHeader::build(200, None)?;
        resp.insert_header("content-type", mime)?;

        // Content-Length dari metadata — tidak perlu baca file dulu.
        let mut len_buf = itoa::Buffer::new();
        resp.insert_header("content-length", len_buf.format(serve_len))?;

        if let Some(ref tag) = etag {
            resp.insert_header("etag", tag.as_str())?;
        }
        if let Some(enc) = content_encoding {
            resp.insert_header("content-encoding", enc)?;
            resp.insert_header("vary", "accept-encoding")?;
        }
        if is_fallback {
            resp.insert_header("cache-control", "no-cache, no-store, must-revalidate")?;
        } else {
            resp.insert_header(
                "cache-control",
                "public, max-age=31536000, immutable, stale-while-revalidate=86400",
            )?;
        }

        if method == "HEAD" {
            session.write_response_header(Box::new(resp), true).await?;
            tracing::debug!(path = %file_path.display(), bytes = serve_len, "HEAD served");
            return Ok(true);
        }

        // ── Stream body dalam chunk 64KB ──────────────────────────────────────
        // Menghindari load seluruh WASM (5–20MB) ke heap per request.
        // tokio::fs::File hanya buka file descriptor; konten dibaca inkremental.
        let mut file = fs::File::open(serve_path).await.map_err(|e| {
            tracing::debug!(path = %serve_path.display(), "static file tidak bisa dibuka: {e}");
            pingora_core::Error::explain(
                pingora_core::ErrorType::FileOpenError,
                format!("open {}: {e}", serve_path.display()),
            )
        })?;

        session.write_response_header(Box::new(resp), false).await?;

        let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
        let mut total_sent: u64 = 0;
        loop {
            let n = file.read(&mut buf).await.map_err(|e| {
                pingora_core::Error::explain(
                    pingora_core::ErrorType::ReadError,
                    format!("read {}: {e}", serve_path.display()),
                )
            })?;
            if n == 0 {
                break;
            }
            total_sent += n as u64;
            let is_last = total_sent >= serve_len;
            session
                .write_response_body(
                    Some(bytes::Bytes::copy_from_slice(&buf[..n])),
                    is_last,
                )
                .await?;
            if is_last {
                break;
            }
        }

        // Pastikan body ditutup jika file lebih pendek dari metadata (truncated file).
        if total_sent < serve_len {
            session.write_response_body(None, true).await?;
        }

        tracing::debug!(
            path     = %file_path.display(),
            fallback = is_fallback,
            bytes    = total_sent,
            mime     = mime,
            encoding = content_encoding.unwrap_or("none"),
            "static served (streamed)"
        );

        Ok(true)
    }
}

/// Cek apakah client menerima suatu content-coding, menghormati `q=0` (disable).
///
/// Parsing token-aware: pisah per koma, ambil bagian sebelum ';', bandingkan
/// exact & case-insensitive. `gzip` juga match alias `x-gzip`.
/// `br;q=0` / `gzip;q=0` dianggap TIDAK didukung (client men-disable secara eksplisit).
fn accepts(accept_encoding: &str, target: &str) -> bool {
    accept_encoding.split(',').any(|part| {
        let mut it = part.split(';');
        let token = it.next().unwrap_or("").trim();

        // RFC 9110 §12.5.3: "*" berarti semua encoding diterima.
        // Cek q-value dulu sebelum return true.
        if token == "*" {
            for param in it {
                if let Some(q) = param.trim().strip_prefix("q=") {
                    if let Ok(qv) = q.trim().parse::<f32>() {
                        return qv > 0.0;
                    }
                }
            }
            return true;
        }

        let token_matches = token.eq_ignore_ascii_case(target)
            || (target == "gzip" && token.eq_ignore_ascii_case("x-gzip"));
        if !token_matches {
            return false;
        }

        // Periksa parameter q — q=0 berarti encoding ditolak.
        for param in it {
            if let Some(q) = param.trim().strip_prefix("q=") {
                if let Ok(qv) = q.trim().parse::<f32>() {
                    return qv > 0.0;
                }
            }
        }
        true
    })
}
