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

        // ── Baca file ──────────────────────────────────────────────────────────
        let body = match fs::read(&serve_path).await {
            Ok(b) => b,
            Err(e) => {
                // Kalau compressed variant error (race condition / fs issue),
                // fallback ke file asli — lebih baik slow daripada 404.
                if content_encoding.is_some() && serve_path != file_path {
                    tracing::warn!(
                        compressed = %serve_path.display(),
                        original   = %file_path.display(),
                        "compressed variant error, fallback ke file asli: {}", e
                    );
                    match fs::read(&file_path).await {
                        Ok(b) => {
                            // serve tanpa encoding (fallback ke raw karena compressed error)
                            return self
                                .write_response(session, &method, &file_path, b, None, is_fallback)
                                .await;
                        }
                        Err(e2) => {
                            tracing::debug!(
                                path = %file_path.display(),
                                "static file tidak ditemukan: {}", e2
                            );
                            return Ok(false);
                        }
                    }
                } else {
                    tracing::debug!(
                        requested = %requested.display(),
                        fallback  = %file_path.display(),
                        "static file tidak ditemukan: {}", e
                    );
                    return Ok(false);
                }
            }
        };

        self.write_response(
            session,
            &method,
            &file_path,
            body,
            content_encoding,
            is_fallback,
        )
        .await
    }

    /// Helper: build + write HTTP response ke session.
    /// file_path = path asli (untuk MIME detection), serve_path bisa .br/.gz.
    async fn write_response(
        &self,
        session: &mut Session,
        method: &str,
        file_path: &Path,
        body: Vec<u8>,
        content_encoding: Option<&'static str>,
        is_fallback: bool,
    ) -> Result<bool> {
        // ── ETag dari metadata file ASLI (size + mtime) ───────────────────────
        // Weak ETag: W/"size-mtime". Murah (tidak hash konten), dan karena
        // berbasis file asli ia representation-independent — cocok dipakai
        // lintas variant br/gz/raw (konten ter-decode identik).
        // Tidak di-generate untuk SPA fallback (index.html no-store, percuma).
        let etag: Option<String> = if is_fallback {
            None
        } else {
            fs::metadata(file_path).await.ok().and_then(|m| {
                let size = m.len();
                let mtime = m
                    .modified()
                    .ok()?
                    .duration_since(UNIX_EPOCH)
                    .ok()?
                    .as_secs();
                Some(format!(r#"W/"{size}-{mtime}""#))
            })
        };

        // ── 304 Not Modified ──────────────────────────────────────────────────
        // Berlaku untuk GET dan HEAD (keduanya conditional request yang valid).
        // Ekstrak If-None-Match jadi owned dulu supaya borrow immutable session
        // selesai sebelum write_response_header() butuh &mut.
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

        // MIME selalu dari file asli — bukan dari .br atau .gz
        let mut mime =
            mime_from_path(file_path.to_str().unwrap_or("")).unwrap_or("application/octet-stream");

        // WASM MUST have correct MIME type or browser refuses to instantiate.
        // Double-check meski mime_from_path sudah benar — safety net.
        if file_path.extension().map(|e| e == "wasm").unwrap_or(false) {
            mime = "application/wasm";
        }

        // Simpan len SEBELUM body di-move ke Bytes (dipakai content-length + tracing).
        let body_len = body.len();

        let mut resp = ResponseHeader::build(200, None)?;
        resp.insert_header("content-type", mime)?;
        // Zero-alloc content-length via itoa (konsisten dgn pemakaian itoa di reject()).
        let mut len_buf = itoa::Buffer::new();
        resp.insert_header("content-length", len_buf.format(body_len))?;

        if let Some(ref tag) = etag {
            resp.insert_header("etag", tag.as_str())?;
        }

        // Content-Encoding + Vary: hanya saat serve pre-compressed variant.
        //
        // Vary: Accept-Encoding WAJIB ada kalau content-encoding di-set.
        // Tanpa ini: CDN/browser bisa cache brotli response dan serve ke client
        // yang tidak support brotli → corrupted/garbled content.
        if let Some(enc) = content_encoding {
            resp.insert_header("content-encoding", enc)?;
            resp.insert_header("vary", "accept-encoding")?;
        }

        if is_fallback {
            resp.insert_header("cache-control", "no-cache, no-store, must-revalidate")?;
        } else {
            // Trunk embed content hash di nama file → immutable safe.
            // stale-while-revalidate beri grace window untuk intermediary cache.
            resp.insert_header(
                "cache-control",
                "public, max-age=31536000, immutable, stale-while-revalidate=86400",
            )?;
        }

        if method == "HEAD" {
            session.write_response_header(Box::new(resp), true).await?;
        } else {
            session.write_response_header(Box::new(resp), false).await?;
            // FIX: zero-copy. Bytes::from(Vec) reuse backing allocation Vec
            // tanpa memcpy — tidak ada lagi body.clone() yang menggandakan
            // 5–15 MB WASM di heap per request.
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await?;
        }

        tracing::debug!(
            path     = %file_path.display(),
            fallback = is_fallback,
            bytes    = body_len,
            mime     = mime,
            encoding = content_encoding.unwrap_or("none"),
            "static served"
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
