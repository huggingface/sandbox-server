//! Filesystem endpoints: raw-body file transfer (no base64), directory
//! listing, stat, delete, mkdir.

use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::http::{stream_body, Request, ResponseWriter};
use crate::sandboxes::SandboxEntry;

/// Resolve the request's `path` parameter to the absolute filesystem path to act
/// on. In dedicated mode (`sandbox = None`) the path is used as-is; in host mode
/// it is rooted at the sandbox home (see `sandboxes::resolve_in_home`).
fn require_path(
    request: &Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> Result<String, std::io::Result<()>> {
    let raw = match request.params.get("path").map(|s| s.as_str()) {
        Some(p) if !p.is_empty() => p,
        _ => return Err(resp.error(400, "missing 'path' query parameter")),
    };
    match sandbox {
        None => Ok(raw.to_string()),
        Some(sbx) => Ok(crate::sandboxes::resolve_in_home(&sbx.home, raw).to_string_lossy().into_owned()),
    }
}

pub fn handle_read(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> std::io::Result<()> {
    let path = match require_path(request, resp, sandbox) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let path = path.as_str();
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return resp.error(404, &format!("no such file: {path}"))
        }
        Err(e) => return resp.error(400, &format!("cannot open {path}: {e}")),
    };
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        return resp.error(409, &format!("is a directory: {path}"));
    }
    // Optional offset/length for parallel ranged downloads.
    let offset: u64 = request.params.get("offset").and_then(|v| v.parse().ok()).unwrap_or(0);
    let length = request
        .params
        .get("length")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(u64::MAX)
        .min(metadata.len().saturating_sub(offset));
    if offset > 0 {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(offset))?;
    }
    resp.start_fixed(200, "application/octet-stream", length)?;
    // Heap, not stack (256 KiB would be needlessly large on the per-connection
    // thread stack), and sized to the request so small reads don't allocate 256 KiB.
    let mut buf = vec![0u8; length.min(256 * 1024) as usize];
    let mut remaining = length;
    while remaining > 0 {
        let max = buf.len().min(remaining as usize);
        let n = file.read(&mut buf[..max])?;
        if n == 0 {
            break;
        }
        resp.raw(&buf[..n])?;
        remaining -= n as u64;
    }
    resp.flush()
}

pub fn handle_write(
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> std::io::Result<()> {
    let path = match require_path(request, resp, sandbox) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mkdir = request.params.get("mkdir").map(|v| v != "false" && v != "0").unwrap_or(true);
    let mode = request.params.get("mode").and_then(|m| u32::from_str_radix(m, 8).ok());

    if mkdir {
        if let Some(parent) = Path::new(&path).parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = fs::create_dir_all(parent) {
                    return resp.error(400, &format!("cannot create parent dirs for {path}: {e}"));
                }
            }
        }
    }
    // Optional offset for parallel chunked uploads: open without truncating and
    // write at the given position (the file is created if missing).
    let mut file = match request.params.get("offset").and_then(|v| v.parse::<u64>().ok()) {
        Some(offset) => match fs::OpenOptions::new().write(true).create(true).open(&path) {
            Ok(mut f) => {
                use std::io::Seek;
                if let Err(e) = f.seek(std::io::SeekFrom::Start(offset)) {
                    return resp.error(400, &format!("cannot seek in {path}: {e}"));
                }
                f
            }
            Err(e) => return resp.error(400, &format!("cannot open {path}: {e}")),
        },
        None => match fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => return resp.error(400, &format!("cannot create {path}: {e}")),
        },
    };
    let size = stream_body(request, reader, |chunk| file.write_all(chunk))?;
    if let Some(mode) = mode {
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(mode));
    }
    if let Some(sbx) = sandbox {
        crate::sandboxes::chown_into_home(&sbx.home, Path::new(&path), sbx.uid);
    }
    resp.json(200, &serde_json::json!({"path": path, "size": size}))
}

fn entry_json(path: &Path, metadata: &fs::Metadata) -> serde_json::Value {
    let file_type = if metadata.is_dir() {
        "dir"
    } else if metadata.file_type().is_symlink() {
        "symlink"
    } else {
        "file"
    };
    let mtime_ms = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64);
    serde_json::json!({
        "name": path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        "path": path.to_string_lossy(),
        "type": file_type,
        "size": metadata.len(),
        "mtime_ms": mtime_ms,
        "mode": format!("{:o}", metadata.permissions().mode() & 0o7777),
    })
}

pub fn handle_list(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> std::io::Result<()> {
    let path = match require_path(request, resp, sandbox) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let path = path.as_str();
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return resp.error(404, &format!("no such directory: {path}"))
        }
        Err(e) => return resp.error(400, &format!("cannot list {path}: {e}")),
    };
    let mut items = Vec::new();
    for entry in entries.flatten() {
        if let Ok(metadata) = entry.metadata() {
            items.push(entry_json(&entry.path(), &metadata));
        }
    }
    items.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    resp.json(200, &serde_json::json!({"entries": items}))
}

pub fn handle_stat(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> std::io::Result<()> {
    let path = match require_path(request, resp, sandbox) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let path = path.as_str();
    match fs::symlink_metadata(path) {
        Ok(metadata) => resp.json(200, &entry_json(Path::new(path), &metadata)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => resp.error(404, &format!("no such path: {path}")),
        Err(e) => resp.error(400, &format!("cannot stat {path}: {e}")),
    }
}

pub fn handle_delete(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> std::io::Result<()> {
    let path = match require_path(request, resp, sandbox) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let path = path.as_str();
    let recursive = request.params.get("recursive").map(|v| v == "true" || v == "1").unwrap_or(false);
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return resp.error(404, &format!("no such path: {path}"))
        }
        Err(e) => return resp.error(400, &format!("cannot stat {path}: {e}")),
    };
    let result = if metadata.is_dir() {
        if recursive {
            fs::remove_dir_all(path)
        } else {
            fs::remove_dir(path)
        }
    } else {
        fs::remove_file(path)
    };
    match result {
        Ok(()) => resp.json(200, &serde_json::json!({"deleted": path})),
        Err(e) => resp.error(400, &format!("cannot delete {path}: {e}")),
    }
}

pub fn handle_mkdir(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> std::io::Result<()> {
    let path = match require_path(request, resp, sandbox) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let path = path.as_str();
    match fs::create_dir_all(path) {
        Ok(()) => {
            if let Some(sbx) = sandbox {
                crate::sandboxes::chown_into_home(&sbx.home, Path::new(path), sbx.uid);
            }
            resp.json(200, &serde_json::json!({"created": path}))
        }
        Err(e) => resp.error(400, &format!("cannot mkdir {path}: {e}")),
    }
}
