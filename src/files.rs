//! Filesystem endpoints: raw-body file transfer (no base64), directory
//! listing, stat, delete, mkdir.
//!
//! Two resolution modes, because the two server modes have different tenants:
//!
//! - **Dedicated**: the job *is* the sandbox, so a path is an ordinary container
//!   path and there is no second tenant to confine it from.
//! - **Host**: the path is resolved beneath the sandbox's home directory
//!   descriptor, one component at a time, never following a symlink — see
//!   [`crate::fsutil`]. These handlers run as root, so following a symlink the
//!   sandbox planted in its own home would let it borrow the server's privileges.

use std::fs::{self, File, Metadata};
use std::io::{self, BufReader, Read, Seek, Write};
use std::net::TcpStream;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::fsutil::{self, ScopedRoot};
use crate::http::{stream_body, Request, ResponseWriter};
use crate::sandboxes::SandboxEntry;

/// A request's `path` parameter, resolved to something we can act on.
enum Target {
    /// Dedicated mode: an ordinary container path, used as-is.
    Direct(PathBuf),
    /// Host mode: `rel` resolved beneath the sandbox home, by descriptor.
    Scoped(ScopedRoot, PathBuf),
}

impl Target {
    /// Absolute path, for error messages and API responses only.
    fn display(&self) -> PathBuf {
        match self {
            Target::Direct(path) => path.clone(),
            Target::Scoped(root, rel) => root.display(rel),
        }
    }

    fn open_read(&self) -> io::Result<File> {
        match self {
            Target::Direct(path) => {
                // O_NONBLOCK so a FIFO cannot block this connection's thread
                // waiting for a writer, and a regular-file check so a device
                // node cannot be streamed as if it were a file.
                let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path)?;
                let metadata = file.metadata()?;
                if metadata.is_dir() {
                    return Err(io::Error::from_raw_os_error(libc::EISDIR));
                }
                if !metadata.is_file() {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
                }
                Ok(file)
            }
            Target::Scoped(root, rel) => root.open_read(rel),
        }
    }

    fn open_write(&self, create_parents: bool, offset: Option<u64>) -> io::Result<File> {
        match self {
            Target::Direct(path) => {
                if create_parents {
                    if let Some(parent) = path.parent() {
                        if !parent.as_os_str().is_empty() {
                            fs::create_dir_all(parent)?;
                        }
                    }
                }
                // Truncate on a plain overwrite; a ranged write must leave the
                // rest of the file alone.
                fs::OpenOptions::new().write(true).create(true).truncate(offset.is_none()).open(path)
            }
            Target::Scoped(root, rel) => root.open_write(rel, create_parents, offset),
        }
    }

    /// `lstat`: a final symlink is reported, not followed.
    fn metadata(&self) -> io::Result<Metadata> {
        match self {
            Target::Direct(path) => fs::symlink_metadata(path),
            Target::Scoped(root, rel) => root.metadata(rel),
        }
    }

    fn list(&self) -> io::Result<Vec<(PathBuf, Metadata)>> {
        match self {
            Target::Direct(path) => {
                let mut entries = Vec::new();
                for entry in fs::read_dir(path)? {
                    let entry = entry?;
                    if let Ok(metadata) = entry.metadata() {
                        entries.push((entry.path(), metadata));
                    }
                }
                Ok(entries)
            }
            Target::Scoped(root, rel) => root.list(rel),
        }
    }

    fn delete(&self, recursive: bool) -> io::Result<()> {
        match self {
            Target::Direct(path) => {
                let metadata = fs::symlink_metadata(path)?;
                if metadata.is_dir() {
                    if recursive {
                        fs::remove_dir_all(path)
                    } else {
                        fs::remove_dir(path)
                    }
                } else {
                    fs::remove_file(path)
                }
            }
            Target::Scoped(root, rel) => root.delete(rel, recursive),
        }
    }

    fn mkdir_all(&self) -> io::Result<()> {
        match self {
            Target::Direct(path) => fs::create_dir_all(path),
            Target::Scoped(root, rel) => root.mkdir_all(rel),
        }
    }
}

/// Resolve the request's `path` parameter. In dedicated mode (`sandbox = None`)
/// the path is used as-is; in host mode it is rooted at the sandbox home.
fn require_path(
    request: &Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<Option<Target>> {
    let raw = match request.params.get("path").map(|s| s.as_str()) {
        Some(p) if !p.is_empty() => p,
        _ => {
            resp.error(400, "missing 'path' query parameter")?;
            return Ok(None);
        }
    };
    match sandbox {
        None => Ok(Some(Target::Direct(PathBuf::from(raw)))),
        Some(sbx) => match ScopedRoot::open(Path::new(&sbx.home), sbx.uid) {
            Ok(root) => Ok(Some(Target::Scoped(root, fsutil::normalize_relative(raw)))),
            Err(e) => {
                resp.error(500, &format!("cannot open sandbox home: {e}"))?;
                Ok(None)
            }
        },
    }
}

/// Map a filesystem error to a status code. `ELOOP` is the interesting one: it is
/// what a refused symlink looks like, and it deserves a message that says so
/// rather than a bare OS error.
fn fs_error(resp: &mut ResponseWriter, action: &str, path: &Path, e: &io::Error) -> io::Result<()> {
    let path = path.display();
    if e.raw_os_error() == Some(libc::ELOOP) {
        return resp.error(
            400,
            &format!("cannot {action} {path}: a path component is a symlink, which this API does not follow"),
        );
    }
    if e.kind() == io::ErrorKind::NotFound {
        return resp.error(404, &format!("no such path: {path}"));
    }
    resp.error(400, &format!("cannot {action} {path}: {e}"))
}

pub fn handle_read(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<()> {
    let Some(target) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = target.display();
    let mut file = match target.open_read() {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::EISDIR) => {
            return resp.error(409, &format!("is a directory: {}", display.display()))
        }
        Err(e) => return fs_error(resp, "open", &display, &e),
    };
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        return resp.error(409, &format!("is a directory: {}", display.display()));
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
        file.seek(io::SeekFrom::Start(offset))?;
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
    resp.flush()?;
    if remaining > 0 {
        // The file shrank under us, so fewer bytes went out than Content-Length
        // promised. Keeping the connection alive would make the next response
        // start mid-body and be read as the tail of this one -- so fail the
        // connection instead. An honest truncated transfer beats a silently
        // desynchronised one.
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "file shrank during read; closing the connection to avoid a desynchronised response",
        ));
    }
    Ok(())
}

pub fn handle_write(
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<()> {
    let Some(target) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = target.display();
    let mkdir = crate::http::bool_param(&request.params, "mkdir", true);
    let mode = request.params.get("mode").and_then(|m| u32::from_str_radix(m, 8).ok());
    // Optional offset for parallel chunked uploads: write at the given position
    // without truncating (the file is created if missing).
    let offset = request.params.get("offset").and_then(|v| v.parse::<u64>().ok());

    // A ranged write deliberately does not truncate, which left a stale tail
    // whenever a large file was overwritten with a smaller one through parallel
    // chunks. `truncate_to` lets the client state the final size once, so the
    // file ends up exactly the content that was uploaded.
    let truncate_to = request.params.get("truncate_to").and_then(|v| v.parse::<u64>().ok());
    let mut file = match target.open_write(mkdir, offset) {
        Ok(f) => f,
        Err(e) => return fs_error(resp, "write", &display, &e),
    };
    if let Some(offset) = offset {
        if let Err(e) = file.seek(io::SeekFrom::Start(offset)) {
            return resp.error(400, &format!("cannot seek in {}: {e}", display.display()));
        }
    }
    let size = stream_body(request, reader, |chunk| file.write_all(chunk))?;
    if let Some(final_size) = truncate_to {
        if let Err(e) = file.set_len(final_size) {
            return resp.error(400, &format!("cannot truncate {} to {final_size}: {e}", display.display()));
        }
    }
    if let Some(mode) = mode {
        // Through the descriptor, so the mode lands on the file we just wrote
        // and cannot be redirected by a concurrent rename.
        let _ = fsutil::fchmod(&file, mode);
    }
    resp.json(200, &serde_json::json!({"path": display.to_string_lossy(), "size": size}))
}

fn entry_json(path: &Path, metadata: &Metadata) -> serde_json::Value {
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
) -> io::Result<()> {
    let Some(target) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = target.display();
    // A directory with a million entries used to be collected in full and
    // serialized into one response body. Paginated, with a default high enough
    // that no realistic directory is truncated without the caller asking.
    let limit = request.params.get("limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(10_000).min(50_000);
    let after = request.params.get("after").map(|s| s.as_str()).unwrap_or("");
    let entries = match target.list() {
        Ok(entries) => entries,
        Err(e) => return fs_error(resp, "list", &display, &e),
    };
    let mut named: Vec<(String, serde_json::Value)> = entries
        .iter()
        .map(|(path, metadata)| {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            (name, entry_json(path, metadata))
        })
        .filter(|(name, _)| name.as_str() > after)
        .collect();
    named.sort_by(|a, b| a.0.cmp(&b.0));
    let truncated = named.len() > limit;
    named.truncate(limit);
    let next = if truncated { named.last().map(|(name, _)| name.clone()) } else { None };
    let items: Vec<serde_json::Value> = named.into_iter().map(|(_, value)| value).collect();
    resp.json(200, &serde_json::json!({"entries": items, "truncated": truncated, "next": next}))
}

pub fn handle_stat(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<()> {
    let Some(target) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = target.display();
    match target.metadata() {
        Ok(metadata) => resp.json(200, &entry_json(&display, &metadata)),
        Err(e) => fs_error(resp, "stat", &display, &e),
    }
}

pub fn handle_delete(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<()> {
    let Some(target) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = target.display();
    let recursive = crate::http::bool_param(&request.params, "recursive", false);
    match target.delete(recursive) {
        Ok(()) => resp.json(200, &serde_json::json!({"deleted": display.to_string_lossy()})),
        Err(e) => fs_error(resp, "delete", &display, &e),
    }
}

pub fn handle_mkdir(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<()> {
    let Some(target) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = target.display();
    match target.mkdir_all() {
        Ok(()) => resp.json(200, &serde_json::json!({"created": display.to_string_lossy()})),
        Err(e) => fs_error(resp, "mkdir", &display, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A throwaway `<base>/home` + `<base>/outside` pair. `outside` stands in for
    /// anything the sandbox must not be able to reach through the server.
    fn layout() -> (PathBuf, PathBuf, PathBuf) {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "sbx-files-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let home = base.join("home");
        let outside = base.join("outside");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&outside).unwrap();
        (base, home, outside)
    }

    /// These tests run unprivileged, so the root is opened for our own uid and
    /// the `fchown` calls inside it are no-ops.
    fn root(home: &Path) -> ScopedRoot {
        ScopedRoot::open(home, unsafe { libc::geteuid() }).unwrap()
    }

    #[test]
    fn normalization_cannot_name_anything_outside_the_home() {
        for path in ["/etc/passwd", "../../etc/passwd", "a/../../../etc/passwd", "/", "./x"] {
            let rel = fsutil::normalize_relative(path);
            assert!(!rel.is_absolute(), "{path:?} normalized to an absolute path");
            assert!(
                !rel.components().any(|c| matches!(c, std::path::Component::ParentDir)),
                "{path:?} kept a `..` component"
            );
        }
        assert_eq!(fsutil::normalize_relative("/a/b/../c"), PathBuf::from("a/c"));
    }

    #[test]
    fn final_symlink_is_not_followed() {
        let (base, home, outside) = layout();
        fs::write(outside.join("secret"), b"secret").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), home.join("escape")).unwrap();
        let root = root(&home);

        assert!(root.open_read(Path::new("escape")).is_err());
        assert!(root.open_write(Path::new("escape"), true, None).is_err());
        // The target is untouched: not read, not truncated.
        assert_eq!(fs::read(outside.join("secret")).unwrap(), b"secret");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn intermediate_symlink_is_not_followed() {
        let (base, home, outside) = layout();
        std::os::unix::fs::symlink(&outside, home.join("escape")).unwrap();
        let root = root(&home);

        assert!(root.open_write(Path::new("escape/created"), true, None).is_err());
        assert!(root.open_read(Path::new("escape/anything")).is_err());
        assert!(root.list(Path::new("escape")).is_err());
        assert!(!outside.join("created").exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn deleting_a_symlink_leaves_its_target_alone() {
        let (base, home, outside) = layout();
        fs::write(outside.join("secret"), b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, home.join("escape")).unwrap();
        let root = root(&home);

        root.delete(Path::new("escape"), true).unwrap();
        assert_eq!(fs::read(outside.join("secret")).unwrap(), b"secret");
        assert!(fs::symlink_metadata(home.join("escape")).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn stat_reports_the_link_not_its_target() {
        let (base, home, outside) = layout();
        fs::write(outside.join("secret"), b"0123456789").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), home.join("escape")).unwrap();
        let root = root(&home);

        let metadata = root.metadata(Path::new("escape")).unwrap();
        assert!(metadata.file_type().is_symlink());
        assert_ne!(metadata.len(), 10, "reported the target's size, so it followed the link");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn listing_reports_symlinks_without_following_them() {
        let (base, home, outside) = layout();
        std::os::unix::fs::symlink(&outside, home.join("escape")).unwrap();
        let root = root(&home);

        let entries = root.list(Path::new("")).unwrap();
        let (_, metadata) = entries.iter().find(|(p, _)| p.ends_with("escape")).unwrap();
        assert!(metadata.file_type().is_symlink());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn writes_create_the_parent_chain_and_round_trip() {
        let (base, home, _) = layout();
        let root = root(&home);

        let mut file = root.open_write(Path::new("a/b/file"), true, None).unwrap();
        file.write_all(b"hello").unwrap();
        drop(file);
        assert_eq!(fs::read(home.join("a/b/file")).unwrap(), b"hello");

        let mut read_back = root.open_read(Path::new("a/b/file")).unwrap();
        let mut content = Vec::new();
        read_back.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"hello");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_plain_write_truncates_and_a_ranged_write_does_not() {
        let (base, home, _) = layout();
        let root = root(&home);
        fs::write(home.join("f"), b"0123456789").unwrap();

        root.open_write(Path::new("f"), false, None).unwrap().write_all(b"ab").unwrap();
        assert_eq!(fs::read(home.join("f")).unwrap(), b"ab");

        fs::write(home.join("f"), b"0123456789").unwrap();
        let mut file = root.open_write(Path::new("f"), false, Some(2)).unwrap();
        file.seek(io::SeekFrom::Start(2)).unwrap();
        file.write_all(b"ab").unwrap();
        assert_eq!(fs::read(home.join("f")).unwrap(), b"01ab456789");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn recursive_delete_walks_by_descriptor_and_skips_symlinked_trees() {
        let (base, home, outside) = layout();
        fs::create_dir_all(home.join("tree/sub")).unwrap();
        fs::write(home.join("tree/sub/file"), b"x").unwrap();
        fs::write(outside.join("keep"), b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, home.join("tree/link")).unwrap();
        let root = root(&home);

        root.delete(Path::new("tree"), true).unwrap();
        assert!(!home.join("tree").exists());
        // The symlink was unlinked; what it pointed at was not descended into.
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"keep");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn special_files_are_refused_rather_than_blocking() {
        let (base, home, _) = layout();
        let fifo = home.join("pipe");
        let c_fifo = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        let root = root(&home);

        // Would otherwise block a privileged thread until a writer appears.
        assert!(root.open_read(Path::new("pipe")).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn the_home_itself_cannot_be_deleted() {
        let (base, home, _) = layout();
        let root = root(&home);
        assert!(root.delete(Path::new(""), true).is_err());
        assert!(home.exists());
        fs::remove_dir_all(base).unwrap();
    }
}
