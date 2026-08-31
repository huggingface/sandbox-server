//! Filesystem endpoints: raw-body file transfer (no base64), directory
//! listing, stat, delete, mkdir.
//!
//! Dedicated-mode paths are ordinary container paths. Host-mode paths are
//! resolved descriptor-by-descriptor from an open sandbox-home fd, with
//! `O_NOFOLLOW` on every component. Sandboxes may create symlinks for their own
//! processes, but the privileged file API never follows them.

use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{self, BufReader, Read, Seek, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use crate::http::{stream_body, Request, ResponseWriter};
use crate::sandboxes::SandboxEntry;

fn c_path(path: &OsStr) -> io::Result<CString> {
    CString::new(path.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn open_fd_at(dirfd: RawFd, name: &OsStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    let name = c_path(name)?;
    let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOFOLLOW, mode) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_dir_at(dirfd: RawFd, name: &OsStr) -> io::Result<File> {
    open_fd_at(dirfd, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

fn dup_file(file: &File) -> io::Result<File> {
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn normalized_relative(path: &str) -> PathBuf {
    let mut result = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(name) => result.push(name),
            Component::ParentDir => {
                result.pop();
            }
            // RootDir / CurDir / Prefix are ignored: host-mode paths are rooted
            // at the sandbox home regardless of a leading slash.
            _ => {}
        }
    }
    result
}

fn path_components(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect()
}

fn proc_fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn proc_child_path(dir: &File, name: &OsStr) -> PathBuf {
    let mut path = proc_fd_path(dir);
    path.push(name);
    path
}

struct ScopedRoot {
    home: PathBuf,
    dir: File,
    uid: u32,
}

impl ScopedRoot {
    fn open(entry: &SandboxEntry) -> io::Result<Self> {
        let home = PathBuf::from(&entry.home);
        let home_c = c_path(home.as_os_str())?;
        let fd = unsafe {
            libc::open(
                home_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { home, dir: unsafe { File::from_raw_fd(fd) }, uid: entry.uid })
    }

    #[cfg(test)]
    fn open_for_test(home: &Path) -> io::Result<Self> {
        let home_c = c_path(home.as_os_str())?;
        let fd = unsafe {
            libc::open(
                home_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            home: home.to_path_buf(),
            dir: unsafe { File::from_raw_fd(fd) },
            uid: unsafe { libc::geteuid() },
        })
    }

    fn chown(&self, file: &File) -> io::Result<()> {
        if unsafe { libc::fchown(file.as_raw_fd(), self.uid, self.uid) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn walk_dir(&self, components: &[OsString], create: bool) -> io::Result<File> {
        let mut dir = dup_file(&self.dir)?;
        for name in components {
            match open_dir_at(dir.as_raw_fd(), name) {
                Ok(child) => dir = child,
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    let name_c = c_path(name)?;
                    let created = unsafe { libc::mkdirat(dir.as_raw_fd(), name_c.as_ptr(), 0o755) };
                    if created != 0 {
                        let mkdir_error = io::Error::last_os_error();
                        if mkdir_error.kind() != io::ErrorKind::AlreadyExists {
                            return Err(mkdir_error);
                        }
                    }
                    let child = open_dir_at(dir.as_raw_fd(), name)?;
                    if created == 0 {
                        self.chown(&child)?;
                    }
                    dir = child;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(dir)
    }

    fn parent_and_name(&self, relative: &Path, create_parents: bool) -> io::Result<(File, OsString)> {
        let components = path_components(relative);
        let Some((name, parents)) = components.split_last() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path refers to the sandbox root"));
        };
        Ok((self.walk_dir(parents, create_parents)?, name.clone()))
    }

    fn open_read(&self, relative: &Path) -> io::Result<File> {
        if relative.as_os_str().is_empty() {
            return dup_file(&self.dir);
        }
        let (parent, name) = self.parent_and_name(relative, false)?;
        open_fd_at(parent.as_raw_fd(), &name, libc::O_RDONLY, 0)
    }

    fn open_dir(&self, relative: &Path) -> io::Result<File> {
        self.walk_dir(&path_components(relative), false)
    }

    fn open_write(&self, relative: &Path, create_parents: bool, offset: Option<u64>) -> io::Result<File> {
        let (parent, name) = self.parent_and_name(relative, create_parents)?;
        let flags = libc::O_WRONLY | libc::O_CREAT | if offset.is_some() { 0 } else { libc::O_TRUNC };
        let mut file = open_fd_at(parent.as_raw_fd(), &name, flags, 0o666)?;
        self.chown(&file)?;
        if let Some(offset) = offset {
            file.seek(io::SeekFrom::Start(offset))?;
        }
        Ok(file)
    }

    fn metadata(&self, relative: &Path) -> io::Result<Metadata> {
        if relative.as_os_str().is_empty() {
            return self.dir.metadata();
        }
        let (parent, name) = self.parent_and_name(relative, false)?;
        fs::symlink_metadata(proc_child_path(&parent, &name))
    }

    fn mkdir_all(&self, relative: &Path) -> io::Result<()> {
        self.walk_dir(&path_components(relative), true).map(drop)
    }

    fn delete(&self, relative: &Path, recursive: bool) -> io::Result<()> {
        let (parent, name) = self.parent_and_name(relative, false)?;
        let metadata = fs::symlink_metadata(proc_child_path(&parent, &name))?;
        if metadata.is_dir() {
            if recursive {
                remove_tree_at(&parent, &name)
            } else {
                unlink_at(&parent, &name, libc::AT_REMOVEDIR)
            }
        } else {
            unlink_at(&parent, &name, 0)
        }
    }
}

fn unlink_at(parent: &File, name: &OsStr, flags: i32) -> io::Result<()> {
    let name = c_path(name)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn remove_tree_at(parent: &File, name: &OsStr) -> io::Result<()> {
    let dir = open_dir_at(parent.as_raw_fd(), name)?;
    for entry in fs::read_dir(proc_fd_path(&dir))? {
        let entry = entry?;
        let child_name = entry.file_name();
        let metadata = fs::symlink_metadata(proc_child_path(&dir, &child_name))?;
        if metadata.is_dir() {
            remove_tree_at(&dir, &child_name)?;
        } else {
            unlink_at(&dir, &child_name, 0)?;
        }
    }
    unlink_at(parent, name, libc::AT_REMOVEDIR)
}

enum ApiPath {
    Dedicated(PathBuf),
    Scoped { root: ScopedRoot, relative: PathBuf },
}

impl ApiPath {
    fn resolve(raw: &str, sandbox: Option<&SandboxEntry>) -> io::Result<Self> {
        match sandbox {
            None => Ok(Self::Dedicated(PathBuf::from(raw))),
            Some(entry) => Ok(Self::Scoped { root: ScopedRoot::open(entry)?, relative: normalized_relative(raw) }),
        }
    }

    fn display(&self) -> PathBuf {
        match self {
            Self::Dedicated(path) => path.clone(),
            Self::Scoped { root, relative } => root.home.join(relative),
        }
    }

    fn open_read(&self) -> io::Result<File> {
        match self {
            Self::Dedicated(path) => File::open(path),
            Self::Scoped { root, relative } => root.open_read(relative),
        }
    }

    fn open_write(&self, create_parents: bool, offset: Option<u64>) -> io::Result<File> {
        match self {
            Self::Dedicated(path) => {
                if create_parents {
                    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                        fs::create_dir_all(parent)?;
                    }
                }
                let mut options = fs::OpenOptions::new();
                options.write(true).create(true).truncate(offset.is_none());
                let mut file = options.open(path)?;
                if let Some(offset) = offset {
                    file.seek(io::SeekFrom::Start(offset))?;
                }
                Ok(file)
            }
            Self::Scoped { root, relative } => root.open_write(relative, create_parents, offset),
        }
    }

    fn metadata(&self) -> io::Result<Metadata> {
        match self {
            Self::Dedicated(path) => fs::symlink_metadata(path),
            Self::Scoped { root, relative } => root.metadata(relative),
        }
    }

    fn list(&self) -> io::Result<Vec<(PathBuf, Metadata)>> {
        let (directory, display) = match self {
            Self::Dedicated(path) => (fs::read_dir(path)?, path.clone()),
            Self::Scoped { root, relative } => {
                let dir = root.open_dir(relative)?;
                (fs::read_dir(proc_fd_path(&dir))?, root.home.join(relative))
            }
        };
        let mut entries = Vec::new();
        for entry in directory.flatten() {
            // `DirEntry::metadata` follows a final symlink. Keep list/stat
            // consistent with the scoped API's no-follow policy.
            if let Ok(metadata) = fs::symlink_metadata(entry.path()) {
                entries.push((display.join(entry.file_name()), metadata));
            }
        }
        Ok(entries)
    }

    fn mkdir_all(&self) -> io::Result<()> {
        match self {
            Self::Dedicated(path) => fs::create_dir_all(path),
            Self::Scoped { root, relative } => root.mkdir_all(relative),
        }
    }

    fn delete(&self, recursive: bool) -> io::Result<()> {
        match self {
            Self::Dedicated(path) => {
                let metadata = fs::symlink_metadata(path)?;
                if metadata.is_dir() {
                    if recursive { fs::remove_dir_all(path) } else { fs::remove_dir(path) }
                } else {
                    fs::remove_file(path)
                }
            }
            Self::Scoped { root, relative } => root.delete(relative, recursive),
        }
    }
}

fn require_path(
    request: &Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<Option<ApiPath>> {
    let raw = match request.params.get("path").map(String::as_str) {
        Some(path) if !path.is_empty() => path,
        _ => {
            resp.error(400, "missing 'path' query parameter")?;
            return Ok(None);
        }
    };
    match ApiPath::resolve(raw, sandbox) {
        Ok(path) => Ok(Some(path)),
        Err(error) => {
            resp.error(400, &format!("cannot resolve {raw}: {error}"))?;
            Ok(None)
        }
    }
}

pub fn handle_read(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<()> {
    let Some(path) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = path.display().to_string_lossy().into_owned();
    let mut file = match path.open_read() {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return resp.error(404, &format!("no such file: {display}"))
        }
        Err(error) => return resp.error(400, &format!("cannot open {display}: {error}")),
    };
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        return resp.error(409, &format!("is a directory: {display}"));
    }
    let offset: u64 = request.params.get("offset").and_then(|value| value.parse().ok()).unwrap_or(0);
    let length = request
        .params
        .get("length")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(u64::MAX)
        .min(metadata.len().saturating_sub(offset));
    if offset > 0 {
        file.seek(io::SeekFrom::Start(offset))?;
    }
    resp.start_fixed(200, "application/octet-stream", length)?;
    let mut buffer = vec![0u8; length.min(256 * 1024) as usize];
    let mut remaining = length;
    while remaining > 0 {
        let max = buffer.len().min(remaining as usize);
        let read = file.read(&mut buffer[..max])?;
        if read == 0 {
            break;
        }
        resp.raw(&buffer[..read])?;
        remaining -= read as u64;
    }
    resp.flush()
}

pub fn handle_write(
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<()> {
    let Some(path) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = path.display().to_string_lossy().into_owned();
    let mkdir = crate::http::bool_param(&request.params, "mkdir", true);
    let mode = request.params.get("mode").and_then(|value| u32::from_str_radix(value, 8).ok());
    let offset = request.params.get("offset").and_then(|value| value.parse::<u64>().ok());
    let mut file = match path.open_write(mkdir, offset) {
        Ok(file) => file,
        Err(error) => return resp.error(400, &format!("cannot open {display}: {error}")),
    };
    let size = stream_body(request, reader, |chunk| file.write_all(chunk))?;
    if let Some(mode) = mode {
        let _ = file.set_permissions(fs::Permissions::from_mode(mode));
    }
    resp.json(200, &serde_json::json!({"path": display, "size": size}))
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
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as i64);
    serde_json::json!({
        "name": path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default(),
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
    let Some(path) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = path.display().to_string_lossy().into_owned();
    let entries = match path.list() {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return resp.error(404, &format!("no such directory: {display}"))
        }
        Err(error) => return resp.error(400, &format!("cannot list {display}: {error}")),
    };
    let mut items: Vec<_> = entries.iter().map(|(path, metadata)| entry_json(path, metadata)).collect();
    items.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    resp.json(200, &serde_json::json!({"entries": items}))
}

pub fn handle_stat(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<()> {
    let Some(path) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = path.display();
    match path.metadata() {
        Ok(metadata) => resp.json(200, &entry_json(&display, &metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            resp.error(404, &format!("no such path: {}", display.to_string_lossy()))
        }
        Err(error) => resp.error(400, &format!("cannot stat {}: {error}", display.to_string_lossy())),
    }
}

pub fn handle_delete(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<()> {
    let Some(path) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = path.display().to_string_lossy().into_owned();
    let recursive = crate::http::bool_param(&request.params, "recursive", false);
    match path.delete(recursive) {
        Ok(()) => resp.json(200, &serde_json::json!({"deleted": display})),
        Err(error) if error.kind() == io::ErrorKind::NotFound => resp.error(404, &format!("no such path: {display}")),
        Err(error) => resp.error(400, &format!("cannot delete {display}: {error}")),
    }
}

pub fn handle_mkdir(
    request: &mut Request,
    resp: &mut ResponseWriter,
    sandbox: Option<&SandboxEntry>,
) -> io::Result<()> {
    let Some(path) = require_path(request, resp, sandbox)? else { return Ok(()) };
    let display = path.display().to_string_lossy().into_owned();
    match path.mkdir_all() {
        Ok(()) => resp.json(200, &serde_json::json!({"created": display})),
        Err(error) => resp.error(400, &format!("cannot mkdir {display}: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

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

    #[test]
    fn scoped_files_reject_final_symlinks() {
        let (base, home, outside) = layout();
        fs::write(outside.join("secret"), b"secret").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), home.join("escape")).unwrap();
        let root = ScopedRoot::open_for_test(&home).unwrap();

        assert!(root.open_read(Path::new("escape")).is_err());
        assert!(root.open_write(Path::new("escape"), true, None).is_err());
        assert_eq!(fs::read(outside.join("secret")).unwrap(), b"secret");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn scoped_files_reject_intermediate_symlinks() {
        let (base, home, outside) = layout();
        std::os::unix::fs::symlink(&outside, home.join("escape")).unwrap();
        let root = ScopedRoot::open_for_test(&home).unwrap();

        assert!(root.open_write(Path::new("escape/created"), true, None).is_err());
        assert!(!outside.join("created").exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn deleting_symlink_does_not_touch_target() {
        let (base, home, outside) = layout();
        fs::write(outside.join("secret"), b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, home.join("escape")).unwrap();
        let root = ScopedRoot::open_for_test(&home).unwrap();

        root.delete(Path::new("escape"), true).unwrap();
        assert_eq!(fs::read(outside.join("secret")).unwrap(), b"secret");
        assert!(!home.join("escape").exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn scoped_write_creates_owned_parent_chain() {
        let (base, home, _) = layout();
        let root = ScopedRoot::open_for_test(&home).unwrap();
        let mut file = root.open_write(Path::new("a/b/file"), true, None).unwrap();
        file.write_all(b"ok").unwrap();
        drop(file);

        assert_eq!(fs::read(home.join("a/b/file")).unwrap(), b"ok");
        fs::remove_dir_all(base).unwrap();
    }
}
