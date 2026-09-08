//! Descriptor-relative filesystem primitives.
//!
//! The server runs as root, outside every sandbox's Landlock domain, while the
//! names it operates on (a home directory's contents, a proxy socket) belong to
//! the sandbox. Resolving those names by path would make the server a confused
//! deputy: a symlink placed in its own home by a sandbox's code would redirect a
//! privileged operation anywhere on the host.
//!
//! So privileged host-mode operations walk the path one component at a time from
//! an already-open home directory descriptor, with `O_NOFOLLOW` on every step,
//! and act through the resulting descriptor (`fchown`, `fchmod`, `unlinkat`)
//! rather than by name. A sandbox is still free to create symlinks for its own
//! processes — this API simply never follows them.

use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// Flags shared by every open below: never follow a symlink, never leak the fd
/// into a child, and never block on a FIFO or device node.
const BASE_FLAGS: i32 = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;

pub fn c_path(path: &OsStr) -> io::Result<CString> {
    CString::new(path.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

/// `openat(dirfd, name, ...)`, wrapped so the fd is owned by a `File`.
pub fn open_at(dirfd: RawFd, name: &OsStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    let name = c_path(name)?;
    let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags | BASE_FLAGS, mode as libc::c_uint) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Open a subdirectory of `dirfd`. Fails with `ELOOP` if `name` is a symlink.
pub fn open_dir_at(dirfd: RawFd, name: &OsStr) -> io::Result<File> {
    open_at(dirfd, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

/// Open `name` as an `O_PATH` descriptor. Unlike a normal open, this *succeeds*
/// on a symlink (referring to the link itself), which is what `stat`-like
/// operations want: they report the link, never its target.
pub fn open_path_at(dirfd: RawFd, name: &OsStr) -> io::Result<File> {
    open_at(dirfd, name, libc::O_PATH, 0)
}

/// `mkdirat`, treating an existing directory as success. Anything else that
/// already occupies the name (including a symlink) surfaces as an error when the
/// caller then tries to open it as a directory.
pub fn mkdir_at(dirfd: RawFd, name: &OsStr, mode: libc::mode_t) -> io::Result<()> {
    let c_name = c_path(name)?;
    if unsafe { libc::mkdirat(dirfd, c_name.as_ptr(), mode) } == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::AlreadyExists {
        return Ok(());
    }
    Err(err)
}

pub fn unlink_at(dirfd: RawFd, name: &OsStr, dir: bool) -> io::Result<()> {
    let c_name = c_path(name)?;
    let flags = if dir { libc::AT_REMOVEDIR } else { 0 };
    if unsafe { libc::unlinkat(dirfd, c_name.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn fchown(file: &File, uid: u32) -> io::Result<()> {
    if unsafe { libc::fchown(file.as_raw_fd(), uid, uid) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn fchmod(file: &File, mode: u32) -> io::Result<()> {
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The `/proc/self/fd/<n>` name of an open descriptor.
///
/// Resolving this magic symlink lands directly on the descriptor's inode without
/// re-walking the original path, so it is a race-free way to hand a pinned inode
/// to an API that only accepts a name (`read_dir`, `connect`). Requires `/proc`,
/// which the server already depends on elsewhere.
pub fn proc_fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// Normalize a user-supplied path into a relative one that cannot name anything
/// outside its root: components are resolved lexically, a leading `/` is
/// dropped, and `..` pops. This is only the first of two defences — the walk
/// below is what stops a symlink from escaping.
pub fn normalize_relative(path: &str) -> PathBuf {
    let mut result = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(name) => result.push(name),
            Component::ParentDir => {
                result.pop();
            }
            // RootDir / CurDir / Prefix are ignored: paths are rooted at the home
            // regardless of a leading slash.
            _ => {}
        }
    }
    result
}

fn components_of(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect()
}

/// An open handle on one sandbox's home directory, and the uid that owns it.
///
/// Every operation is expressed relative to `dir`, so the home cannot be swapped
/// out from under us and no component of a request path is ever dereferenced as a
/// symlink.
pub struct ScopedRoot {
    home: PathBuf,
    dir: File,
    uid: u32,
}

/// Where a walk ended up: the directory holding the final component, and that
/// component's name. `None` means the path referred to the root itself.
pub struct Located {
    pub parent: File,
    pub name: Option<OsString>,
}

impl ScopedRoot {
    pub fn open(home: &Path, uid: u32) -> io::Result<Self> {
        let c_home = c_path(home.as_os_str())?;
        let fd = unsafe {
            libc::open(c_home.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { home: home.to_path_buf(), dir: unsafe { File::from_raw_fd(fd) }, uid })
    }

    pub fn dir_fd(&self) -> RawFd {
        self.dir.as_raw_fd()
    }

    /// Absolute path of `rel`, for error messages and API responses only — never
    /// for an actual filesystem operation.
    pub fn display(&self, rel: &Path) -> PathBuf {
        self.home.join(rel)
    }

    fn dup_dir(&self) -> io::Result<File> {
        let fd = unsafe { libc::fcntl(self.dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Walk to the directory containing `rel`'s last component. With
    /// `create_dirs`, missing intermediate directories are created (owned by the
    /// sandbox) as we go.
    pub fn locate(&self, rel: &Path, create_dirs: bool) -> io::Result<Located> {
        let mut components = components_of(rel);
        let Some(name) = components.pop() else {
            return Ok(Located { parent: self.dup_dir()?, name: None });
        };
        let mut parent = self.dup_dir()?;
        for component in components {
            if create_dirs {
                mkdir_at(parent.as_raw_fd(), &component, 0o700)?;
            }
            let next = open_dir_at(parent.as_raw_fd(), &component)?;
            if create_dirs {
                // Created as root; hand it to the sandbox so its own code can use it.
                let _ = fchown(&next, self.uid);
            }
            parent = next;
        }
        Ok(Located { parent, name: Some(name) })
    }

    /// Open `rel` for reading. Fails if any component (including the last) is a
    /// symlink, and if the target is not a regular file — a FIFO or device node
    /// would otherwise block or misbehave on a privileged thread.
    pub fn open_read(&self, rel: &Path) -> io::Result<File> {
        let located = self.locate(rel, false)?;
        let Some(name) = located.name else {
            return Err(io::Error::from_raw_os_error(libc::EISDIR));
        };
        let file = open_at(located.parent.as_raw_fd(), &name, libc::O_RDONLY, 0)?;
        let metadata = file.metadata()?;
        if metadata.is_dir() {
            return Err(io::Error::from_raw_os_error(libc::EISDIR));
        }
        if !metadata.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
        }
        Ok(file)
    }

    /// Open `rel` for writing, creating it (and optionally its parents) as the
    /// sandbox's uid. `offset.is_none()` truncates, matching a plain overwrite;
    /// a ranged write leaves the rest of the file intact.
    pub fn open_write(&self, rel: &Path, create_parents: bool, offset: Option<u64>) -> io::Result<File> {
        let located = self.locate(rel, create_parents)?;
        let Some(name) = located.name else {
            return Err(io::Error::from_raw_os_error(libc::EISDIR));
        };
        let mut flags = libc::O_WRONLY | libc::O_CREAT;
        if offset.is_none() {
            flags |= libc::O_TRUNC;
        }
        let file = open_at(located.parent.as_raw_fd(), &name, flags, 0o600)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
        }
        let _ = fchown(&file, self.uid);
        Ok(file)
    }

    /// `stat` of `rel` without following a final symlink (the link itself is
    /// reported, like `lstat`).
    pub fn metadata(&self, rel: &Path) -> io::Result<Metadata> {
        let located = self.locate(rel, false)?;
        match located.name {
            None => located.parent.metadata(),
            Some(name) => open_path_at(located.parent.as_raw_fd(), &name)?.metadata(),
        }
    }

    /// List `rel`, returning each entry's absolute display path and its
    /// `lstat` metadata.
    pub fn list(&self, rel: &Path) -> io::Result<Vec<(PathBuf, Metadata)>> {
        let located = self.locate(rel, false)?;
        let dir = match &located.name {
            None => self.dup_dir()?,
            Some(name) => open_dir_at(located.parent.as_raw_fd(), name)?,
        };
        let mut entries = Vec::new();
        // The fd is already pinned to this directory's inode, so reading it
        // through /proc/self/fd cannot be redirected by a concurrent rename.
        for entry in std::fs::read_dir(proc_fd_path(&dir))? {
            let name = entry?.file_name();
            let Ok(handle) = open_path_at(dir.as_raw_fd(), &name) else { continue };
            let Ok(metadata) = handle.metadata() else { continue };
            entries.push((self.display(&rel.join(&name)), metadata));
        }
        Ok(entries)
    }

    /// Remove `rel`. A symlink is unlinked itself, never followed, so deleting
    /// one never touches its target.
    pub fn delete(&self, rel: &Path, recursive: bool) -> io::Result<()> {
        let located = self.locate(rel, false)?;
        let Some(name) = located.name else {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "cannot delete the sandbox home"));
        };
        let parent_fd = located.parent.as_raw_fd();
        let metadata = open_path_at(parent_fd, &name)?.metadata();
        let is_dir = metadata.map(|m| m.is_dir()).unwrap_or(false);
        if !is_dir {
            return unlink_at(parent_fd, &name, false);
        }
        if recursive {
            let dir = open_dir_at(parent_fd, &name)?;
            remove_dir_contents(&dir)?;
        }
        unlink_at(parent_fd, &name, true)
    }

    /// Create `rel` and any missing parents, all owned by the sandbox.
    pub fn mkdir_all(&self, rel: &Path) -> io::Result<()> {
        let located = self.locate(rel, true)?;
        let Some(name) = located.name else {
            return Ok(()); // the home itself always exists
        };
        mkdir_at(located.parent.as_raw_fd(), &name, 0o700)?;
        let dir = open_dir_at(located.parent.as_raw_fd(), &name)?;
        let _ = fchown(&dir, self.uid);
        Ok(())
    }
}

/// Depth-first removal of everything under an open directory, entirely through
/// descriptors: no path is ever re-resolved, and no symlink is followed.
fn remove_dir_contents(dir: &File) -> io::Result<()> {
    let mut subdirs = Vec::new();
    for entry in std::fs::read_dir(proc_fd_path(dir))? {
        let name = entry?.file_name();
        let is_dir = open_path_at(dir.as_raw_fd(), &name).and_then(|h| h.metadata()).map(|m| m.is_dir());
        if is_dir.unwrap_or(false) {
            subdirs.push(name);
        } else {
            unlink_at(dir.as_raw_fd(), &name, false)?;
        }
    }
    for name in subdirs {
        let child = open_dir_at(dir.as_raw_fd(), &name)?;
        remove_dir_contents(&child)?;
        drop(child);
        unlink_at(dir.as_raw_fd(), &name, true)?;
    }
    Ok(())
}
