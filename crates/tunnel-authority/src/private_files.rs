//! Owner-only files addressed relative to pinned directory handles.
//! Neither a final symlink nor a symlink in an ancestor can be followed. An
//! ancestor rename after traversal cannot redirect reads or secret writes.

#[cfg(unix)]
mod platform {
    use std::ffi::OsString;
    use std::fs::{File, Metadata};
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};

    use rustix::fs::{AtFlags, CWD, Mode, OFlags, openat, statat, unlinkat};

    use crate::Result;

    struct PrivatePath {
        directory: File,
        name: OsString,
    }

    impl PrivatePath {
        fn open(path: &Path) -> Result<Self> {
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|_| "cannot resolve private file directory")?
                    .join(path)
            };
            let name = path
                .file_name()
                .ok_or("private file path requires a file name")?
                .to_os_string();
            let parent = path.parent().ok_or("private file path requires a parent")?;
            let directory_flags =
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let mut directory = File::from(
                openat(CWD, "/", directory_flags, Mode::empty())
                    .map_err(|_| "cannot open private file directory")?,
            );
            for component in parent.components() {
                match component {
                    Component::RootDir | Component::CurDir => {}
                    Component::Normal(name) => {
                        directory = File::from(
                            openat(&directory, name, directory_flags, Mode::empty())
                                .map_err(|_| "directory is inaccessible or a symlink")?,
                        );
                    }
                    _ => return Err("parent traversal is forbidden in private file paths"),
                }
            }
            let metadata = directory
                .metadata()
                .map_err(|_| "cannot inspect private file directory")?;
            if metadata.mode() & 0o7777 != 0o700
                || metadata.uid() != rustix::process::geteuid().as_raw()
            {
                return Err("file parent must be owned by this user with mode 0700");
            }
            Ok(Self { directory, name })
        }

        fn still_names(&self, metadata: &Metadata) -> bool {
            statat(&self.directory, &self.name, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|current| {
                // The stat ABI uses different integer widths on Linux
                // and Darwin; MetadataExt normalizes both to u64.
                #[allow(clippy::unnecessary_cast)]
                let identity = (current.st_dev as u64, current.st_ino as u64);
                identity == (metadata.dev(), metadata.ino())
            })
        }
    }

    fn validate_file(metadata: &Metadata) -> Result<()> {
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err("input must be a regular file with no hard links");
        }
        if metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("file must be owned by this user with mode 0600");
        }
        Ok(())
    }

    pub(super) fn read(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
        let path = PrivatePath::open(path)?;
        let file = File::from(
            openat(
                &path.directory,
                &path.name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "input is missing, inaccessible or a symlink")?,
        );
        let before = file.metadata().map_err(|_| "cannot inspect input")?;
        validate_file(&before)?;
        if before.len() > max_bytes as u64 {
            return Err("input exceeds size limit");
        }
        let mut bytes = Vec::with_capacity(max_bytes.min(4096));
        (&file)
            .take((max_bytes + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read input")?;
        if bytes.len() > max_bytes {
            return Err("input exceeds size limit");
        }
        let after = file.metadata().map_err(|_| "cannot inspect input")?;
        validate_file(&after)?;
        if before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || !path.still_names(&after)
        {
            return Err("input changed while it was read");
        }
        Ok(bytes)
    }

    pub(crate) struct NewFile {
        path: PrivatePath,
        file: File,
        committed: bool,
    }

    impl NewFile {
        pub(crate) fn create(path: &Path) -> Result<Self> {
            let path = PrivatePath::open(path)?;
            let file = File::from(
                openat(
                    &path.directory,
                    &path.name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(|_| "output already exists or cannot be created")?,
            );
            let output = Self {
                path,
                file,
                committed: false,
            };
            let metadata = output
                .file
                .metadata()
                .map_err(|_| "cannot inspect output")?;
            validate_file(&metadata)?;
            Ok(output)
        }

        pub(crate) fn write_and_sync(&mut self, bytes: &[u8]) -> Result<()> {
            self.file
                .write_all(bytes)
                .map_err(|_| "cannot write output")?;
            self.file.sync_all().map_err(|_| "cannot sync output")?;
            self.path
                .directory
                .sync_all()
                .map_err(|_| "cannot sync output directory")?;
            let metadata = self.file.metadata().map_err(|_| "cannot inspect output")?;
            validate_file(&metadata)?;
            if !self.path.still_names(&metadata) {
                return Err("output path changed while it was written");
            }
            Ok(())
        }

        pub(crate) fn commit(&mut self) {
            self.committed = true;
        }
    }

    impl Drop for NewFile {
        fn drop(&mut self) {
            if !self.committed
                && let Ok(metadata) = self.file.metadata()
                && self.path.still_names(&metadata)
            {
                // Never remove a different file that replaced our output.
                let _ = unlinkat(&self.path.directory, &self.path.name, AtFlags::empty());
                let _ = self.path.directory.sync_all();
            }
        }
    }
}

#[cfg(unix)]
pub(crate) use platform::NewFile;

#[cfg(unix)]
pub(crate) fn read(path: &std::path::Path, max_bytes: usize) -> crate::Result<Vec<u8>> {
    platform::read(path, max_bytes)
}

// The authority is distributed only on the Unix server-capable targets. Keep
// workspace compilation possible elsewhere, but never silently drop private
// file protections on an unsupported platform.
#[cfg(not(unix))]
pub(crate) struct NewFile;

#[cfg(not(unix))]
impl NewFile {
    pub(crate) fn create(_: &std::path::Path) -> crate::Result<Self> {
        Err("private authority files require Unix")
    }
    pub(crate) fn write_and_sync(&mut self, _: &[u8]) -> crate::Result<()> {
        Err("private authority files require Unix")
    }
    pub(crate) fn commit(&mut self) {}
}

#[cfg(not(unix))]
pub(crate) fn read(_: &std::path::Path, _: usize) -> crate::Result<Vec<u8>> {
    Err("private authority files require Unix")
}
