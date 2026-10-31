//! A bounded, exclusively locked authority-state file.
//!
//! The lock lives in a stable sibling inode, never in the state inode that an
//! update replaces. All accesses use a pinned private directory. This store
//! protects a known local state from accidental replacement; it cannot detect
//! rollback of the entire volume between processes. The caller owns schema,
//! identity and monotonic-counter validation and must stop on every write error.

pub(crate) const MAX_STATE_BYTES: usize = 256 * 1024;

// These are the Unix server platforms this repository ships. Other targets
// still compile, but do not get a weaker substitute for atomic NOREPLACE.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use std::{
        ffi::OsString,
        fmt,
        fs::{File, Metadata, TryLockError},
        io::{Read, Write},
        os::unix::fs::MetadataExt,
        path::{Component, Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use rustix::{
        fs::{
            AtFlags, CWD, Mode, OFlags, RenameFlags, openat, renameat, renameat_with, statat,
            unlinkat,
        },
        io::Errno,
    };

    use super::MAX_STATE_BYTES;
    use crate::Result;

    const MAX_PATH_BYTES: usize = 4096;
    const TEMP_ATTEMPTS: usize = 16;
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct Directory {
        path: PathBuf,
        file: File,
        identity: Metadata,
    }

    impl Directory {
        fn open(path: &Path) -> Result<Self> {
            let file = open_directory(path)?;
            let identity = file
                .metadata()
                .map_err(|_| "cannot inspect authority state directory")?;
            validate_directory(&identity)?;
            Ok(Self {
                path: path.to_owned(),
                file,
                identity,
            })
        }

        fn validate(&self) -> Result<()> {
            let held = self
                .file
                .metadata()
                .map_err(|_| "cannot inspect authority state directory")?;
            validate_directory(&held)?;
            let named = open_directory(&self.path)?;
            let named = named
                .metadata()
                .map_err(|_| "cannot inspect authority state directory")?;
            validate_directory(&named)?;
            if !same_inode(&held, &self.identity) || !same_inode(&held, &named) {
                return Err("authority state directory changed");
            }
            Ok(())
        }

        fn still_names(&self, name: &OsString, metadata: &Metadata) -> bool {
            statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|current| {
                // Linux and Darwin expose different stat integer widths.
                #[allow(clippy::unnecessary_cast)]
                let identity = (current.st_dev as u64, current.st_ino as u64);
                identity == (metadata.dev(), metadata.ino())
            })
        }
    }

    fn open_directory(path: &Path) -> Result<File> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = File::from(
            openat(CWD, "/", flags, Mode::empty())
                .map_err(|_| "cannot open authority state directory")?,
        );
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => {
                    directory =
                        File::from(openat(&directory, name, flags, Mode::empty()).map_err(
                            |_| "authority state directory is inaccessible or a symlink",
                        )?);
                }
                _ => return Err("authority state path contains parent traversal"),
            }
        }
        Ok(directory)
    }

    fn validate_directory(metadata: &Metadata) -> Result<()> {
        if !metadata.is_dir()
            || metadata.mode() & 0o7777 != 0o700
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("authority state directory must be owned by this user with mode 0700");
        }
        Ok(())
    }

    fn validate_file(metadata: &Metadata) -> Result<()> {
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err("authority state files must be regular files without hard links");
        }
        if metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("authority state files must be owned by this user with mode 0600");
        }
        Ok(())
    }

    fn same_inode(first: &Metadata, second: &Metadata) -> bool {
        first.dev() == second.dev() && first.ino() == second.ino()
    }

    fn unchanged(first: &Metadata, second: &Metadata) -> bool {
        same_inode(first, second)
            && first.len() == second.len()
            && first.mtime() == second.mtime()
            && first.mtime_nsec() == second.mtime_nsec()
            && first.ctime() == second.ctime()
            && first.ctime_nsec() == second.ctime_nsec()
            && first.mode() == second.mode()
            && first.nlink() == second.nlink()
            && first.uid() == second.uid()
    }

    struct LockedPath {
        directory: Directory,
        name: OsString,
        lock_name: OsString,
        lock: File,
        lock_identity: Metadata,
    }

    impl LockedPath {
        fn acquire(path: &Path, initialize: bool) -> Result<Self> {
            if path.as_os_str().is_empty()
                || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
                || path
                    .components()
                    .any(|part| matches!(part, Component::ParentDir))
            {
                return Err("invalid authority state path");
            }
            let absolute = if path.is_absolute() {
                path.to_owned()
            } else {
                std::env::current_dir()
                    .map_err(|_| "cannot resolve authority state directory")?
                    .join(path)
            };
            let name = absolute
                .file_name()
                .ok_or("authority state path requires a file name")?
                .to_os_string();
            let parent = absolute
                .parent()
                .ok_or("authority state path requires a parent")?;
            let directory = Directory::open(parent)?;
            let mut lock_name = OsString::from(".");
            lock_name.push(&name);
            lock_name.push(".lock");
            let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let (lock, created) = if initialize {
                match openat(
                    &directory.file,
                    &lock_name,
                    flags | OFlags::CREATE | OFlags::EXCL,
                    Mode::RUSR | Mode::WUSR,
                ) {
                    Ok(file) => (File::from(file), true),
                    Err(Errno::EXIST) => (
                        File::from(
                            openat(&directory.file, &lock_name, flags, Mode::empty())
                                .map_err(|_| "authority state lock is inaccessible or a symlink")?,
                        ),
                        false,
                    ),
                    Err(_) => return Err("cannot create authority state lock"),
                }
            } else {
                (
                    File::from(
                        openat(&directory.file, &lock_name, flags, Mode::empty()).map_err(
                            |_| "authority state lock is missing, inaccessible or a symlink",
                        )?,
                    ),
                    false,
                )
            };
            let lock_identity = lock
                .metadata()
                .map_err(|_| "cannot inspect authority state lock")?;
            validate_file(&lock_identity)?;
            if lock_identity.len() != 0 {
                return Err("authority state lock must be empty");
            }
            match lock.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => return Err("authority state is already open"),
                Err(TryLockError::Error(_)) => return Err("cannot lock authority state"),
            }
            let locked = Self {
                directory,
                name,
                lock_name,
                lock,
                lock_identity,
            };
            locked.validate()?;
            if created {
                locked
                    .lock
                    .sync_all()
                    .map_err(|_| "cannot sync authority state lock")?;
                locked
                    .directory
                    .file
                    .sync_all()
                    .map_err(|_| "cannot sync authority state directory")?;
            }
            Ok(locked)
        }

        fn validate(&self) -> Result<()> {
            self.directory.validate()?;
            let metadata = self
                .lock
                .metadata()
                .map_err(|_| "cannot inspect authority state lock")?;
            validate_file(&metadata)?;
            if !unchanged(&metadata, &self.lock_identity)
                || !self.directory.still_names(&self.lock_name, &metadata)
            {
                return Err("authority state lock changed");
            }
            Ok(())
        }

        fn open_state(&self) -> Result<File> {
            Ok(File::from(
                openat(
                    &self.directory.file,
                    &self.name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| "authority state is missing, inaccessible or a symlink")?,
            ))
        }
    }

    impl Drop for LockedPath {
        fn drop(&mut self) {
            // The guard owns the writer lease. Closing its descriptor alone
            // can leave the lock held by a duplicate inherited before exec.
            // If explicit unlock fails, File still closes normally; a remaining
            // duplicate may keep the state unavailable until its final close.
            let _ = self.lock.unlock();
        }
    }

    struct Temporary<'a> {
        directory: &'a Directory,
        name: OsString,
        file: Option<File>,
        moved: bool,
    }

    impl<'a> Temporary<'a> {
        fn create(directory: &'a Directory) -> Result<Self> {
            for _ in 0..TEMP_ATTEMPTS {
                let sequence = NEXT_TEMP
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                    .map_err(|_| "authority temporary name counter exhausted")?;
                let name = OsString::from(format!(
                    ".authority-state-{}-{sequence}.tmp",
                    std::process::id()
                ));
                match openat(
                    &directory.file,
                    &name,
                    OFlags::RDWR
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::NONBLOCK
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                ) {
                    Ok(file) => {
                        return Ok(Self {
                            directory,
                            name,
                            file: Some(File::from(file)),
                            moved: false,
                        });
                    }
                    Err(Errno::EXIST) => continue,
                    Err(_) => return Err("cannot create authority state temporary file"),
                }
            }
            Err("cannot reserve authority state temporary file")
        }

        fn write_and_sync(&mut self, bytes: &[u8]) -> Result<()> {
            let file = self
                .file
                .as_mut()
                .ok_or("authority state temporary file is unavailable")?;
            file.write_all(bytes)
                .map_err(|_| "cannot write authority state temporary file")?;
            file.sync_all()
                .map_err(|_| "cannot sync authority state temporary file")?;
            let metadata = file
                .metadata()
                .map_err(|_| "cannot inspect authority state temporary file")?;
            validate_file(&metadata)?;
            if !self.directory.still_names(&self.name, &metadata) {
                return Err("authority state temporary file changed");
            }
            Ok(())
        }

        fn take_published(&mut self) -> Result<File> {
            self.moved = true;
            self.file
                .take()
                .ok_or("authority state temporary file is unavailable")
        }
    }

    impl Drop for Temporary<'_> {
        fn drop(&mut self) {
            if !self.moved
                && let Some(file) = &self.file
                && let Ok(metadata) = file.metadata()
                && self.directory.still_names(&self.name, &metadata)
            {
                let _ = unlinkat(&self.directory.file, &self.name, AtFlags::empty());
                let _ = self.directory.file.sync_all();
            }
        }
    }

    pub(crate) struct StateStore {
        path: LockedPath,
        // Keeping this inode open prevents its identity being reused while
        // the cooperative writer lock and expected snapshot are retained.
        current: File,
        current_identity: Metadata,
        bytes: Vec<u8>,
    }

    impl fmt::Debug for StateStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.debug_struct("StateStore").finish_non_exhaustive()
        }
    }

    fn validate_bytes(bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Err("authority state must not be empty");
        }
        if bytes.len() > MAX_STATE_BYTES {
            return Err("authority state exceeds size limit");
        }
        Ok(())
    }

    fn read_state(path: &LockedPath, file: &File) -> Result<(Vec<u8>, Metadata)> {
        path.validate()?;
        let before = file
            .metadata()
            .map_err(|_| "cannot inspect authority state")?;
        validate_file(&before)?;
        if before.len() == 0 || before.len() > MAX_STATE_BYTES as u64 {
            return Err("authority state is empty or exceeds size limit");
        }
        // This is a newly opened descriptor per call, so its cursor is not
        // shared with the retained inode or a concurrent bounded reader.
        let mut bytes = Vec::with_capacity((before.len() as usize).min(MAX_STATE_BYTES));
        file.take((MAX_STATE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read authority state")?;
        validate_bytes(&bytes)?;
        let after = file
            .metadata()
            .map_err(|_| "cannot inspect authority state")?;
        validate_file(&after)?;
        if !unchanged(&before, &after) || !path.directory.still_names(&path.name, &after) {
            return Err("authority state changed while it was read");
        }
        path.validate()?;
        Ok((bytes, after))
    }

    impl StateStore {
        pub(crate) fn initialize(path: &Path, bytes: &[u8]) -> Result<Self> {
            validate_bytes(bytes)?;
            let path = LockedPath::acquire(path, true)?;
            match statat(&path.directory.file, &path.name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => return Err("authority state already exists"),
                Err(Errno::NOENT) => {}
                Err(_) => return Err("cannot inspect authority state path"),
            }
            let mut temporary = Temporary::create(&path.directory)?;
            temporary.write_and_sync(bytes)?;
            path.validate()?;
            renameat_with(
                &path.directory.file,
                &temporary.name,
                &path.directory.file,
                &path.name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| "authority state already exists or cannot be installed")?;
            let current = temporary.take_published()?;
            path.directory
                .file
                .sync_all()
                .map_err(|_| "cannot sync authority state directory")?;
            drop(temporary);
            let current_identity = current
                .metadata()
                .map_err(|_| "cannot inspect authority state")?;
            let store = Self {
                path,
                current,
                current_identity,
                bytes: bytes.to_owned(),
            };
            store.load()?;
            Ok(store)
        }

        pub(crate) fn open(path: &Path) -> Result<Self> {
            let path = LockedPath::acquire(path, false)?;
            let current = path.open_state()?;
            let (bytes, current_identity) = read_state(&path, &current)?;
            Ok(Self {
                path,
                current,
                current_identity,
                bytes,
            })
        }

        pub(crate) fn load(&self) -> Result<Vec<u8>> {
            let held = self
                .current
                .metadata()
                .map_err(|_| "cannot inspect authority state")?;
            validate_file(&held)?;
            if !unchanged(&held, &self.current_identity) {
                return Err("authority state changed outside the writer");
            }
            let named = self.path.open_state()?;
            let (bytes, metadata) = read_state(&self.path, &named)?;
            if !unchanged(&metadata, &self.current_identity) || bytes != self.bytes {
                return Err("authority state changed outside the writer");
            }
            Ok(bytes)
        }

        pub(crate) fn replace(&mut self, bytes: &[u8]) -> Result<()> {
            self.replace_observed(bytes, |_| Ok(()))
        }

        // The observer is used only to inject failures/crashes at the actual
        // transaction boundaries in tests; production always supplies a no-op.
        fn replace_observed(
            &mut self,
            bytes: &[u8],
            mut observe: impl FnMut(WriteStage) -> Result<()>,
        ) -> Result<()> {
            validate_bytes(bytes)?;
            self.load()?;
            let mut temporary = Temporary::create(&self.path.directory)?;
            temporary.write_and_sync(bytes)?;
            observe(WriteStage::TemporarySynced)?;
            // Re-read instead of silently repairing an externally edited file.
            self.load()?;
            renameat(
                &self.path.directory.file,
                &temporary.name,
                &self.path.directory.file,
                &self.path.name,
            )
            .map_err(|_| "cannot replace authority state")?;
            let current = temporary.take_published()?;
            observe(WriteStage::Renamed)?;
            self.path
                .directory
                .file
                .sync_all()
                .map_err(|_| "cannot sync authority state directory")?;
            observe(WriteStage::DirectorySynced)?;
            self.path.validate()?;
            let current_identity = current
                .metadata()
                .map_err(|_| "cannot inspect authority state")?;
            validate_file(&current_identity)?;
            if !self
                .path
                .directory
                .still_names(&self.path.name, &current_identity)
            {
                return Err("authority state path changed while it was replaced");
            }
            drop(temporary);
            self.current = current;
            self.current_identity = current_identity;
            self.bytes = bytes.to_owned();
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WriteStage {
        TemporarySynced,
        Renamed,
        DirectorySynced,
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            os::unix::fs::{PermissionsExt, symlink},
            process::Command,
        };

        struct Fixture {
            _directory: tempfile::TempDir,
            directory: PathBuf,
            state: PathBuf,
        }
        impl Fixture {
            fn new() -> Self {
                let temp = tempfile::tempdir().unwrap();
                let directory = fs::canonicalize(temp.path()).unwrap();
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
                let state = directory.join("state.json");
                Self {
                    _directory: temp,
                    directory,
                    state,
                }
            }
        }

        #[test]
        fn explicit_initialization_and_stable_lock_survive_replacement() {
            let fixture = Fixture::new();
            assert!(StateStore::open(&fixture.state).is_err());
            assert!(!fixture.directory.join(".state.json.lock").exists());
            let mut store = StateStore::initialize(&fixture.state, b"old").unwrap();
            let lock_before = fs::metadata(fixture.directory.join(".state.json.lock"))
                .unwrap()
                .ino();
            let state_before = fs::metadata(&fixture.state).unwrap().ino();
            assert!(StateStore::open(&fixture.state).is_err());
            assert!(StateStore::initialize(&fixture.state, b"overwrite").is_err());
            store.replace(b"new").unwrap();
            assert_ne!(state_before, fs::metadata(&fixture.state).unwrap().ino());
            assert_eq!(
                lock_before,
                fs::metadata(fixture.directory.join(".state.json.lock"))
                    .unwrap()
                    .ino()
            );
            assert!(
                StateStore::open(&fixture.state).is_err(),
                "replacement released the writer lock"
            );
            assert_eq!(store.load().unwrap(), b"new");
            drop(store);
            let reopened = StateStore::open(&fixture.state).unwrap();
            assert_eq!(reopened.load().unwrap(), b"new");
            drop(reopened);
            assert!(StateStore::initialize(&fixture.state, b"overwrite").is_err());
        }

        #[test]
        fn writer_guard_releases_lock_while_a_duplicate_descriptor_remains_open() {
            let fixture = Fixture::new();
            let store = StateStore::initialize(&fixture.state, b"old").unwrap();
            let lock_path = fixture.directory.join(".state.json.lock");
            let lock_before = fs::metadata(&lock_path).unwrap();
            // A clone shares the lock's open file description, as does a
            // descriptor inherited by another thread's child before exec.
            let old_duplicate = store.path.lock.try_clone().unwrap();
            assert_eq!(
                StateStore::open(&fixture.state).unwrap_err(),
                "authority state is already open"
            );
            assert_eq!(store.load().unwrap(), b"old");
            drop(store);

            let mut successor = StateStore::open(&fixture.state)
                .expect("dropping the writer must release its lock while a duplicate is open");
            assert_eq!(successor.load().unwrap(), b"old");
            assert!(same_inode(&lock_before, &old_duplicate.metadata().unwrap()));
            drop(old_duplicate);
            assert_eq!(
                StateStore::open(&fixture.state).unwrap_err(),
                "authority state is already open",
                "closing the old duplicate released the successor's writer lock"
            );
            successor.replace(b"new").unwrap();
            assert!(same_inode(&lock_before, &fs::metadata(&lock_path).unwrap()));
            drop(successor);
            assert_eq!(
                StateStore::open(&fixture.state).unwrap().load().unwrap(),
                b"new"
            );
        }

        #[test]
        fn missing_empty_oversized_and_private_path_violations_refuse() {
            let fixture = Fixture::new();
            assert!(StateStore::initialize(&fixture.state, b"").is_err());
            assert!(StateStore::initialize(&fixture.state, &vec![0; MAX_STATE_BYTES + 1]).is_err());
            assert!(
                StateStore::initialize(&fixture.directory.join("../state.json"), b"state").is_err()
            );
            let store = StateStore::initialize(&fixture.state, b"state").unwrap();
            drop(store);
            fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(StateStore::open(&fixture.state).is_err());
            fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o600)).unwrap();
            let hardlink = fixture.directory.join("alias");
            fs::hard_link(&fixture.state, &hardlink).unwrap();
            assert!(StateStore::open(&fixture.state).is_err());
            fs::remove_file(&hardlink).unwrap();
            fs::rename(&fixture.state, &hardlink).unwrap();
            symlink(&hardlink, &fixture.state).unwrap();
            assert!(StateStore::open(&fixture.state).is_err());
            assert!(StateStore::initialize(&fixture.state, b"replace link").is_err());
            fs::remove_file(&fixture.state).unwrap();
            assert!(
                StateStore::open(&fixture.state).is_err(),
                "missing state was recreated"
            );
            fs::rename(&hardlink, &fixture.state).unwrap();
            fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(StateStore::open(&fixture.state).is_err());
        }

        #[test]
        fn external_content_or_lock_replacement_is_not_repaired() {
            let fixture = Fixture::new();
            let mut store = StateStore::initialize(&fixture.state, b"approved").unwrap();
            fs::write(&fixture.state, b"modified").unwrap();
            assert!(store.load().is_err());
            assert!(store.replace(b"overwrite").is_err());
            assert_eq!(fs::read(&fixture.state).unwrap(), b"modified");
            drop(store);
            let mut store = StateStore::open(&fixture.state).unwrap();
            let lock = fixture.directory.join(".state.json.lock");
            fs::rename(&lock, fixture.directory.join("old.lock")).unwrap();
            fs::write(&lock, []).unwrap();
            fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(store.load().is_err());
            assert!(store.replace(b"overwrite").is_err());
            assert_eq!(fs::read(&fixture.state).unwrap(), b"modified");
        }

        #[test]
        fn renamed_parent_is_detected_without_following_replacement() {
            let fixture = Fixture::new();
            let private = fixture.directory.join("private");
            fs::create_dir(&private).unwrap();
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
            let state = private.join("state.json");
            let mut store = StateStore::initialize(&state, b"original").unwrap();
            let moved = fixture.directory.join("moved");
            fs::rename(&private, &moved).unwrap();
            fs::create_dir(&private).unwrap();
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&state, b"replacement").unwrap();
            assert!(store.load().is_err());
            assert!(store.replace(b"overwrite").is_err());
            assert_eq!(fs::read(&state).unwrap(), b"replacement");
            assert_eq!(fs::read(moved.join("state.json")).unwrap(), b"original");
        }

        #[test]
        fn failure_before_and_after_rename_returns_no_success_and_preserves_whole_states() {
            for failed_stage in [
                WriteStage::TemporarySynced,
                WriteStage::Renamed,
                WriteStage::DirectorySynced,
            ] {
                let fixture = Fixture::new();
                let mut store = StateStore::initialize(&fixture.state, b"old-state").unwrap();
                let result = store.replace_observed(b"new-state", |stage| {
                    if stage == failed_stage {
                        Err("injected persistence failure")
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(result, Err("injected persistence failure"));
                let expected: &[u8] = if failed_stage == WriteStage::TemporarySynced {
                    b"old-state"
                } else {
                    b"new-state"
                };
                assert_eq!(fs::read(&fixture.state).unwrap(), expected);
                if failed_stage != WriteStage::TemporarySynced {
                    assert!(store.replace(b"must-not-repair").is_err());
                }
                drop(store);
                assert_eq!(
                    StateStore::open(&fixture.state).unwrap().load().unwrap(),
                    expected
                );
            }
        }

        #[test]
        fn abrupt_exit_never_exposes_a_partial_state_and_releases_the_lock() {
            const CHILD: &str = "AGENTUPLINK_STATE_STORE_CRASH_CASE";
            const STATE: &str = "AGENTUPLINK_STATE_STORE_CRASH_PATH";
            if let Ok(stage) = std::env::var(CHILD) {
                let path = PathBuf::from(std::env::var_os(STATE).unwrap());
                let mut store = StateStore::open(&path).unwrap();
                store
                    .replace_observed(b"new-state", |point| {
                        if format!("{point:?}") == stage {
                            std::process::exit(73);
                        }
                        Ok(())
                    })
                    .unwrap();
                panic!("crash boundary was not reached");
            }
            for point in [
                WriteStage::TemporarySynced,
                WriteStage::Renamed,
                WriteStage::DirectorySynced,
            ] {
                let fixture = Fixture::new();
                drop(StateStore::initialize(&fixture.state, b"old-state").unwrap());
                let output = Command::new(std::env::current_exe().unwrap())
                    .arg("--exact")
                    .arg("state_store::platform::tests::abrupt_exit_never_exposes_a_partial_state_and_releases_the_lock")
                    .arg("--nocapture")
                    .env(CHILD, format!("{point:?}"))
                    .env(STATE, &fixture.state)
                    .output().unwrap();
                assert_eq!(output.status.code(), Some(73));
                let bytes = StateStore::open(&fixture.state).unwrap().load().unwrap();
                let expected: &[u8] = if point == WriteStage::TemporarySynced {
                    b"old-state"
                } else {
                    b"new-state"
                };
                assert_eq!(bytes, expected);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use platform::StateStore;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[derive(Debug)]
pub(crate) struct StateStore;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl StateStore {
    pub(crate) fn initialize(_: &std::path::Path, _: &[u8]) -> crate::Result<Self> {
        Err("durable authority state requires Linux or macOS")
    }
    pub(crate) fn open(_: &std::path::Path) -> crate::Result<Self> {
        Err("durable authority state requires Linux or macOS")
    }
    pub(crate) fn load(&self) -> crate::Result<Vec<u8>> {
        Err("durable authority state requires Linux or macOS")
    }
    pub(crate) fn replace(&mut self, _: &[u8]) -> crate::Result<()> {
        Err("durable authority state requires Linux or macOS")
    }
}
