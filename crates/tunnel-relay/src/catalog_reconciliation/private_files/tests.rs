use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;

use super::{NewFile, read};

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        // Darwin's temporary parent may be a symlink; pin its real path first.
        let parent = std::env::temp_dir().canonicalize().expect("temporary root");
        let path = parent.join(format!("catalog-private-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).expect("directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn private_file_roundtrip_is_create_only_and_bounded() {
    let directory = Directory::new();
    let path = directory.0.join("input");
    let mut output = NewFile::create(&path).expect("create");
    output.write_and_sync(b"abcd").expect("sync");
    output.commit();
    drop(output);
    assert_eq!(read(&path, 4).expect("read"), b"abcd");
    assert!(read(&path, 3).is_err());
    assert!(NewFile::create(&path).is_err());
    let metadata = fs::metadata(&path).expect("metadata");
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
}

#[test]
fn private_file_permissions_links_ancestors_and_traversal_are_refused() {
    let directory = Directory::new();
    let path = directory.0.join("input");
    let mut output = NewFile::create(&path).expect("create");
    output.write_and_sync(b"private").expect("sync");
    output.commit();
    drop(output);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("mode");
    assert!(read(&path, 10).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    let alias = directory.0.join("alias");
    fs::hard_link(&path, &alias).expect("hard link");
    assert!(read(&path, 10).is_err());
    fs::remove_file(&alias).expect("remove alias");
    symlink(&path, &alias).expect("symlink");
    assert!(read(&alias, 10).is_err());
    assert!(NewFile::create(&alias).is_err());
    let ancestor = directory.0.join("ancestor");
    symlink(&directory.0, &ancestor).expect("ancestor symlink");
    assert!(read(&ancestor.join("input"), 10).is_err());
    assert!(NewFile::create(&ancestor.join("output")).is_err());
    assert!(read(&directory.0.join("../input"), 10).is_err());
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o750)).expect("mode");
    assert!(read(&path, 10).is_err());
    assert!(NewFile::create(&directory.0.join("output")).is_err());
}

#[test]
fn private_file_uncommitted_cleanup_never_removes_a_replacement_inode() {
    let directory = Directory::new();
    let path = directory.0.join("output");
    let output = NewFile::create(&path).expect("create");
    fs::remove_file(&path).expect("unlink original");
    fs::write(&path, b"replacement").expect("replacement");
    drop(output);
    assert_eq!(fs::read(&path).expect("preserved"), b"replacement");
    fs::remove_file(&path).expect("remove");
    drop(NewFile::create(&path).expect("new uncommitted"));
    assert!(!path.exists());
}

#[test]
fn private_file_parent_rename_cannot_redirect_the_pinned_writer() {
    let directory = Directory::new();
    let original = directory.0.join("original");
    fs::create_dir(&original).expect("directory");
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).expect("mode");
    let mut output = NewFile::create(&original.join("output")).expect("create");
    let moved = directory.0.join("moved");
    fs::rename(&original, &moved).expect("rename");
    fs::create_dir(&original).expect("replacement directory");
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).expect("mode");
    output
        .write_and_sync(b"pinned")
        .expect("sync pinned directory");
    output.commit();
    assert_eq!(
        fs::read(moved.join("output")).expect("original inode"),
        b"pinned"
    );
    assert!(!original.join("output").exists());
}
