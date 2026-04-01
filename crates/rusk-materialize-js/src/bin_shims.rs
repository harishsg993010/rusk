//! Bin shim generation for node_modules/.bin/.
//!
//! Creates executable shims in node_modules/.bin/ that proxy to the
//! actual scripts declared in package.json "bin" fields.

use std::io;
use std::path::{Path, PathBuf};

/// A binary entry from a package's "bin" field.
#[derive(Clone, Debug)]
pub struct BinEntry {
    /// Name of the binary (becomes the shim filename).
    pub name: String,
    /// Relative path to the script file within the package.
    pub script_path: String,
    /// Absolute path to the package directory.
    pub package_dir: PathBuf,
}

/// Install bin shims for the given entries.
pub fn install_bin_shims(bin_dir: &Path, entries: &[BinEntry]) -> io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(bin_dir)?;
    let mut created = Vec::new();

    for entry in entries {
        let target = entry.package_dir.join(&entry.script_path);
        let shim_path = bin_dir.join(&entry.name);

        // On Unix, create a shell script shim
        #[cfg(unix)]
        {
            let content = format!(
                "#!/bin/sh\nexec node \"{}\" \"$@\"\n",
                target.to_string_lossy()
            );
            std::fs::write(&shim_path, content)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o755))?;
        }

        // On Windows, create a .cmd shim
        #[cfg(windows)]
        {
            let cmd_path = shim_path.with_extension("cmd");
            let content = format!(
                "@node \"{}\" %*\r\n",
                target.to_string_lossy()
            );
            std::fs::write(&cmd_path, content)?;
            created.push(cmd_path);
        }

        created.push(shim_path);
    }

    Ok(created)
}
