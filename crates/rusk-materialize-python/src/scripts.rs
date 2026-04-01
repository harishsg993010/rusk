//! Script/entry point installation for Python packages.
//!
//! Handles creating wrapper scripts in the virtualenv's bin/ directory
//! for console_scripts and gui_scripts entry points declared by packages.

use std::io;
use std::path::{Path, PathBuf};

/// An entry point declared by a Python package.
#[derive(Clone, Debug)]
pub struct EntryPoint {
    /// Name of the script (becomes the filename in bin/).
    pub name: String,
    /// Module path (e.g., "mypackage.cli").
    pub module: String,
    /// Function name (e.g., "main").
    pub function: String,
    /// Whether this is a GUI script (vs console script).
    pub gui: bool,
}

impl EntryPoint {
    /// Parse an entry point from the standard format: "name = module:function".
    pub fn parse(spec: &str) -> Option<Self> {
        let (name, rest) = spec.split_once('=')?;
        let rest = rest.trim();
        let (module, function) = rest.split_once(':')?;
        Some(Self {
            name: name.trim().to_string(),
            module: module.trim().to_string(),
            function: function.trim().to_string(),
            gui: false,
        })
    }
}

/// Install script wrappers for entry points into the virtualenv bin directory.
pub fn install_scripts(
    bin_dir: &Path,
    python_path: &Path,
    entry_points: &[EntryPoint],
) -> io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(bin_dir)?;
    let mut installed = Vec::new();

    for ep in entry_points {
        let script_path = bin_dir.join(&ep.name);
        let content = generate_script_content(python_path, &ep.module, &ep.function);
        std::fs::write(&script_path, &content)?;

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))?;
        }

        installed.push(script_path);
    }

    Ok(installed)
}

/// Generate the content of a wrapper script.
fn generate_script_content(python_path: &Path, module: &str, function: &str) -> String {
    let python = python_path.to_string_lossy();

    if cfg!(target_os = "windows") {
        // Windows .exe wrapper would be more complex; this is a .py launcher
        format!(
            "#!{python}\nimport sys\nfrom {module} import {function}\nsys.exit({function}())\n"
        )
    } else {
        format!(
            "#!/usr/bin/env {python}\nimport sys\nfrom {module} import {function}\nsys.exit({function}())\n"
        )
    }
}
