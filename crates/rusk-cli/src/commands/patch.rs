//! `rusk patch` — modify installed packages.
//!
//! - `rusk patch <package>`: copies the package from node_modules to
//!   `.rusk/patches/<package>/` for editing.
//! - `rusk patch <package> --commit`: generates a diff between the original
//!   and modified copy, saves it to `patches/<package>.patch`, and records
//!   the patched dependency in the manifest so future installs re-apply it.

use clap::Args;
use miette::Result;
use std::path::Path;

/// Patch a package for local modification.
#[derive(Debug, Args)]
pub struct PatchArgs {
    /// Package name to patch.
    pub package: String,

    /// Commit the patch: generate a diff and save it.
    #[arg(long)]
    pub commit: bool,
}

pub async fn run(args: PatchArgs) -> Result<()> {
    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {e}"))?;
    let patches_work_dir = project_dir.join(".rusk").join("patches");

    if args.commit {
        // Generate diff between the installed version and the patched copy.
        let pkg_dir = project_dir.join("node_modules").join(&args.package);
        let patch_dir = patches_work_dir.join(&args.package);

        if !patch_dir.exists() {
            return Err(miette::miette!(
                "No patch working directory found at {}. Run `rusk patch {}` first.",
                patch_dir.display(),
                args.package
            ));
        }

        if !pkg_dir.exists() {
            return Err(miette::miette!(
                "Package {} not found in node_modules. Run `rusk install` first.",
                args.package
            ));
        }

        // Generate the diff.
        // On Unix we use `diff -ruN`; on Windows we do a simple file-by-file
        // comparison and produce a unified-style diff ourselves.
        let diff_output = generate_diff(&pkg_dir, &patch_dir)?;

        // Save the patch file.
        let patch_file = project_dir
            .join("patches")
            .join(format!("{}.patch", args.package));
        std::fs::create_dir_all(patch_file.parent().unwrap())
            .map_err(|e| miette::miette!("failed to create patches dir: {e}"))?;
        std::fs::write(&patch_file, &diff_output)
            .map_err(|e| miette::miette!("failed to write patch file: {e}"))?;

        println!("Patch saved to patches/{}.patch", args.package);
        println!("This patch will be applied on future installs.");

        // Update the manifest to record the patched dependency.
        update_manifest_patched_deps(&project_dir, &args.package)?;
    } else {
        // Copy the package to the patches working directory for editing.
        let src = project_dir.join("node_modules").join(&args.package);
        if !src.exists() {
            return Err(miette::miette!(
                "Package {} not found in node_modules. Run `rusk install` first.",
                args.package
            ));
        }

        std::fs::create_dir_all(&patches_work_dir)
            .map_err(|e| miette::miette!("failed to create patches dir: {e}"))?;

        let dst = patches_work_dir.join(&args.package);
        if dst.exists() {
            std::fs::remove_dir_all(&dst)
                .map_err(|e| miette::miette!("failed to remove old patch dir: {e}"))?;
        }

        copy_dir_recursive(&src, &dst)
            .map_err(|e| miette::miette!("failed to copy package: {e}"))?;

        println!("Package copied to .rusk/patches/{}/", args.package);
        println!(
            "Edit the files, then run: rusk patch {} --commit",
            args.package
        );
    }

    Ok(())
}

/// Generate a diff between `original` and `modified` directories.
///
/// On Unix, shells out to `diff -ruN`. On Windows (or if diff is unavailable),
/// falls back to a simple file-level comparison that produces a minimal
/// unified-style output.
fn generate_diff(original: &Path, modified: &Path) -> Result<Vec<u8>> {
    // Try shelling out to `diff` first.
    let result = std::process::Command::new("diff")
        .args([
            "-ruN",
            &original.to_string_lossy(),
            &modified.to_string_lossy(),
        ])
        .output();

    match result {
        Ok(output) => {
            // diff exits 0 (no diff) or 1 (differences found); both are fine.
            // Exit code 2 means trouble.
            if output.status.code() == Some(2) {
                return Err(miette::miette!(
                    "diff command failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Ok(output.stdout)
        }
        Err(_) => {
            // `diff` not available — produce a simple manifest of changed files.
            let mut buf = format!(
                "# rusk patch diff (fallback — `diff` not available)\n\
                 # original: {}\n\
                 # modified: {}\n",
                original.display(),
                modified.display()
            )
            .into_bytes();

            collect_file_changes(original, modified, original, modified, &mut buf)
                .map_err(|e| miette::miette!("failed to generate diff: {e}"))?;

            Ok(buf)
        }
    }
}

/// Walk both trees and append simple change records for any differing files.
fn collect_file_changes(
    orig_root: &Path,
    mod_root: &Path,
    orig_dir: &Path,
    mod_dir: &Path,
    buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    if mod_dir.is_dir() {
        for entry in std::fs::read_dir(mod_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let mod_path = mod_dir.join(&name);
            let orig_path = orig_dir.join(&name);

            if mod_path.is_dir() {
                collect_file_changes(orig_root, mod_root, &orig_path, &mod_path, buf)?;
            } else {
                let rel = mod_path.strip_prefix(mod_root).unwrap_or(&mod_path);
                let mod_contents = std::fs::read(&mod_path).unwrap_or_default();
                let orig_contents = if orig_path.exists() {
                    std::fs::read(&orig_path).unwrap_or_default()
                } else {
                    Vec::new()
                };
                if mod_contents != orig_contents {
                    buf.extend_from_slice(
                        format!("--- a/{}\n+++ b/{}\n", rel.display(), rel.display()).as_bytes(),
                    );
                    if !orig_path.exists() {
                        buf.extend_from_slice(b"# new file\n");
                    }
                }
            }
        }
    }
    Ok(())
}

/// Add the package to `[js_dependencies.patched_dependencies]` in rusk.toml.
fn update_manifest_patched_deps(project_dir: &Path, package: &str) -> Result<()> {
    let manifest_path = project_dir.join("rusk.toml");
    if !manifest_path.exists() {
        // Nothing to update — the user may be using package.json only.
        return Ok(());
    }

    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| miette::miette!("failed to read rusk.toml: {e}"))?;

    let mut doc: toml::Value = toml::from_str(&content)
        .map_err(|e| miette::miette!("failed to parse rusk.toml: {e}"))?;

    // Ensure js_dependencies exists.
    let js_deps = doc
        .as_table_mut()
        .ok_or_else(|| miette::miette!("invalid rusk.toml: expected table"))?
        .entry("js_dependencies")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));

    let js_table = js_deps
        .as_table_mut()
        .ok_or_else(|| miette::miette!("js_dependencies is not a table"))?;

    let patched = js_table
        .entry("patched_dependencies")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));

    let patched_table = patched
        .as_table_mut()
        .ok_or_else(|| miette::miette!("patched_dependencies is not a table"))?;

    patched_table.insert(
        package.to_string(),
        toml::Value::String(format!("patches/{}.patch", package)),
    );

    let updated = toml::to_string_pretty(&doc)
        .map_err(|e| miette::miette!("failed to serialize rusk.toml: {e}"))?;
    std::fs::write(&manifest_path, updated)
        .map_err(|e| miette::miette!("failed to write rusk.toml: {e}"))?;

    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let d = dst.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_recursive(&entry.path(), &d)?;
        } else {
            std::fs::copy(entry.path(), &d)?;
        }
    }
    Ok(())
}
