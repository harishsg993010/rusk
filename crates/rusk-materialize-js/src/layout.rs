//! JS materialization layout.
//!
//! Computes and executes the node_modules directory layout. Supports two
//! modes: a flat "hoisted" layout (like npm/yarn) and a virtual store
//! layout (like pnpm) that uses symlinks for deduplication.

use rusk_cas::CasStore;
use rusk_core::{PackageId, Sha256Digest, Version};
use rusk_materialize::linker::{self, LinkStrategy};
use rusk_materialize::planner::{FileType, MaterializationEntry, MaterializationPlan};
use rusk_materialize::state::InstallState;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, instrument};

/// Layout mode for node_modules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsLayoutMode {
    /// Standard hoisted layout: packages at `node_modules/<name>`.
    Hoisted,
    /// Virtual store layout: packages at `node_modules/.rusk/<name>@<version>/node_modules/<name>`,
    /// with symlinks from `node_modules/<name>` -> `.rusk/...`.
    VirtualStore,
}

impl Default for JsLayoutMode {
    fn default() -> Self {
        JsLayoutMode::VirtualStore
    }
}

/// Materializes packages into a node_modules directory.
pub struct JsMaterializer {
    /// Root project directory.
    project_dir: PathBuf,
    /// Layout mode.
    mode: JsLayoutMode,
    /// Link strategy for placing files.
    link_strategy: LinkStrategy,
    /// CAS store reference.
    cas: Arc<CasStore>,
}

impl JsMaterializer {
    /// Create a new JS materializer.
    pub fn new(project_dir: PathBuf, cas: Arc<CasStore>, mode: JsLayoutMode) -> Self {
        let node_modules = project_dir.join("node_modules");
        let link_strategy = linker::detect_link_strategy(cas.root(), &node_modules);

        Self {
            project_dir,
            mode,
            link_strategy,
            cas,
        }
    }

    /// The node_modules directory path.
    pub fn node_modules_dir(&self) -> PathBuf {
        self.project_dir.join("node_modules")
    }

    /// The virtual store directory (`.rusk` inside node_modules).
    pub fn virtual_store_dir(&self) -> PathBuf {
        self.node_modules_dir().join(".rusk")
    }

    /// Compute a materialization plan for the given packages.
    #[instrument(skip(self, packages))]
    pub fn plan(
        &self,
        packages: &[(PackageId, Version, Sha256Digest)],
        current_state: &InstallState,
    ) -> MaterializationPlan {
        let mut plan = MaterializationPlan::new(self.node_modules_dir());

        for (package, version, digest) in packages {
            if current_state.is_up_to_date(package, version, digest) {
                plan.mark_up_to_date();
                continue;
            }

            let relative_path = match self.mode {
                JsLayoutMode::Hoisted => {
                    // node_modules/<name>
                    PathBuf::from(package.display_name())
                }
                JsLayoutMode::VirtualStore => {
                    // node_modules/.rusk/<name>@<version>/node_modules/<name>
                    let store_name = format!("{}@{}", package.display_name(), version);
                    PathBuf::from(".rusk")
                        .join(&store_name)
                        .join("node_modules")
                        .join(package.display_name())
                }
            };

            let entry = self.cas.entry(digest);
            let size = entry
                .ok()
                .flatten()
                .map(|e| e.size)
                .unwrap_or(0);

            plan.add_entry(MaterializationEntry {
                package: package.clone(),
                version: version.clone(),
                digest: *digest,
                relative_path,
                file_type: FileType::ExtractedArchive,
                size,
                depth: 0,
            });
        }

        plan.sort_by_depth();
        info!(
            pending = plan.pending_count(),
            up_to_date = plan.up_to_date,
            mode = ?self.mode,
            "JS materialization plan computed"
        );

        plan
    }

    /// Execute a materialization plan.
    #[instrument(skip(self, plan))]
    pub fn execute(&self, plan: &MaterializationPlan) -> io::Result<InstallState> {
        let node_modules = self.node_modules_dir();
        std::fs::create_dir_all(&node_modules)?;

        if self.mode == JsLayoutMode::VirtualStore {
            std::fs::create_dir_all(self.virtual_store_dir())?;
        }

        let mut state = InstallState::new();

        for entry in &plan.entries {
            let target = node_modules.join(&entry.relative_path);
            debug!(
                package = %entry.package,
                target = %target.display(),
                strategy = ?self.link_strategy,
                "materializing JS package"
            );

            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Read the archive from CAS and extract it
            if let Some(data) = self.cas.read(&entry.digest)? {
                // In a real implementation, this would extract the tarball.
                // For now, write the raw data as a placeholder.
                std::fs::create_dir_all(&target)?;
                std::fs::write(target.join(".rusk-cas-digest"), entry.digest.to_hex())?;
            }

            // Create symlink in hoisted position if using virtual store mode
            if self.mode == JsLayoutMode::VirtualStore {
                let hoisted = node_modules.join(entry.package.display_name());
                if !hoisted.exists() {
                    if let Some(parent) = hoisted.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    // Create a directory junction / symlink
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&target, &hoisted)?;
                    #[cfg(windows)]
                    std::os::windows::fs::symlink_dir(&target, &hoisted)?;
                }
            }

            state.record_install(
                entry.package.clone(),
                entry.version.clone(),
                entry.digest,
                target,
            );
        }

        info!(
            installed = state.packages.len(),
            "JS materialization complete"
        );

        Ok(state)
    }
}
