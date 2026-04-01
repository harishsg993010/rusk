//! `rusk gc` command.
//!
//! Runs garbage collection on the content-addressed store,
//! removing unreferenced blobs to reclaim disk space.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;
use std::collections::HashSet;

/// Arguments for the gc command.
#[derive(Debug, Args)]
pub struct GcArgs {
    /// Dry-run: show what would be deleted without actually deleting.
    #[arg(long)]
    pub dry_run: bool,

    /// Also run integrity verification on remaining blobs.
    #[arg(long)]
    pub verify: bool,
}

pub async fn run(args: GcArgs) -> Result<()> {
    tracing::info!(dry_run = args.dry_run, "starting garbage collection");

    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let config = OrchestratorConfig::for_project(project_dir);

    // Open CAS
    let cas_dir = &config.cas_dir;
    if !cas_dir.exists() {
        crate::output::print_info("No CAS directory found. Nothing to collect.");
        return Ok(());
    }

    let cas = rusk_cas::CasStore::open(cas_dir)
        .map_err(|e| miette::miette!("failed to open CAS: {}", e))?;

    let spinner = crate::output::create_spinner("Scanning CAS store...");

    // Walk the CAS directory to find all blobs
    let mut total_size: u64 = 0;
    let mut total_blobs: u64 = 0;
    let mut blob_digests: Vec<(rusk_core::Sha256Digest, u64)> = Vec::new();

    // Walk the shard directories
    let layout = rusk_cas::StoreLayout::new(cas_dir.clone());
    if let Ok(shards) = layout.list_shards() {
        for shard_dir in shards {
            if let Ok(entries) = std::fs::read_dir(&shard_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(meta) = std::fs::metadata(&path) {
                            let size = meta.len();
                            total_size += size;
                            total_blobs += 1;

                            // Try to parse the filename as a hex digest
                            if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
                                if let Ok(digest) = rusk_core::Sha256Digest::from_hex(filename) {
                                    blob_digests.push((digest, size));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Determine which blobs are referenced by the lockfile
    let mut referenced: HashSet<rusk_core::Sha256Digest> = HashSet::new();
    let lockfile_path = config.lockfile_path();
    if lockfile_path.exists() {
        if let Ok(lockfile) = rusk_lockfile::load_lockfile(&lockfile_path) {
            for (_id, pkg) in &lockfile.packages {
                referenced.insert(pkg.digest);
            }
        }
    }

    // Find unreferenced blobs
    let unreferenced: Vec<(rusk_core::Sha256Digest, u64)> = blob_digests
        .iter()
        .filter(|(digest, _)| !referenced.contains(digest))
        .cloned()
        .collect();

    let unreferenced_size: u64 = unreferenced.iter().map(|(_, s)| *s).sum();

    spinner.finish_and_clear();

    // Print summary
    crate::output::print_info(&format!(
        "CAS store: {} blobs, {} total",
        total_blobs,
        format_bytes(total_size)
    ));
    crate::output::print_info(&format!(
        "Referenced: {} blobs",
        referenced.len()
    ));
    crate::output::print_info(&format!(
        "Unreferenced: {} blobs ({})",
        unreferenced.len(),
        format_bytes(unreferenced_size)
    ));

    if unreferenced.is_empty() {
        crate::output::print_success("Nothing to collect.");
        return Ok(());
    }

    if args.dry_run {
        crate::output::print_info("Dry run: the following blobs would be deleted:");
        for (digest, size) in &unreferenced {
            crate::output::print_info(&format!(
                "  {} ({})",
                digest.to_hex(),
                format_bytes(*size)
            ));
        }
        crate::output::print_success(&format!(
            "gc dry-run complete: would reclaim {}",
            format_bytes(unreferenced_size)
        ));
    } else {
        let delete_spinner = crate::output::create_spinner("Deleting unreferenced blobs...");
        let mut deleted = 0u64;
        let mut reclaimed = 0u64;

        for (digest, size) in &unreferenced {
            if let Ok(true) = cas.delete(digest) {
                deleted += 1;
                reclaimed += size;
            }
        }

        delete_spinner.finish_and_clear();

        crate::output::print_success(&format!(
            "gc complete: deleted {} blobs, reclaimed {}",
            deleted,
            format_bytes(reclaimed)
        ));
    }

    // Optional integrity verification
    if args.verify {
        let verify_spinner = crate::output::create_spinner("Verifying blob integrity...");
        let mut verified = 0u64;
        let mut corrupt = 0u64;

        for (digest, _size) in &blob_digests {
            if referenced.contains(digest) {
                if let Ok(Some(data)) = cas.read(digest) {
                    let computed = rusk_core::Sha256Digest::compute(&data);
                    if computed == *digest {
                        verified += 1;
                    } else {
                        corrupt += 1;
                        crate::output::print_error(&format!(
                            "Corrupt blob: {} (expected {}, computed {})",
                            digest.to_hex(),
                            digest.to_hex(),
                            computed.to_hex()
                        ));
                    }
                }
            }
        }

        verify_spinner.finish_and_clear();

        if corrupt > 0 {
            crate::output::print_warning(&format!(
                "Integrity check: {verified} OK, {corrupt} corrupt"
            ));
        } else {
            crate::output::print_success(&format!(
                "Integrity check: all {verified} referenced blobs OK"
            ));
        }
    }

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
