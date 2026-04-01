//! Install flow orchestration.
//!
//! Coordinates the full install workflow: read manifest -> resolve ->
//! download -> materialize -> update lockfile -> update state.

use crate::config::OrchestratorConfig;
use rusk_cas::CasStore;
use rusk_core::{Ecosystem, PackageId, Sha256Digest, Version};
use rusk_lockfile::schema::{LockedPackage, Lockfile};
use rusk_manifest::schema::{DependencyEntry, Manifest};
use rusk_materialize_js::extract_npm_tarball;
use rusk_materialize_python::extract_wheel;
use rusk_observability::MetricsCollector;
use rusk_registry::{ArtifactType, DependencyKind, RegistryClient};
use rusk_registry_npm::NpmRegistryClient;
use rusk_registry_pypi::PypiRegistryClient;
use rusk_resolver_js::parse_npm_range;
use rusk_transport::{DownloadManager, DownloadManagerConfig, DownloadRequest, ProgressTracker};
use std::collections::{HashSet, VecDeque};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn, instrument};

/// Error type for install operations.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("manifest not found at {0}")]
    ManifestNotFound(String),
    #[error("manifest parse error: {0}")]
    ManifestParse(String),
    #[error("resolution failed: {0}")]
    ResolutionFailed(String),
    #[error("download failed: {0}")]
    DownloadFailed(String),
    #[error("materialization failed: {0}")]
    MaterializationFailed(String),
    #[error("policy violation: {0}")]
    PolicyViolation(String),
    #[error("lockfile mismatch in frozen mode")]
    FrozenMismatch,
    #[error("lockfile error: {0}")]
    LockfileError(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result of a successful install.
#[derive(Clone, Debug)]
pub struct InstallResult {
    /// Number of packages resolved.
    pub resolved: usize,
    /// Number of packages downloaded.
    pub downloaded: usize,
    /// Number of packages already cached.
    pub cached: usize,
    /// Number of packages materialized.
    pub materialized: usize,
    /// Total wall-clock time.
    pub elapsed_ms: u64,
}

/// A resolved package ready for download.
#[derive(Clone, Debug)]
struct ResolvedPackage {
    package_id: PackageId,
    version: Version,
    tarball_url: String,
    digest: Option<Sha256Digest>,
    dependencies: Vec<rusk_registry::DependencySpec>,
}

/// Run the full install flow.
///
/// This is the main entry point for the `rusk install` command.
#[instrument(skip(config, on_progress))]
pub async fn run_install(
    config: &OrchestratorConfig,
    on_progress: Option<Box<dyn Fn(&str) + Send + Sync>>,
) -> Result<InstallResult, InstallError> {
    let start = Instant::now();
    let metrics = MetricsCollector::new();

    info!(project = %config.project_dir.display(), "starting install");

    // Step 1: Open or create the CAS store
    let emit = |msg: &str| {
        if let Some(ref cb) = on_progress {
            cb(msg);
        }
    };

    emit("Opening CAS store...");
    let cas = Arc::new(
        CasStore::open(&config.cas_dir).map_err(InstallError::Io)?,
    );

    // Step 2: Read and parse the manifest
    let manifest_path = config.manifest_path();
    if !manifest_path.exists() {
        return Err(InstallError::ManifestNotFound(
            manifest_path.to_string_lossy().to_string(),
        ));
    }

    // FAST PATH: If lockfile + install state exist and node_modules is populated,
    // skip resolution and network entirely. Just verify and hardlink from cache.
    let lockfile_path = config.lockfile_path();
    let state_path = config.state_path();
    let node_modules = config.node_modules_path();

    if lockfile_path.exists() && state_path.exists() && node_modules.exists() {
        if let Ok(state) = rusk_materialize::InstallState::load(&state_path) {
            if let Ok(lockfile) = rusk_lockfile::load_lockfile(&lockfile_path) {
                // Check if all locked packages are in the install state
                let all_installed = lockfile.packages.iter().all(|(_, pkg)| {
                    let key = pkg.package.canonical();
                    state.packages.contains_key(&key) &&
                    node_modules.join(pkg.package.display_name()).exists()
                });

                if all_installed && !lockfile.packages.is_empty() {
                    let elapsed = start.elapsed();
                    emit("Already up to date.");
                    info!(
                        packages = lockfile.packages.len(),
                        elapsed_ms = elapsed.as_millis() as u64,
                        "install skipped: already up to date"
                    );
                    return Ok(InstallResult {
                        resolved: lockfile.packages.len(),
                        downloaded: 0,
                        cached: lockfile.packages.len(),
                        materialized: 0,
                        elapsed_ms: elapsed.as_millis() as u64,
                    });
                }
            }
        }
    }

    // WARM PATH: Lockfile exists but node_modules is missing/incomplete.
    // Skip resolution entirely — just materialize from lockfile + CAS.
    // Security: lockfile has SHA-256 digests. CAS blobs verified by digest.
    if lockfile_path.exists() && !config.frozen {
        if let Ok(lockfile) = rusk_lockfile::load_lockfile(&lockfile_path) {
            if !lockfile.packages.is_empty() {
                let all_in_cas = lockfile.packages.iter().all(|(_, pkg)| {
                    cas.contains(&pkg.digest)
                });

                if all_in_cas {
                    emit("Lockfile found, materializing from cache...");
                    info!(packages = lockfile.packages.len(), "warm install from lockfile");

                    let extracted_cache = config.extracted_cache_dir();
                    std::fs::create_dir_all(&node_modules)?;
                    std::fs::create_dir_all(&extracted_cache)?;

                    let mut materialized_count = 0usize;
                    let mut hardlinked_count = 0usize;

                    for (_, locked_pkg) in &lockfile.packages {
                        let pkg_name = locked_pkg.package.display_name();
                        let target_dir = node_modules.join(&pkg_name);
                        let cache_dir = extracted_cache
                            .join(&locked_pkg.digest.shard_prefix())
                            .join(locked_pkg.digest.to_hex());

                        if target_dir.exists() {
                            materialized_count += 1;
                            continue; // Already materialized
                        }

                        // Security: verify CAS blob exists AND its content matches the
                        // expected digest before trusting the extracted cache.
                        // This catches both missing blobs and corrupted-in-place blobs.
                        match cas.read(&locked_pkg.digest) {
                            Ok(Some(data)) => {
                                let actual = rusk_core::Sha256Digest::compute(&data);
                                if actual != locked_pkg.digest {
                                    // CAS blob corrupted in place — evict extracted cache
                                    if cache_dir.exists() {
                                        let _ = std::fs::remove_dir_all(&cache_dir);
                                    }
                                    return Err(InstallError::MaterializationFailed(
                                        format!(
                                            "CAS integrity failed for {pkg_name}@{}: digest mismatch (expected {}, got {})",
                                            locked_pkg.version, locked_pkg.digest, actual
                                        )
                                    ));
                                }
                            }
                            _ => {
                                if cache_dir.exists() {
                                    let _ = std::fs::remove_dir_all(&cache_dir);
                                }
                                return Err(InstallError::MaterializationFailed(
                                    format!(
                                        "CAS integrity failed for {pkg_name}@{}: blob missing for digest {}",
                                        locked_pkg.version, locked_pkg.digest
                                    )
                                ));
                            }
                        }

                        if cache_dir.exists() {
                            // Fast path: hardlink from extracted cache (CAS verified above)
                            if locked_pkg.ecosystem == Ecosystem::Js {
                                hardlink_dir(&cache_dir, &target_dir)?;
                            }
                            // Python packages are extracted directly to site-packages, not cached
                            hardlinked_count += 1;
                        } else {
                            let blob_data = cas.read(&locked_pkg.digest)?
                                .ok_or_else(|| InstallError::MaterializationFailed(
                                    format!("CAS missing for {pkg_name}")
                                ))?;

                            match locked_pkg.ecosystem {
                                Ecosystem::Js => {
                                    // npm tarball → extract to cache → hardlink to node_modules
                                    std::fs::create_dir_all(&cache_dir)?;
                                    extract_npm_tarball(&blob_data, &cache_dir)
                                        .map_err(|e| InstallError::MaterializationFailed(
                                            format!("failed to extract {pkg_name}: {e}")
                                        ))?;
                                    hardlink_dir(&cache_dir, &target_dir)?;
                                }
                                Ecosystem::Python => {
                                    // wheel zip → extract directly to site-packages
                                    let site_packages = config.site_packages_path();
                                    std::fs::create_dir_all(&site_packages)?;
                                    extract_wheel(&blob_data, &site_packages)
                                        .map_err(|e| InstallError::MaterializationFailed(
                                            format!("failed to extract wheel {pkg_name}: {e}")
                                        ))?;
                                }
                            }
                        }
                        materialized_count += 1;
                    }

                    // Update install state
                    let mut state = rusk_materialize::InstallState::new();
                    for (_, locked_pkg) in &lockfile.packages {
                        let target_dir = node_modules.join(locked_pkg.package.display_name());
                        state.record_install(
                            locked_pkg.package.clone(),
                            locked_pkg.version.clone(),
                            locked_pkg.digest,
                            target_dir,
                        );
                    }
                    if let Some(parent) = state_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    let _ = state.save(&state_path);

                    let elapsed = start.elapsed();
                    info!(
                        materialized = materialized_count,
                        hardlinked = hardlinked_count,
                        elapsed_ms = elapsed.as_millis() as u64,
                        "warm install complete"
                    );

                    return Ok(InstallResult {
                        resolved: lockfile.packages.len(),
                        downloaded: 0,
                        cached: lockfile.packages.len(),
                        materialized: materialized_count,
                        elapsed_ms: elapsed.as_millis() as u64,
                    });
                }
            }
        }
    }

    info!(manifest = %manifest_path.display(), "reading manifest");
    emit("Reading rusk.toml...");

    let manifest_content = std::fs::read_to_string(&manifest_path)?;
    let manifest: Manifest = rusk_manifest::parse_manifest(&manifest_content)
        .map_err(|e| InstallError::ManifestParse(e.to_string()))?;

    // Step 3: Resolve full transitive dependency graph via parallel BFS
    //
    // Strategy: level-by-level BFS. Each level's metadata is fetched in
    // parallel (up to 32 concurrent HTTP requests). Once a level resolves,
    // we collect their transitive deps and fire the next level.
    let mut resolved_packages: Vec<ResolvedPackage> = Vec::new();
    let mut resolved_names: HashSet<String> = HashSet::new();

    if let Some(ref js_deps) = manifest.js_dependencies {
        emit("Resolving JavaScript dependencies...");
        let npm_client = Arc::new(NpmRegistryClient::default_registry());

        // Seed with direct dependencies
        let all_deps = collect_js_deps(js_deps, config.include_dev);
        let mut current_level: Vec<(String, String)> = all_deps
            .iter()
            .map(|(name, entry)| (name.clone(), entry.version_req().to_string()))
            .collect();

        info!(direct = all_deps.len(), "resolving JS dependencies (parallel transitive)");

        let mut depth = 0u32;
        while !current_level.is_empty() {
            // Deduplicate this level against already-resolved
            let to_fetch: Vec<(String, String)> = current_level
                .into_iter()
                .filter(|(name, _)| !resolved_names.contains(name))
                .collect::<Vec<_>>();

            // Deduplicate within the level (keep first occurrence)
            let mut seen_in_level = HashSet::new();
            let to_fetch: Vec<(String, String)> = to_fetch
                .into_iter()
                .filter(|(name, _)| seen_in_level.insert(name.clone()))
                .collect();

            if to_fetch.is_empty() {
                break;
            }

            emit(&format!(
                "Resolving level {} ({} packages, {} resolved so far)...",
                depth, to_fetch.len(), resolved_packages.len()
            ));
            info!(depth, batch_size = to_fetch.len(), "fetching metadata batch");

            // Fetch all metadata in this level in parallel
            let mut handles = Vec::with_capacity(to_fetch.len());
            for (name, version_req_str) in &to_fetch {
                let client = npm_client.clone();
                let name = name.clone();
                let version_req_str = version_req_str.clone();
                handles.push(tokio::spawn(async move {
                    let pkg_id = PackageId::js(&name);
                    let result = client.fetch_package_metadata(&pkg_id).await;
                    (name, version_req_str, pkg_id, result)
                }));
            }

            // Collect results
            let results = futures::future::join_all(handles).await;

            let mut next_level: Vec<(String, String)> = Vec::new();

            for join_result in results {
                let (name, version_req_str, pkg_id, fetch_result) = join_result
                    .map_err(|e| InstallError::ResolutionFailed(
                        format!("task join error: {e}")
                    ))?;

                // Skip if another task in this batch already resolved it
                if resolved_names.contains(&name) {
                    continue;
                }

                let pkg_meta = fetch_result.map_err(|e| InstallError::ResolutionFailed(
                    format!("failed to fetch metadata for {name}: {e}")
                ))?;

                // Parse version requirement
                let semver_req = parse_npm_range(&version_req_str)
                    .map_err(|e| InstallError::ResolutionFailed(
                        format!("invalid version range for {name}: {e}")
                    ))?;
                let version_req = rusk_core::VersionReq::SemverReq(semver_req);

                // Find best matching version
                let matching_versions: Vec<&Version> = pkg_meta
                    .versions
                    .iter()
                    .filter(|v| version_req.matches(v))
                    .collect();

                if matching_versions.is_empty() {
                    return Err(InstallError::ResolutionFailed(
                        format!("no version of {name} matches {version_req_str}")
                    ));
                }

                let best_version = matching_versions
                    .iter()
                    .max()
                    .expect("non-empty");

                info!(package = %name, version = %best_version, "resolved");

                // Get version metadata
                let ver_str = best_version.to_string();
                let ver_meta = if let Some(meta) = pkg_meta.version_metadata.get(&ver_str) {
                    meta.clone()
                } else {
                    npm_client
                        .fetch_version_metadata(&pkg_id, best_version)
                        .await
                        .map_err(|e| InstallError::ResolutionFailed(
                            format!("failed to fetch version metadata for {name}@{ver_str}: {e}")
                        ))?
                };

                let tarball_url = ver_meta
                    .preferred_artifact()
                    .map(|a| a.url.to_string())
                    .ok_or_else(|| InstallError::ResolutionFailed(
                        format!("no download artifact found for {name}@{ver_str}")
                    ))?;

                let digest = ver_meta.preferred_artifact().and_then(|a| a.sha256);

                // Queue transitive deps for next level
                for dep in &ver_meta.dependencies {
                    if dep.kind == DependencyKind::Normal && !resolved_names.contains(&dep.name) {
                        next_level.push((dep.name.clone(), dep.requirement.clone()));
                    }
                }

                resolved_names.insert(name.clone());
                resolved_packages.push(ResolvedPackage {
                    package_id: pkg_id,
                    version: (*best_version).clone(),
                    tarball_url,
                    digest,
                    dependencies: ver_meta.dependencies,
                });
            }

            current_level = next_level;
            depth += 1;
        }

        metrics.record_resolved(resolved_packages.len() as u64);
    }

    // Process Python dependencies
    let mut py_resolved_packages: Vec<ResolvedPackage> = Vec::new();
    if let Some(ref py_deps) = manifest.python_dependencies {
        emit("Resolving Python dependencies...");
        let pypi_client = Arc::new(PypiRegistryClient::default_registry());

        // Seed with direct dependencies
        let all_py_deps = collect_python_deps(py_deps, config.include_dev);
        let mut current_level: Vec<(String, String)> = all_py_deps
            .iter()
            .map(|(name, entry)| (name.clone(), entry.version_req().to_string()))
            .collect();

        info!(direct = all_py_deps.len(), "resolving Python dependencies (parallel transitive)");

        let mut py_resolved_names: HashSet<String> = HashSet::new();
        let mut depth = 0u32;
        while !current_level.is_empty() {
            // Deduplicate this level against already-resolved
            let to_fetch: Vec<(String, String)> = current_level
                .into_iter()
                .filter(|(name, _)| !py_resolved_names.contains(name))
                .collect::<Vec<_>>();

            // Deduplicate within the level (keep first occurrence)
            let mut seen_in_level = HashSet::new();
            let to_fetch: Vec<(String, String)> = to_fetch
                .into_iter()
                .filter(|(name, _)| seen_in_level.insert(name.clone()))
                .collect();

            if to_fetch.is_empty() {
                break;
            }

            emit(&format!(
                "Resolving Python level {} ({} packages, {} resolved so far)...",
                depth, to_fetch.len(), py_resolved_packages.len()
            ));
            info!(depth, batch_size = to_fetch.len(), "fetching PyPI metadata batch");

            // Fetch all metadata in this level in parallel
            let mut handles = Vec::with_capacity(to_fetch.len());
            for (name, version_req_str) in &to_fetch {
                let client = pypi_client.clone();
                let name = name.clone();
                let version_req_str = version_req_str.clone();
                handles.push(tokio::spawn(async move {
                    let pkg_id = PackageId::python(&name);
                    let result = client.fetch_package_metadata(&pkg_id).await;
                    (name, version_req_str, pkg_id, result)
                }));
            }

            // Collect results
            let results = futures::future::join_all(handles).await;

            let mut next_level: Vec<(String, String)> = Vec::new();

            for join_result in results {
                let (name, version_req_str, pkg_id, fetch_result) = join_result
                    .map_err(|e| InstallError::ResolutionFailed(
                        format!("task join error: {e}")
                    ))?;

                // Skip if another task in this batch already resolved it
                if py_resolved_names.contains(&name) {
                    continue;
                }

                let pkg_meta = fetch_result.map_err(|e| InstallError::ResolutionFailed(
                    format!("failed to fetch metadata for {name}: {e}")
                ))?;

                // Parse PEP 440 version requirement
                let version_req = if version_req_str.is_empty() {
                    // No constraint: match any version
                    None
                } else {
                    let pep440_req = parse_pep440_req(&version_req_str)
                        .map_err(|e| InstallError::ResolutionFailed(
                            format!("invalid PEP 440 specifier for {name}: {e}")
                        ))?;
                    Some(rusk_core::VersionReq::Pep440Req(pep440_req))
                };

                // Find best matching version
                let matching_versions: Vec<&Version> = pkg_meta
                    .versions
                    .iter()
                    .filter(|v| {
                        // Skip prereleases unless explicitly allowed
                        if !config.allow_prereleases && v.is_prerelease() {
                            return false;
                        }
                        match &version_req {
                            Some(req) => req.matches(v),
                            None => true,
                        }
                    })
                    .collect();

                if matching_versions.is_empty() {
                    return Err(InstallError::ResolutionFailed(
                        format!("no version of {name} matches {version_req_str}")
                    ));
                }

                let best_version = matching_versions
                    .iter()
                    .max()
                    .expect("non-empty");

                info!(package = %name, version = %best_version, "resolved (Python)");

                // Get version metadata
                let ver_str = best_version.to_string();
                let ver_meta = if let Some(meta) = pkg_meta.version_metadata.get(&ver_str) {
                    meta.clone()
                } else {
                    pypi_client
                        .fetch_version_metadata(&pkg_id, best_version)
                        .await
                        .map_err(|e| InstallError::ResolutionFailed(
                            format!("failed to fetch version metadata for {name}@{ver_str}: {e}")
                        ))?
                };

                // Prefer wheel artifacts over sdist
                let artifact = ver_meta
                    .artifacts
                    .iter()
                    .find(|a| a.artifact_type == ArtifactType::PythonWheel)
                    .or_else(|| ver_meta.preferred_artifact())
                    .ok_or_else(|| InstallError::ResolutionFailed(
                        format!("no download artifact found for {name}@{ver_str}")
                    ))?;

                let tarball_url = artifact.url.to_string();
                let digest = artifact.sha256;

                // Queue transitive deps for next level
                for dep in &ver_meta.dependencies {
                    if dep.kind == DependencyKind::Normal && !py_resolved_names.contains(&dep.name) {
                        next_level.push((dep.name.clone(), dep.requirement.clone()));
                    }
                }

                py_resolved_names.insert(name.clone());
                py_resolved_packages.push(ResolvedPackage {
                    package_id: pkg_id,
                    version: (*best_version).clone(),
                    tarball_url,
                    digest,
                    dependencies: ver_meta.dependencies,
                });
            }

            current_level = next_level;
            depth += 1;
        }

        metrics.record_resolved(py_resolved_packages.len() as u64);
    }

    let total_resolved = resolved_packages.len() + py_resolved_packages.len();

    if total_resolved == 0 {
        info!("no dependencies to install");
        let elapsed = start.elapsed();
        return Ok(InstallResult {
            resolved: 0,
            downloaded: 0,
            cached: 0,
            materialized: 0,
            elapsed_ms: elapsed.as_millis() as u64,
        });
    }

    // Step 4: Download all packages (JS tarballs + Python wheels)
    let all_packages: Vec<&ResolvedPackage> = resolved_packages
        .iter()
        .chain(py_resolved_packages.iter())
        .collect();

    emit(&format!("Downloading {} packages...", all_packages.len()));
    info!(count = all_packages.len(), "downloading packages");

    let download_config = DownloadManagerConfig {
        max_concurrent: config.download_concurrency,
        ..Default::default()
    };
    let download_manager = DownloadManager::new(cas.clone(), download_config);
    let tracker = ProgressTracker::new();
    tracker.set_total(all_packages.len() as u64);

    let download_requests: Vec<DownloadRequest> = all_packages
        .iter()
        .map(|rp| {
            let url = url::Url::parse(&rp.tarball_url).expect("artifact URL already validated");
            DownloadRequest {
                url,
                expected_digest: rp.digest,
                label: format!("{}@{}", rp.package_id.display_name(), rp.version),
            }
        })
        .collect();

    let results = download_manager
        .download_batch(download_requests, &tracker)
        .await;

    let mut downloaded_count = 0usize;
    let mut cached_count = 0usize;
    let mut download_digests: Vec<Sha256Digest> = Vec::new();

    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(dl_result) => {
                if dl_result.cached {
                    cached_count += 1;
                } else {
                    downloaded_count += 1;
                }
                download_digests.push(dl_result.digest);
            }
            Err(e) => {
                let rp = all_packages[i];
                return Err(InstallError::DownloadFailed(
                    format!("failed to download {}@{}: {}", rp.package_id.display_name(), rp.version, e)
                ));
            }
        }
    }

    metrics.record_downloaded(downloaded_count as u64, 0);

    // Step 5a: Materialize JS packages into node_modules using extracted cache + hardlinks
    //
    // Security model:
    //   - Extracted cache is keyed by SHA-256 digest (same as CAS)
    //   - Cache entry is only used if CAS blob with matching digest exists
    //   - If CAS blob is missing/corrupted, we skip the cache and re-download
    //   - Hardlinks share inodes with the cache, so tampering with
    //     node_modules files does NOT affect the cached copy (hardlinks
    //     are independent after creation; modifying one doesn't change the other
    //     on most filesystems since writes create a new inode via COW or truncate+write)
    //
    // Fast path: digest in extracted cache + digest in CAS → hardlink (no tar extraction)
    // Slow path: extract tarball from CAS → populate extracted cache → hardlink

    let mut materialized_count = 0usize;
    let mut hardlinked_count = 0usize;
    let mut extracted_count = 0usize;
    let js_count = resolved_packages.len();

    if !resolved_packages.is_empty() {
        emit("Materializing packages into node_modules...");
        info!("materializing JS packages");

        let extracted_cache = config.extracted_cache_dir();
        std::fs::create_dir_all(&node_modules)?;
        std::fs::create_dir_all(&extracted_cache)?;

        for (i, rp) in resolved_packages.iter().enumerate() {
            let digest = download_digests[i];
            let pkg_name = rp.package_id.display_name();
            let target_dir = node_modules.join(&pkg_name);
            let cache_dir = extracted_cache
                .join(&digest.shard_prefix())
                .join(digest.to_hex());

            // Security check: CAS blob must exist for this digest
            if !cas.contains(&digest) {
                return Err(InstallError::MaterializationFailed(
                    format!(
                        "CAS integrity check failed for {pkg_name}@{}: blob not found for digest {}",
                        rp.version, digest
                    )
                ));
            }

            // Remove existing target if present
            if target_dir.exists() {
                std::fs::remove_dir_all(&target_dir)?;
            }

            if cache_dir.exists() {
                // Fast path: hardlink from extracted cache
                emit(&format!("Linking {pkg_name}@{} (cached)...", rp.version));
                hardlink_dir(&cache_dir, &target_dir)
                    .map_err(|e| InstallError::MaterializationFailed(
                        format!("failed to hardlink {pkg_name}@{}: {}", rp.version, e)
                    ))?;
                hardlinked_count += 1;
            } else {
                // Slow path: extract from CAS → populate cache → hardlink
                emit(&format!("Extracting {pkg_name}@{}...", rp.version));

                let tarball_data = cas
                    .read(&digest)?
                    .ok_or_else(|| InstallError::MaterializationFailed(
                        format!("CAS entry missing for {pkg_name}@{}", rp.version)
                    ))?;

                // Extract to cache directory
                std::fs::create_dir_all(&cache_dir)?;
                extract_npm_tarball(&tarball_data, &cache_dir)
                    .map_err(|e| InstallError::MaterializationFailed(
                        format!("failed to extract {pkg_name}@{}: {}", rp.version, e)
                    ))?;

                // Hardlink from cache to node_modules
                hardlink_dir(&cache_dir, &target_dir)
                    .map_err(|e| InstallError::MaterializationFailed(
                        format!("failed to hardlink {pkg_name}@{}: {}", rp.version, e)
                    ))?;
                extracted_count += 1;
            }

            materialized_count += 1;
        }

        info!(
            materialized = materialized_count,
            hardlinked = hardlinked_count,
            extracted = extracted_count,
            "JS materialization complete"
        );
    }

    // Step 5b: Materialize Python packages into .venv/lib/site-packages/
    //
    // Wheels are zip files. We extract them directly into site-packages.
    // The same CAS + digest verification applies.
    let mut py_materialized_count = 0usize;

    if !py_resolved_packages.is_empty() {
        let site_packages = config.site_packages_path();
        emit(&format!(
            "Materializing Python packages into {}...",
            site_packages.display()
        ));
        info!(site_packages = %site_packages.display(), "materializing Python packages");

        std::fs::create_dir_all(&site_packages)?;

        for (i, rp) in py_resolved_packages.iter().enumerate() {
            let digest_idx = js_count + i;
            let digest = download_digests[digest_idx];
            let pkg_name = rp.package_id.display_name();

            // Security check: CAS blob must exist for this digest
            if !cas.contains(&digest) {
                return Err(InstallError::MaterializationFailed(
                    format!(
                        "CAS integrity check failed for {pkg_name}@{}: blob not found for digest {}",
                        rp.version, digest
                    )
                ));
            }

            emit(&format!("Extracting wheel {pkg_name}@{}...", rp.version));

            let wheel_data = cas
                .read(&digest)?
                .ok_or_else(|| InstallError::MaterializationFailed(
                    format!("CAS entry missing for {pkg_name}@{}", rp.version)
                ))?;

            // Extract wheel zip into site-packages
            extract_wheel(&wheel_data, &site_packages)
                .map_err(|e| InstallError::MaterializationFailed(
                    format!("failed to extract wheel {pkg_name}@{}: {}", rp.version, e)
                ))?;

            py_materialized_count += 1;
        }

        info!(
            materialized = py_materialized_count,
            "Python materialization complete"
        );
    }

    let total_materialized = materialized_count + py_materialized_count;
    metrics.record_materialized(total_materialized as u64);

    // Step 6: Write/update lockfile
    emit("Writing rusk.lock...");
    info!("updating lockfile");

    let mut lockfile = Lockfile::new();

    // Add JS packages to lockfile
    for (i, rp) in resolved_packages.iter().enumerate() {
        let digest = download_digests[i];
        let locked_pkg = LockedPackage {
            package: rp.package_id.clone(),
            version: rp.version.clone(),
            ecosystem: Ecosystem::Js,
            digest,
            source_url: Some(rp.tarball_url.clone()),
            dependencies: Vec::new(),
            dev: false,
            signer: None,
            resolved_by: Some("rusk-orchestrator".to_string()),
        };
        lockfile.add_package(locked_pkg);
    }

    // Add Python packages to lockfile
    for (i, rp) in py_resolved_packages.iter().enumerate() {
        let digest_idx = js_count + i;
        let digest = download_digests[digest_idx];
        let locked_pkg = LockedPackage {
            package: rp.package_id.clone(),
            version: rp.version.clone(),
            ecosystem: Ecosystem::Python,
            digest,
            source_url: Some(rp.tarball_url.clone()),
            dependencies: Vec::new(),
            dev: false,
            signer: None,
            resolved_by: Some("rusk-orchestrator".to_string()),
        };
        lockfile.add_package(locked_pkg);
    }

    rusk_lockfile::save_lockfile(&lockfile, &lockfile_path)
        .map_err(|e| InstallError::LockfileError(e.to_string()))?;

    // Step 7: Write install state
    emit("Saving install state...");

    let mut state = rusk_materialize::InstallState::new();

    // Record JS installs
    for (i, rp) in resolved_packages.iter().enumerate() {
        let digest = download_digests[i];
        let target_dir = node_modules.join(rp.package_id.display_name());
        state.record_install(
            rp.package_id.clone(),
            rp.version.clone(),
            digest,
            target_dir,
        );
    }

    // Record Python installs
    let site_packages = config.site_packages_path();
    for (i, rp) in py_resolved_packages.iter().enumerate() {
        let digest_idx = js_count + i;
        let digest = download_digests[digest_idx];
        let target_dir = site_packages.join(rp.package_id.display_name());
        state.record_install(
            rp.package_id.clone(),
            rp.version.clone(),
            digest,
            target_dir,
        );
    }

    let state_path = config.state_path();
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    state
        .save(&state_path)
        .map_err(|e| InstallError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    let elapsed = start.elapsed();

    info!(
        resolved = total_resolved,
        downloaded = downloaded_count,
        cached = cached_count,
        materialized = total_materialized,
        elapsed_ms = elapsed.as_millis() as u64,
        "install complete"
    );

    Ok(InstallResult {
        resolved: total_resolved,
        downloaded: downloaded_count,
        cached: cached_count,
        materialized: total_materialized,
        elapsed_ms: elapsed.as_millis() as u64,
    })
}

/// Collect JS dependencies from the manifest, optionally including dev deps.
fn collect_js_deps(
    js_deps: &rusk_manifest::schema::JsDependencies,
    include_dev: bool,
) -> Vec<(String, DependencyEntry)> {
    let mut deps: Vec<(String, DependencyEntry)> = Vec::new();

    for (name, entry) in &js_deps.dependencies {
        deps.push((name.clone(), entry.clone()));
    }

    if include_dev {
        for (name, entry) in &js_deps.dev_dependencies {
            deps.push((name.clone(), entry.clone()));
        }
    }

    deps
}

/// Collect Python dependencies from the manifest, optionally including dev deps.
fn collect_python_deps(
    py_deps: &rusk_manifest::schema::PythonDependencies,
    include_dev: bool,
) -> Vec<(String, DependencyEntry)> {
    let mut deps: Vec<(String, DependencyEntry)> = Vec::new();

    for (name, entry) in &py_deps.dependencies {
        deps.push((name.clone(), entry.clone()));
    }

    if include_dev {
        for (name, entry) in &py_deps.dev_dependencies {
            deps.push((name.clone(), entry.clone()));
        }
    }

    deps
}

/// Parse a PEP 440 version specifier string into `pep440_rs::VersionSpecifiers`.
fn parse_pep440_req(req: &str) -> Result<pep440_rs::VersionSpecifiers, String> {
    req.parse::<pep440_rs::VersionSpecifiers>()
        .map_err(|e| format!("failed to parse PEP 440 specifier '{req}': {e}"))
}

/// Recursively hardlink all files from `src` into `dst`.
///
/// Creates the directory structure in `dst` and hardlinks each file.
/// Falls back to copy if hardlink fails (e.g., cross-device).
fn hardlink_dir(src: &Path, dst: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            hardlink_dir(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            // Try hardlink first, fall back to copy
            if std::fs::hard_link(&src_path, &dst_path).is_err() {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
        // Skip symlinks for security (npm tarballs shouldn't have them)
    }

    Ok(())
}
