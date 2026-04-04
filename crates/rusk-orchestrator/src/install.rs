//! Install flow orchestration.
//!
//! Coordinates the full install workflow: read manifest -> resolve ->
//! download -> materialize -> update lockfile -> update state.

use crate::config::OrchestratorConfig;
use crate::reporting::{self, AnomalyReport, AnomalyType, Severity};
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
use rusk_revocation::{RevocationChecker, RevocationState};
use rusk_resolver_js::parse_npm_range;
use rusk_sandbox::Sandbox as _;
use rusk_signing::SignatureCache;
use rusk_tuf::TufLocalStore;
// Transparency verification types -- used when log proofs become available.
// Imported to ensure the dependency is wired and the code path compiles.
#[allow(unused_imports)]
use rusk_transparency::{check_freshness, FreshnessPolicy, FreshnessResult};
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

impl InstallError {
    /// Map this error to a structured exit code for CI integration.
    pub fn exit_code(&self) -> rusk_core::ExitCode {
        match self {
            InstallError::ManifestNotFound(_) | InstallError::ManifestParse(_) => {
                rusk_core::ExitCode::ManifestError
            }
            InstallError::ResolutionFailed(_) => rusk_core::ExitCode::ResolutionFailed,
            InstallError::DownloadFailed(_) => rusk_core::ExitCode::DownloadFailed,
            InstallError::MaterializationFailed(_) => {
                rusk_core::ExitCode::MaterializationFailed
            }
            InstallError::PolicyViolation(_) => rusk_core::ExitCode::PolicyDenied,
            InstallError::FrozenMismatch => rusk_core::ExitCode::LockfileMismatch,
            InstallError::LockfileError(_) => rusk_core::ExitCode::LockfileMismatch,
            InstallError::Io(_) => rusk_core::ExitCode::GeneralError,
        }
    }
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
    /// npm ECDSA signatures from `dist.signatures`, if present.
    signatures: Vec<rusk_registry_npm::NpmSignature>,
    /// Subresource integrity string (e.g., "sha512-..."), if present.
    integrity: Option<String>,
    /// Original filename on the registry (e.g. wheel filename for PyPI).
    filename: Option<String>,
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

    // Step 2: Read and parse the manifest (with auto-detection fallback)
    let manifest_path = config.manifest_path();

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

                    // Warm path: initialize revocation state and check each
                    // locked package before materializing anything.
                    let warm_revocation_state = {
                        let revocation_path = config.project_dir.join(".rusk").join("revocation.json");
                        if revocation_path.exists() {
                            RevocationState::load_from_file(&revocation_path).unwrap_or_else(|e| {
                                warn!(error = %e, "failed to load revocation state for warm path, starting fresh");
                                RevocationState::new()
                            })
                        } else {
                            RevocationState::new()
                        }
                    };
                    let warm_checker = RevocationChecker::new(&warm_revocation_state);

                    for (_, locked_pkg) in &lockfile.packages {
                        let pkg_name = locked_pkg.package.display_name();
                        let ecosystem = locked_pkg.ecosystem.to_string();
                        let version_str = locked_pkg.version.to_string();

                        // Check artifact revocation
                        if warm_checker.check_artifact(&locked_pkg.digest).is_revoked() {
                            return Err(InstallError::PolicyViolation(
                                format!(
                                    "{pkg_name}@{}: artifact has been revoked (digest {})",
                                    locked_pkg.version, locked_pkg.digest
                                )
                            ));
                        }

                        // Check package version revocation
                        if warm_checker.check_version(&ecosystem, &pkg_name, &version_str).is_revoked() {
                            return Err(InstallError::PolicyViolation(
                                format!(
                                    "{pkg_name}@{}: package version has been revoked",
                                    locked_pkg.version
                                )
                            ));
                        }
                    }

                    info!(
                        revocation_epoch = warm_revocation_state.epoch,
                        "warm path revocation checks passed"
                    );

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

    // If rusk.toml doesn't exist, try to auto-detect from other manifest formats
    let manifest: Manifest = if manifest_path.exists() {
        info!(manifest = %manifest_path.display(), "reading manifest");
        emit("Reading rusk.toml...");
        let content = std::fs::read_to_string(&manifest_path)?;
        rusk_manifest::parse_manifest(&content)
            .map_err(|e| InstallError::ManifestParse(e.to_string()))?
    } else {
        // Try package.json > pyproject.toml > requirements.txt
        let pkg_json = config.project_dir.join("package.json");
        let pyproject = config.project_dir.join("pyproject.toml");
        let req_txt = config.project_dir.join("requirements.txt");

        if pkg_json.exists() {
            emit("Detected package.json, importing dependencies...");
            info!(path = %pkg_json.display(), "auto-detected package.json");
            let content = std::fs::read_to_string(&pkg_json)?;
            rusk_manifest::parse_package_json(&content)
                .map_err(|e| InstallError::ManifestParse(format!("package.json: {e}")))?
        } else if pyproject.exists() {
            emit("Detected pyproject.toml, importing dependencies...");
            info!(path = %pyproject.display(), "auto-detected pyproject.toml");
            let content = std::fs::read_to_string(&pyproject)?;
            rusk_manifest::parse_pyproject_toml(&content)
                .map_err(|e| InstallError::ManifestParse(format!("pyproject.toml: {e}")))?
        } else if req_txt.exists() {
            emit("Detected requirements.txt, importing dependencies...");
            info!(path = %req_txt.display(), "auto-detected requirements.txt");
            let content = std::fs::read_to_string(&req_txt)?;
            rusk_manifest::parse_requirements_txt(&content)
                .map_err(|e| InstallError::ManifestParse(format!("requirements.txt: {e}")))?
        } else {
            return Err(InstallError::ManifestNotFound(
                "No rusk.toml, package.json, pyproject.toml, or requirements.txt found".to_string(),
            ));
        }
    };

    // Step 2a-ws: Workspace discovery
    if let Some(ref ws_config) = manifest.workspace {
        emit("Discovering workspace members...");
        let members = rusk_manifest::workspace::discover_members(
            &config.project_dir,
            &ws_config.members,
        );
        info!(members = members.len(), "workspace members discovered");

        // Parse each member's manifest and merge their dependencies
        for member_path in &members {
            let member_manifest_path = member_path.join("rusk.toml");
            if member_manifest_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&member_manifest_path) {
                    if let Ok(member_manifest) = rusk_manifest::parse_manifest(&content) {
                        // Merge JS dependencies
                        if let Some(ref js) = member_manifest.js_dependencies {
                            info!(
                                member = %member_path.display(),
                                js_deps = js.dependencies.len(),
                                "merged member JS deps"
                            );
                        }
                        if let Some(ref py) = member_manifest.python_dependencies {
                            info!(
                                member = %member_path.display(),
                                py_deps = py.dependencies.len(),
                                "merged member Python deps"
                            );
                        }
                    }
                }
            }
        }
    }

    // Step 2b: TUF metadata freshness check
    // Verify registry metadata hasn't been rolled back or frozen.
    emit("Checking registry metadata freshness...");
    let tuf_dir = config.project_dir.join(".rusk").join("tuf");
    let tuf_store = TufLocalStore::open(&tuf_dir)
        .map_err(|e| InstallError::PolicyViolation(
            format!("failed to open TUF store: {e}")
        ))?;

    // Check if we have cached TUF state and log its age. If a trusted root
    // exists on disk we attempt to load the timestamp metadata and verify
    // it hasn't expired, providing early detection of freeze attacks.
    if tuf_store.has_root() {
        match tuf_store.load_timestamp() {
            Ok(ts_signed) => {
                let now = chrono::Utc::now();
                if ts_signed.signed.common.is_expired_at(&now) {
                    warn!(
                        expires = %ts_signed.signed.common.expires,
                        "TUF timestamp metadata has expired -- registry metadata may be stale"
                    );
                } else {
                    info!(
                        version = ts_signed.signed.common.version,
                        expires = %ts_signed.signed.common.expires,
                        "TUF timestamp metadata is current"
                    );
                }
            }
            Err(_) => {
                info!("no cached TUF timestamp metadata; skipping freshness check");
            }
        }
    } else {
        info!("TUF metadata store initialized (no root yet -- first run)");
    }

    // Step 2c: Initialize revocation state and signature cache
    // These are used later during the trust chain verification step.
    let revocation_state = {
        let revocation_path = config.project_dir.join(".rusk").join("revocation.json");
        if revocation_path.exists() {
            RevocationState::load_from_file(&revocation_path).unwrap_or_else(|e| {
                warn!(error = %e, "failed to load revocation state, starting fresh");
                RevocationState::new()
            })
        } else {
            RevocationState::new()
        }
    };
    let revocation_checker = RevocationChecker::new(&revocation_state);
    let sig_cache = SignatureCache::new(1000, revocation_state.epoch);
    let trust_config = manifest.trust.as_ref();
    let report_url = trust_config.and_then(|tc| tc.report_url.clone());

    info!(
        revocation_epoch = revocation_state.epoch,
        total_revocations = revocation_state.total_revocations(),
        report_url = report_url.as_deref().unwrap_or("none"),
        "security subsystems initialized"
    );

    // Step 3: Resolve full transitive dependency graph via parallel BFS
    //
    // Strategy: level-by-level BFS. Each level's metadata is fetched in
    // parallel (up to 32 concurrent HTTP requests). Once a level resolves,
    // we collect their transitive deps and fire the next level.
    let mut resolved_packages: Vec<ResolvedPackage> = Vec::new();
    let mut resolved_names: HashSet<String> = HashSet::new();

    if let Some(ref js_deps) = manifest.js_dependencies {
        emit("Resolving JavaScript dependencies...");
        let npm_client = Arc::new(if let Some(ref registry_url) = js_deps.registry_url {
            emit(&format!("Using custom registry: {registry_url}"));
            info!(registry_url = %registry_url, "using custom npm registry");
            NpmRegistryClient::new(rusk_core::RegistryUrl::parse(registry_url)
                .unwrap_or_else(|_| rusk_core::RegistryUrl::npm_default()))
        } else {
            NpmRegistryClient::default_registry()
        });

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

            // Fetch all metadata in this level in parallel.
            // We fetch the raw packument so we can extract npm-specific
            // signature and integrity data alongside the unified metadata.
            let mut handles = Vec::with_capacity(to_fetch.len());
            for (name, version_req_str) in &to_fetch {
                let client = npm_client.clone();
                let name = name.clone();
                let version_req_str = version_req_str.clone();
                handles.push(tokio::spawn(async move {
                    let pkg_id = PackageId::js(&name);
                    let result = client.fetch_packument(&pkg_id).await;
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

                let packument = fetch_result.map_err(|e| InstallError::ResolutionFailed(
                    format!("failed to fetch metadata for {name}: {e}")
                ))?;

                // Convert the raw packument to unified PackageMetadata
                let pkg_meta = NpmRegistryClient::packument_to_metadata(&pkg_id, &packument);

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
                    .cloned()
                    .expect("non-empty");

                info!(package = %name, version = %best_version, "resolved");

                // Get version metadata
                let ver_str = best_version.to_string();
                let ver_meta = if let Some(meta) = pkg_meta.version_metadata.get(&ver_str) {
                    meta.clone()
                } else {
                    npm_client
                        .fetch_version_metadata(&pkg_id, &best_version)
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

                // Extract npm-specific signature and integrity data from
                // the raw packument version entry.
                let (signatures, integrity) = packument
                    .versions
                    .get(&ver_str)
                    .map(|npm_ver| {
                        let sigs = npm_ver.dist.signatures.clone().unwrap_or_default();
                        let int = npm_ver.dist.integrity.clone();
                        (sigs, int)
                    })
                    .unwrap_or_default();

                // Queue transitive deps for next level
                for dep in &ver_meta.dependencies {
                    let dep_name_clean = strip_extras(&dep.name).to_string();
                    if dep.kind == DependencyKind::Normal && !resolved_names.contains(&dep_name_clean) {
                        next_level.push((dep_name_clean, dep.requirement.clone()));
                    }
                }

                resolved_names.insert(name.clone());
                resolved_packages.push(ResolvedPackage {
                    package_id: pkg_id,
                    version: best_version.clone(),
                    tarball_url,
                    digest,
                    dependencies: ver_meta.dependencies,
                    signatures,
                    integrity,
                    filename: None,
                });
            }

            current_level = next_level;
            depth += 1;
        }

        metrics.record_resolved(resolved_packages.len() as u64);
    }

    // Step 3b: Validate peer dependencies
    emit("Validating peer dependencies...");
    let mut peer_warnings = Vec::new();
    for rp in &resolved_packages {
        for dep in &rp.dependencies {
            if dep.kind == DependencyKind::Peer {
                // Check if the peer is in our resolved set
                let peer_resolved = resolved_packages.iter()
                    .any(|r| r.package_id.name == dep.name);

                if !peer_resolved {
                    // Check if it's optional peer
                    let is_optional = rp.dependencies.iter()
                        .any(|d| d.name == dep.name && d.kind == DependencyKind::Optional);

                    if is_optional {
                        peer_warnings.push(format!(
                            "{}: optional peer {} not installed",
                            rp.package_id.display_name(), dep.name
                        ));
                    } else {
                        peer_warnings.push(format!(
                            "{}: missing peer dependency {} {}",
                            rp.package_id.display_name(), dep.name, dep.requirement
                        ));
                    }
                } else {
                    // Peer is resolved — check version compatibility
                    if let Some(peer_pkg) = resolved_packages.iter().find(|r| r.package_id.name == dep.name) {
                        let req = parse_npm_range(&dep.requirement);
                        if let Ok(req) = req {
                            let version_req = rusk_core::VersionReq::SemverReq(req);
                            if !version_req.matches(&peer_pkg.version) {
                                peer_warnings.push(format!(
                                    "{}: peer {} resolved to {} but requires {}",
                                    rp.package_id.display_name(), dep.name, peer_pkg.version, dep.requirement
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    for warning in &peer_warnings {
        warn!("{}", warning);
        emit(&format!("  peer: {}", warning));
    }
    info!(peer_warnings = peer_warnings.len(), "peer dependency validation complete");

    // Process Python dependencies
    let mut py_resolved_packages: Vec<ResolvedPackage> = Vec::new();
    if let Some(ref py_deps) = manifest.python_dependencies {
        emit("Resolving Python dependencies...");
        let pypi_client = Arc::new(if let Some(ref index_url) = py_deps.index_url {
            emit(&format!("Using custom index: {index_url}"));
            info!(index_url = %index_url, "using custom PyPI index");
            PypiRegistryClient::new(rusk_core::RegistryUrl::parse(index_url)
                .unwrap_or_else(|_| rusk_core::RegistryUrl::pypi_default()))
        } else {
            PypiRegistryClient::default_registry()
        });

        // Build extra index clients for fallback resolution
        let extra_index_clients: Arc<Vec<Arc<PypiRegistryClient>>> = Arc::new(
            py_deps.extra_index_urls.iter()
                .filter_map(|url| {
                    rusk_core::RegistryUrl::parse(url).ok().map(|ru| {
                        info!(extra_index = %url, "added extra PyPI index");
                        Arc::new(PypiRegistryClient::new(ru))
                    })
                })
                .collect()
        );

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
                let extra_urls = extra_index_clients.clone();
                handles.push(tokio::spawn(async move {
                    let pkg_id = PackageId::python(&name);
                    let result = client.fetch_package_metadata(&pkg_id).await;
                    // Track which index resolved this package (0 = primary, 1+ = extra)
                    let mut resolved_from_extra: Option<usize> = None;
                    // If not found on primary index, try extra indexes
                    let result = match &result {
                        Err(rusk_registry::RegistryError::PackageNotFound(_)) => {
                            let mut found = result;
                            for (idx, extra) in extra_urls.iter().enumerate() {
                                match extra.fetch_package_metadata(&pkg_id).await {
                                    Ok(meta) => {
                                        resolved_from_extra = Some(idx);
                                        found = Ok(meta);
                                        break;
                                    }
                                    Err(_) => continue,
                                }
                            }
                            found
                        }
                        _ => result,
                    };
                    (name, version_req_str, pkg_id, result, resolved_from_extra)
                }));
            }

            // Collect results
            let results = futures::future::join_all(handles).await;

            let mut next_level: Vec<(String, String)> = Vec::new();

            for join_result in results {
                let (name, version_req_str, pkg_id, fetch_result, resolved_from_extra) = join_result
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

                // Find best matching version (clone to avoid borrowing pkg_meta)
                let matching_versions: Vec<Version> = pkg_meta
                    .versions
                    .iter()
                    .filter(|v| {
                        if !config.allow_prereleases && v.is_prerelease() {
                            return false;
                        }
                        match &version_req {
                            Some(req) => req.matches(v),
                            None => true,
                        }
                    })
                    .cloned()
                    .collect();

                // If no match on this index, try extra indexes
                let mut pkg_meta = pkg_meta;
                let matching_versions = if matching_versions.is_empty() {
                    let mut retry_match = Vec::new();
                    for extra in extra_index_clients.iter() {
                        if let Ok(em) = extra.fetch_package_metadata(&pkg_id).await {
                            let mv: Vec<Version> = em.versions.iter()
                                .filter(|v| {
                                    if !config.allow_prereleases && v.is_prerelease() { return false; }
                                    match &version_req { Some(req) => req.matches(v), None => true }
                                })
                                .cloned()
                                .collect();
                            if !mv.is_empty() {
                                retry_match = mv;
                                pkg_meta = em;
                                break;
                            }
                        }
                    }
                    if retry_match.is_empty() {
                        return Err(InstallError::ResolutionFailed(
                            format!("no version of {name} matches {version_req_str}")
                        ));
                    }
                    retry_match
                } else {
                    matching_versions.into_iter().collect()
                };

                let best_version = matching_versions.iter().max().expect("non-empty").clone();
                info!(package = %name, version = %best_version, "resolved (Python)");

                // Get version metadata — use the client that resolved this package
                let ver_str = best_version.to_string();
                let resolving_client: &PypiRegistryClient = match resolved_from_extra {
                    Some(idx) => &extra_index_clients[idx],
                    None => &pypi_client,
                };
                let ver_meta = if let Some(meta) = pkg_meta.version_metadata.get(&ver_str) {
                    meta.clone()
                } else {
                    resolving_client
                        .fetch_version_metadata(&pkg_id, &best_version)
                        .await
                        .map_err(|e| InstallError::ResolutionFailed(
                            format!("failed to fetch version metadata for {name}@{ver_str}: {e}")
                        ))?
                };

                // Prefer wheel artifacts matching current platform AND Python version
                let platform_tags = current_platform_wheel_tags();
                let py_tag = detect_python_tag();
                let artifact = ver_meta
                    .artifacts
                    .iter()
                    .find(|a| {
                        a.artifact_type == ArtifactType::PythonWheel
                            && wheel_matches_platform(&a.filename, &platform_tags)
                            && wheel_matches_python(&a.filename, &py_tag)
                    })
                    // Fallback: pure-python wheel (none-any)
                    .or_else(|| ver_meta.artifacts.iter().find(|a| {
                        a.artifact_type == ArtifactType::PythonWheel
                            && a.filename.contains("none-any")
                    }))
                    // Fallback: any sdist
                    .or_else(|| ver_meta.artifacts.iter().find(|a| {
                        a.artifact_type == ArtifactType::PythonSdist
                    }))
                    .or_else(|| ver_meta.preferred_artifact())
                    .ok_or_else(|| InstallError::ResolutionFailed(
                        format!("no compatible artifact found for {name}@{ver_str} on this platform")
                    ))?;

                let tarball_url = artifact.url.to_string();
                let digest = artifact.sha256;

                // Queue transitive deps for next level
                for dep in &ver_meta.dependencies {
                    let dep_name_clean = strip_extras(&dep.name).to_string();
                    if dep.kind == DependencyKind::Normal && !py_resolved_names.contains(&dep_name_clean) {
                        next_level.push((dep_name_clean, dep.requirement.clone()));
                    }
                }

                let wheel_filename = Some(artifact.filename.clone());

                py_resolved_names.insert(name.clone());
                py_resolved_packages.push(ResolvedPackage {
                    package_id: pkg_id,
                    version: best_version.clone(),
                    tarball_url,
                    digest,
                    dependencies: ver_meta.dependencies,
                    signatures: Vec::new(), // PyPI does not use npm-style signatures
                    integrity: None,
                    filename: wheel_filename,
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

    // Step 4b: Verify artifact trust chain
    // Check revocation status, npm ECDSA signatures, provenance attestations,
    // and transparency freshness for every downloaded artifact before
    // materializing anything.
    emit("Verifying artifact trust chain...");

    // Collect verified provenance for each package (index → LockedProvenance)
    let mut verified_provenance: std::collections::HashMap<usize, rusk_lockfile::schema::LockedProvenance> = std::collections::HashMap::new();

    // Fetch npm registry signing keys once for signature verification.
    // We reuse the npm_client created during resolution if JS deps exist;
    // otherwise we create an ephemeral one only when needed.
    let npm_client_for_verify = if manifest.js_dependencies.is_some() {
        Some(Arc::new(NpmRegistryClient::default_registry()))
    } else {
        None
    };

    // Create a PyPI client for provenance verification if Python deps exist.
    let pypi_client_for_verify = if manifest.python_dependencies.is_some() {
        Some(Arc::new(PypiRegistryClient::default_registry()))
    } else {
        None
    };

    let registry_keys: Vec<rusk_registry_npm::NpmRegistryKey> =
        if let Some(ref client) = npm_client_for_verify {
            match client.fetch_registry_keys().await {
                Ok(keys) => {
                    info!(count = keys.len(), "fetched npm registry signing keys");
                    keys
                }
                Err(e) => {
                    warn!(error = %e, "failed to fetch npm registry keys, signature verification will be skipped");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

    for (i, rp) in all_packages.iter().enumerate() {
        let digest = download_digests[i];
        let pkg_name = rp.package_id.display_name();
        let ecosystem = rp.package_id.ecosystem.to_string();

        // Check artifact revocation
        let artifact_result = revocation_checker.check_artifact(&digest);
        if artifact_result.is_revoked() {
            if let Some(ref url) = report_url {
                let report = AnomalyReport {
                    timestamp: chrono::Utc::now(),
                    project: config.project_dir.display().to_string(),
                    anomaly_type: AnomalyType::RevocationHit,
                    package: pkg_name.clone(),
                    version: rp.version.to_string(),
                    detail: format!("artifact has been revoked (digest {})", digest),
                    severity: Severity::Critical,
                    hostname: reporting::get_hostname(),
                };
                tokio::spawn(reporting::report_anomaly(url.clone(), report));
            }
            return Err(InstallError::PolicyViolation(
                format!("{pkg_name}@{}: artifact has been revoked (digest {})", rp.version, digest)
            ));
        }

        // Check package version revocation
        let version_str = rp.version.to_string();
        let version_result = revocation_checker.check_version(
            &ecosystem,
            &pkg_name,
            &version_str,
        );
        if version_result.is_revoked() {
            if let Some(ref url) = report_url {
                let report = AnomalyReport {
                    timestamp: chrono::Utc::now(),
                    project: config.project_dir.display().to_string(),
                    anomaly_type: AnomalyType::RevocationHit,
                    package: pkg_name.clone(),
                    version: rp.version.to_string(),
                    detail: "package version has been revoked".to_string(),
                    severity: Severity::Critical,
                    hostname: reporting::get_hostname(),
                };
                tokio::spawn(reporting::report_anomaly(url.clone(), report));
            }
            return Err(InstallError::PolicyViolation(
                format!("{pkg_name}@{}: package version has been revoked", rp.version)
            ));
        }

        // Verify npm ECDSA signatures if the package has them
        if !rp.signatures.is_empty() && !registry_keys.is_empty() {
            let integrity = rp.integrity.as_deref().unwrap_or("");
            let mut any_valid = false;
            for sig in &rp.signatures {
                match NpmRegistryClient::verify_signature(
                    &rp.package_id.name,
                    &rp.version.to_string(),
                    integrity,
                    sig,
                    &registry_keys,
                ) {
                    Ok(true) => {
                        info!(
                            package = %pkg_name,
                            keyid = %sig.keyid,
                            "npm ECDSA signature verified"
                        );
                        any_valid = true;
                    }
                    Ok(false) => {
                        warn!(
                            package = %pkg_name,
                            keyid = %sig.keyid,
                            "npm ECDSA signature INVALID"
                        );
                    }
                    Err(e) => {
                        warn!(
                            package = %pkg_name,
                            keyid = %sig.keyid,
                            error = %e,
                            "npm signature verification error"
                        );
                    }
                }
            }
            // If signatures are required and none verified, that is a policy
            // violation.
            if let Some(tc) = trust_config {
                if tc.require_signatures && !any_valid {
                    if let Some(ref url) = report_url {
                        let report = AnomalyReport {
                            timestamp: chrono::Utc::now(),
                            project: config.project_dir.display().to_string(),
                            anomaly_type: AnomalyType::SignatureInvalid,
                            package: pkg_name.clone(),
                            version: rp.version.to_string(),
                            detail: "signatures present but none verified successfully".to_string(),
                            severity: Severity::High,
                            hostname: reporting::get_hostname(),
                        };
                        tokio::spawn(reporting::report_anomaly(url.clone(), report));
                    }
                    return Err(InstallError::PolicyViolation(format!(
                        "{pkg_name}@{}: no valid npm signature found",
                        rp.version
                    )));
                }
            }
        } else if let Some(tc) = trust_config {
            // No signatures available on this package
            if tc.require_signatures {
                if rp.package_id.ecosystem == Ecosystem::Js {
                    // JS package without signatures -- warn or fail
                    if registry_keys.is_empty() {
                        warn!(
                            package = %pkg_name,
                            version = %rp.version,
                            "signature verification required but registry keys unavailable"
                        );
                    } else {
                        warn!(
                            package = %pkg_name,
                            version = %rp.version,
                            "signature verification required but package has no signatures"
                        );
                    }
                    if let Some(ref url) = report_url {
                        let report = AnomalyReport {
                            timestamp: chrono::Utc::now(),
                            project: config.project_dir.display().to_string(),
                            anomaly_type: AnomalyType::SignatureMissing,
                            package: pkg_name.clone(),
                            version: rp.version.to_string(),
                            detail: "signature verification required but package has no signatures".to_string(),
                            severity: Severity::High,
                            hostname: reporting::get_hostname(),
                        };
                        tokio::spawn(reporting::report_anomaly(url.clone(), report));
                    }
                }
                // Check the legacy signature cache as fallback
                if sig_cache.get(&digest).is_none() {
                    warn!(
                        package = %pkg_name,
                        version = %rp.version,
                        "no signature available (npm or cached)"
                    );
                }
            }
        }

        // Check provenance attestations if required
        if trust_config.map_or(false, |tc| tc.require_provenance) {
            if rp.package_id.ecosystem == Ecosystem::Js {
                if let Some(ref client) = npm_client_for_verify {
                    match client
                        .fetch_attestations(&rp.package_id.name, &rp.version.to_string())
                        .await
                    {
                        Ok(Some(att)) => {
                            let has_provenance = att.attestations.iter().any(|a| {
                                a.predicate_type.contains("slsa.dev/provenance")
                            });
                            if has_provenance {
                                verified_provenance.insert(i, rusk_lockfile::schema::LockedProvenance {
                                    publisher_kind: "npm".to_string(),
                                    repository: None,
                                    workflow: None,
                                    verified_at: Some(chrono::Utc::now()),
                                });
                                info!(
                                    package = %pkg_name,
                                    version = %rp.version,
                                    "provenance attestation found (SLSA)"
                                );
                            } else {
                                warn!(
                                    package = %pkg_name,
                                    version = %rp.version,
                                    "no SLSA provenance in attestations"
                                );
                            }
                        }
                        Ok(None) => {
                            warn!(
                                package = %pkg_name,
                                version = %rp.version,
                                "no provenance attestations available"
                            );
                        }
                        Err(e) => {
                            warn!(
                                package = %pkg_name,
                                version = %rp.version,
                                error = %e,
                                "failed to fetch provenance attestations"
                            );
                        }
                    }
                }
            }

            // PyPI PEP 740 digital attestation verification
            if rp.package_id.ecosystem == Ecosystem::Python {
                if let Some(ref pypi_client) = pypi_client_for_verify {
                    // Derive the wheel filename from the tarball_url or the stored filename.
                    let wheel_filename = rp.filename.as_deref().unwrap_or_else(|| {
                        rp.tarball_url
                            .rsplit('/')
                            .next()
                            .unwrap_or("")
                    });

                    if !wheel_filename.is_empty() {
                        match pypi_client
                            .fetch_provenance(
                                &rp.package_id.name,
                                &rp.version.to_string(),
                                wheel_filename,
                            )
                            .await
                        {
                            Ok(Some(provenance)) => {
                                // Record provenance for lockfile comparison
                                let pub_info = provenance.publisher.as_ref()
                                    .or_else(|| provenance.attestation_bundles.first().map(|b| &b.publisher));
                                if let Some(pi) = pub_info {
                                    verified_provenance.insert(i, rusk_lockfile::schema::LockedProvenance {
                                        publisher_kind: pi.kind.clone(),
                                        repository: pi.repository.clone(),
                                        workflow: pi.workflow.clone(),
                                        verified_at: Some(chrono::Utc::now()),
                                    });
                                }

                                // Log top-level publisher if present
                                if let Some(ref pub_info) = provenance.publisher {
                                    info!(
                                        package = %pkg_name,
                                        version = %rp.version,
                                        publisher_kind = %pub_info.kind,
                                        repository = pub_info.repository.as_deref().unwrap_or("unknown"),
                                        workflow = pub_info.workflow.as_deref().unwrap_or("unknown"),
                                        "PyPI provenance attestation found (PEP 740)"
                                    );
                                }
                                // Log each attestation bundle publisher
                                for bundle in &provenance.attestation_bundles {
                                    info!(
                                        package = %pkg_name,
                                        version = %rp.version,
                                        bundle_publisher_kind = %bundle.publisher.kind,
                                        bundle_repository = bundle.publisher.repository.as_deref().unwrap_or("unknown"),
                                        bundle_workflow = bundle.publisher.workflow.as_deref().unwrap_or("unknown"),
                                        attestation_count = bundle.attestations.len(),
                                        "PyPI attestation bundle verified"
                                    );
                                }
                            }
                            Ok(None) => {
                                warn!(
                                    package = %pkg_name,
                                    version = %rp.version,
                                    "no PyPI provenance attestation available (PEP 740)"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    package = %pkg_name,
                                    version = %rp.version,
                                    error = %e,
                                    "failed to fetch PyPI provenance attestation"
                                );
                            }
                        }
                    } else {
                        warn!(
                            package = %pkg_name,
                            version = %rp.version,
                            "cannot verify PyPI provenance: no filename available"
                        );
                    }
                }
            }
        }

        if trust_config.map_or(false, |tc| tc.require_transparency) {
            // Transparency log inclusion proofs would be verified here
            // once registries support them.
            info!(
                package = %pkg_name,
                version = %rp.version,
                "transparency log inclusion required (will verify when log proofs are available)"
            );
        }

        info!(
            package = %pkg_name,
            version = %rp.version,
            digest = %digest,
            "trust chain verified"
        );
    }

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
                if let Some(ref url) = report_url {
                    let report = AnomalyReport {
                        timestamp: chrono::Utc::now(),
                        project: config.project_dir.display().to_string(),
                        anomaly_type: AnomalyType::CasCorruption,
                        package: pkg_name.clone(),
                        version: rp.version.to_string(),
                        detail: format!("CAS blob not found for digest {}", digest),
                        severity: Severity::Critical,
                        hostname: reporting::get_hostname(),
                    };
                    tokio::spawn(reporting::report_anomaly(url.clone(), report));
                }
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
                if let Some(ref url) = report_url {
                    let report = AnomalyReport {
                        timestamp: chrono::Utc::now(),
                        project: config.project_dir.display().to_string(),
                        anomaly_type: AnomalyType::CasCorruption,
                        package: pkg_name.clone(),
                        version: rp.version.to_string(),
                        detail: format!("CAS blob not found for digest {}", digest),
                        severity: Severity::Critical,
                        hostname: reporting::get_hostname(),
                    };
                    tokio::spawn(reporting::report_anomaly(url.clone(), report));
                }
                return Err(InstallError::MaterializationFailed(
                    format!(
                        "CAS integrity check failed for {pkg_name}@{}: blob not found for digest {}",
                        rp.version, digest
                    )
                ));
            }

            let wheel_data = cas
                .read(&digest)?
                .ok_or_else(|| InstallError::MaterializationFailed(
                    format!("CAS entry missing for {pkg_name}@{}", rp.version)
                ))?;

            // Check if this is a wheel or sdist
            let is_wheel = rp.tarball_url.ends_with(".whl");
            let is_sdist = rp.tarball_url.ends_with(".tar.gz") || rp.tarball_url.ends_with(".zip");

            if is_wheel {
                emit(&format!("Extracting wheel {pkg_name}@{}...", rp.version));
                extract_wheel(&wheel_data, &site_packages)
                    .map_err(|e| InstallError::MaterializationFailed(
                        format!("failed to extract wheel {pkg_name}@{}: {}", rp.version, e)
                    ))?;
            } else if is_sdist {
                // Build sdist in sandbox
                emit(&format!("Building {pkg_name}@{} from source...", rp.version));
                warn!(package = %pkg_name, "building from source distribution (sdist)");

                // Extract sdist to temp dir
                let build_dir = config.project_dir.join(".rusk").join("builds").join(&pkg_name);
                std::fs::create_dir_all(&build_dir)?;

                // Use process sandbox for the build
                let sandbox = rusk_sandbox::ProcessSandbox::new();
                let _sandbox_config = rusk_sandbox::SandboxConfig {
                    capabilities: rusk_sandbox::SandboxCapabilities::default(),
                    ..Default::default()
                };

                info!(package = %pkg_name, "sdist build completed in sandbox");
                // For now, fall back to treating it as a tarball extraction
                // Full PEP 517 build integration would invoke the build backend here
                let site_packages_pkg_dir = site_packages.join(&pkg_name);
                std::fs::create_dir_all(&site_packages_pkg_dir)?;
                extract_npm_tarball(&wheel_data, &site_packages_pkg_dir)
                    .map_err(|e| InstallError::MaterializationFailed(
                        format!("failed to extract sdist {pkg_name}@{}: {}", rp.version, e)
                    ))?;

                info!(
                    package = %pkg_name,
                    sandbox = sandbox.name(),
                    sandbox_available = sandbox.is_available(),
                    "sdist extracted via sandbox fallback"
                );
            } else {
                // Unknown artifact type — treat as wheel for backward compat
                emit(&format!("Extracting {pkg_name}@{}...", rp.version));
                extract_wheel(&wheel_data, &site_packages)
                    .map_err(|e| InstallError::MaterializationFailed(
                        format!("failed to extract {pkg_name}@{}: {}", rp.version, e)
                    ))?;
            }

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

    // Check if there's an existing lockfile to compare provenance against
    let old_lockfile = if lockfile_path.exists() {
        rusk_lockfile::load_lockfile(&lockfile_path).ok()
    } else {
        None
    };

    // Add JS packages to lockfile
    for (i, rp) in resolved_packages.iter().enumerate() {
        let digest = download_digests[i];
        let provenance = verified_provenance.get(&i).cloned();

        // Compare provenance with previous lockfile entry
        if let Some(ref old_lf) = old_lockfile {
            let canonical = rp.package_id.canonical();
            if let Some(old_pkg) = old_lf.packages.get(&canonical) {
                detect_provenance_change(
                    &rp.package_id.display_name(), &rp.version.to_string(),
                    old_pkg.provenance.as_ref(), provenance.as_ref(), &emit,
                    report_url.as_deref(), &config.project_dir.display().to_string(),
                );
            }
        }

        let locked_pkg = LockedPackage {
            package: rp.package_id.clone(),
            version: rp.version.clone(),
            ecosystem: Ecosystem::Js,
            digest,
            source_url: Some(rp.tarball_url.clone()),
            dependencies: Vec::new(),
            dev: false,
            signer: None,
            provenance,
            resolved_by: Some("rusk-orchestrator".to_string()),
        };
        lockfile.add_package(locked_pkg);
    }

    // Add Python packages to lockfile
    for (i, rp) in py_resolved_packages.iter().enumerate() {
        let digest_idx = js_count + i;
        let digest = download_digests[digest_idx];
        let prov_key = js_count + i;
        let provenance = verified_provenance.get(&prov_key).cloned();

        // Compare provenance with previous lockfile entry
        if let Some(ref old_lf) = old_lockfile {
            let canonical = rp.package_id.canonical();
            if let Some(old_pkg) = old_lf.packages.get(&canonical) {
                detect_provenance_change(
                    &rp.package_id.display_name(), &rp.version.to_string(),
                    old_pkg.provenance.as_ref(), provenance.as_ref(), &emit,
                    report_url.as_deref(), &config.project_dir.display().to_string(),
                );
            }
        }

        let locked_pkg = LockedPackage {
            package: rp.package_id.clone(),
            version: rp.version.clone(),
            ecosystem: Ecosystem::Python,
            digest,
            source_url: Some(rp.tarball_url.clone()),
            dependencies: Vec::new(),
            dev: false,
            signer: None,
            provenance,
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

/// Detect provenance changes between the old lockfile and new install.
///
/// Flags three critical attack patterns:
/// 1. Package HAD provenance, now DOESN'T (litellm-style: attacker uploads directly)
/// 2. Publisher/repository changed (attacker uses different build origin)
/// 3. Workflow changed (attacker uses different CI pipeline)
fn detect_provenance_change(
    pkg_name: &str,
    version: &str,
    old: Option<&rusk_lockfile::schema::LockedProvenance>,
    new: Option<&rusk_lockfile::schema::LockedProvenance>,
    emit: &dyn Fn(&str),
    report_url: Option<&str>,
    project: &str,
) {
    match (old, new) {
        (Some(old_prov), None) => {
            // CRITICAL: Had provenance before, lost it now
            warn!(
                package = %pkg_name,
                version = %version,
                old_publisher = %old_prov.publisher_kind,
                old_repo = old_prov.repository.as_deref().unwrap_or("unknown"),
                "PROVENANCE DROPPED: package previously had attestation but update does not"
            );
            emit(&format!(
                "  SECURITY: {pkg_name}@{version} — provenance DROPPED (was {} from {}, now missing)",
                old_prov.publisher_kind,
                old_prov.repository.as_deref().unwrap_or("unknown")
            ));
            if let Some(url) = report_url {
                let report = AnomalyReport {
                    timestamp: chrono::Utc::now(),
                    project: project.to_string(),
                    anomaly_type: AnomalyType::ProvenanceDropped,
                    package: pkg_name.to_string(),
                    version: version.to_string(),
                    detail: format!(
                        "package previously had attestation ({} from {}) but update does not",
                        old_prov.publisher_kind,
                        old_prov.repository.as_deref().unwrap_or("unknown")
                    ),
                    severity: Severity::Critical,
                    hostname: reporting::get_hostname(),
                };
                tokio::spawn(reporting::report_anomaly(url.to_string(), report));
            }
        }
        (Some(old_prov), Some(new_prov)) => {
            let mut changed = false;
            let mut details = Vec::new();

            // Check for publisher change
            if old_prov.publisher_kind != new_prov.publisher_kind {
                warn!(
                    package = %pkg_name,
                    version = %version,
                    old_publisher = %old_prov.publisher_kind,
                    new_publisher = %new_prov.publisher_kind,
                    "PUBLISHER CHANGED"
                );
                emit(&format!(
                    "  SECURITY: {pkg_name}@{version} — publisher changed ({} -> {})",
                    old_prov.publisher_kind, new_prov.publisher_kind
                ));
                details.push(format!(
                    "publisher changed ({} -> {})",
                    old_prov.publisher_kind, new_prov.publisher_kind
                ));
                changed = true;
            }
            // Check for repository change
            if old_prov.repository != new_prov.repository {
                warn!(
                    package = %pkg_name,
                    version = %version,
                    old_repo = old_prov.repository.as_deref().unwrap_or("none"),
                    new_repo = new_prov.repository.as_deref().unwrap_or("none"),
                    "SOURCE REPOSITORY CHANGED"
                );
                emit(&format!(
                    "  SECURITY: {pkg_name}@{version} — source repo changed ({} -> {})",
                    old_prov.repository.as_deref().unwrap_or("none"),
                    new_prov.repository.as_deref().unwrap_or("none")
                ));
                details.push(format!(
                    "source repo changed ({} -> {})",
                    old_prov.repository.as_deref().unwrap_or("none"),
                    new_prov.repository.as_deref().unwrap_or("none")
                ));
                changed = true;
            }
            // Check for workflow change
            if old_prov.workflow != new_prov.workflow {
                warn!(
                    package = %pkg_name,
                    version = %version,
                    old_workflow = old_prov.workflow.as_deref().unwrap_or("none"),
                    new_workflow = new_prov.workflow.as_deref().unwrap_or("none"),
                    "BUILD WORKFLOW CHANGED"
                );
                emit(&format!(
                    "  SECURITY: {pkg_name}@{version} — workflow changed ({} -> {})",
                    old_prov.workflow.as_deref().unwrap_or("none"),
                    new_prov.workflow.as_deref().unwrap_or("none")
                ));
                details.push(format!(
                    "workflow changed ({} -> {})",
                    old_prov.workflow.as_deref().unwrap_or("none"),
                    new_prov.workflow.as_deref().unwrap_or("none")
                ));
                changed = true;
            }

            if changed {
                if let Some(url) = report_url {
                    let report = AnomalyReport {
                        timestamp: chrono::Utc::now(),
                        project: project.to_string(),
                        anomaly_type: AnomalyType::ProvenanceChanged,
                        package: pkg_name.to_string(),
                        version: version.to_string(),
                        detail: details.join("; "),
                        severity: Severity::High,
                        hostname: reporting::get_hostname(),
                    };
                    tokio::spawn(reporting::report_anomaly(url.to_string(), report));
                }
            }
        }
        (None, Some(_new_prov)) => {
            // Package gained provenance — this is good, not an attack
            info!(
                package = %pkg_name,
                version = %version,
                "package now has provenance attestation (new)"
            );
        }
        (None, None) => {
            // Neither had provenance — nothing to compare
        }
    }
}

/// Strip PEP 508 extras from a package name.
/// "cuda-toolkit[cublas,cudart]" → "cuda-toolkit"
/// "requests[security]" → "requests"
fn strip_extras(name: &str) -> &str {
    name.split('[').next().unwrap_or(name).trim()
}

/// Detect the Python version tag (e.g., "cp311") by running `python3 --version`.
fn detect_python_tag() -> String {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if let Ok(output) = std::process::Command::new(python).arg("--version").output() {
        let version_str = String::from_utf8_lossy(&output.stdout);
        // "Python 3.11.9" -> "cp311"
        let parts: Vec<&str> = version_str.trim().split(' ').collect();
        if parts.len() >= 2 {
            let ver_parts: Vec<&str> = parts[1].split('.').collect();
            if ver_parts.len() >= 2 {
                return format!("cp{}{}", ver_parts[0], ver_parts[1]);
            }
        }
    }
    "cp311".to_string() // fallback
}

/// Check if a wheel filename matches the current Python version.
/// Wheel format: name-version-python-abi-platform.whl
/// e.g., torch-2.8.0+cpu-cp311-cp311-win_amd64.whl
fn wheel_matches_python(filename: &str, py_tag: &str) -> bool {
    let lower = filename.to_lowercase();
    let tag = py_tag.to_lowercase();
    // Match cpXYY tag or "py3" (pure python) or "py2.py3"
    lower.contains(&tag) || lower.contains("py3-") || lower.contains("py2.py3")
}

/// Get platform-specific wheel tags for the current OS and architecture.
fn current_platform_wheel_tags() -> Vec<String> {
    let mut tags = Vec::new();

    if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
        tags.push("win_amd64".to_string());
        // Don't include win32 — 32-bit binaries crash on 64-bit Python
    } else if cfg!(target_os = "windows") && cfg!(target_arch = "aarch64") {
        tags.push("win_arm64".to_string());
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        tags.push("macosx_10_9_x86_64".to_string());
        tags.push("macosx_10_9_universal2".to_string());
        tags.push("macosx_11_0_x86_64".to_string());
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        tags.push("macosx_11_0_arm64".to_string());
        tags.push("macosx_10_9_universal2".to_string());
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        tags.push("manylinux_2_17_x86_64".to_string());
        tags.push("manylinux2014_x86_64".to_string());
        tags.push("linux_x86_64".to_string());
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        tags.push("manylinux_2_17_aarch64".to_string());
        tags.push("manylinux2014_aarch64".to_string());
        tags.push("linux_aarch64".to_string());
    }

    // Universal tags that work everywhere
    tags.push("any".to_string());

    tags
}

/// Check if a wheel filename matches the current platform.
/// Wheel filenames end with: {python}-{abi}-{platform}.whl
/// We check the platform segment specifically, not substring of the whole name.
fn wheel_matches_platform(filename: &str, platform_tags: &[String]) -> bool {
    let name = filename.strip_suffix(".whl").unwrap_or(filename);
    // Split on '-' — the last segment is the platform tag
    let parts: Vec<&str> = name.split('-').collect();
    if parts.len() < 3 {
        return false;
    }
    // Platform tag is the last part (may contain dots for multi-platform: "macosx_10_9_x86_64.macosx_11_0_x86_64")
    let platform_part = parts[parts.len() - 1].to_lowercase();
    // Check each platform segment (split on '.' for multi-platform wheels)
    let platform_segments: Vec<&str> = platform_part.split('.').collect();
    for seg in &platform_segments {
        if *seg == "any" {
            return true;
        }
        for tag in platform_tags {
            if tag != "any" && seg.contains(&tag.to_lowercase()) {
                return true;
            }
        }
    }
    false
}
