//! Hoisted node_modules layout.
//!
//! Implements the traditional "hoisted" node_modules layout where dependencies
//! are lifted to the highest possible level in the tree to reduce duplication.
//! This is the npm v3+ default behavior.

use std::collections::HashMap;
use std::path::PathBuf;

/// A hoisted layout plan describing where each package should be placed.
#[derive(Clone, Debug)]
pub struct HoistedLayout {
    /// Packages placed at the root node_modules level.
    pub root_packages: Vec<HoistedEntry>,
    /// Packages that must be nested due to version conflicts.
    pub nested_packages: Vec<NestedEntry>,
}

/// A package that can be hoisted to the root level.
#[derive(Clone, Debug)]
pub struct HoistedEntry {
    pub name: String,
    pub version: String,
    pub path: PathBuf,
}

/// A package that must remain nested due to a version conflict.
#[derive(Clone, Debug)]
pub struct NestedEntry {
    pub name: String,
    pub version: String,
    /// The parent package path under which this is nested.
    pub parent_path: PathBuf,
    pub path: PathBuf,
}

/// Compute the hoisted layout for a dependency graph.
///
/// This is a simplified hoisting algorithm:
/// 1. For each package, check if it can be placed at the root
/// 2. If a different version already occupies the root, nest it
pub fn compute_hoisted_layout(
    packages: &[(String, String, Vec<String>)],
) -> HoistedLayout {
    let mut root_versions: HashMap<String, String> = HashMap::new();
    let mut root_packages = Vec::new();
    let mut nested_packages = Vec::new();

    for (name, version, _deps) in packages {
        if let Some(existing) = root_versions.get(name) {
            if existing != version {
                // Version conflict -- must nest
                nested_packages.push(NestedEntry {
                    name: name.clone(),
                    version: version.clone(),
                    parent_path: PathBuf::from("node_modules"),
                    path: PathBuf::from(format!("node_modules/.rusk/{name}@{version}/node_modules/{name}")),
                });
                continue;
            }
        } else {
            root_versions.insert(name.clone(), version.clone());
            root_packages.push(HoistedEntry {
                name: name.clone(),
                version: version.clone(),
                path: PathBuf::from(format!("node_modules/{name}")),
            });
        }
    }

    HoistedLayout {
        root_packages,
        nested_packages,
    }
}
