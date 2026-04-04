//! `rusk tree` command.
//!
//! Displays the dependency tree from the lockfile in a human-readable
//! tree format (like `npm ls` or `uv tree`). Supports `--depth` to
//! limit nesting and `--format json` for machine output.

use clap::Args;
use miette::Result;
use std::collections::{BTreeMap, HashSet};

/// Arguments for the tree command.
#[derive(Debug, Args)]
pub struct TreeArgs {
    /// Maximum depth to display (0 = direct deps only).
    #[arg(long)]
    pub depth: Option<usize>,

    /// Output format: text or json.
    #[arg(long = "output", default_value = "text")]
    pub output: String,
}

pub async fn run(args: TreeArgs) -> Result<()> {
    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let lockfile_path = project_dir.join("rusk.lock");
    if !lockfile_path.exists() {
        crate::output::print_warning("No rusk.lock found. Run `rusk install` first.");
        return Ok(());
    }

    let lockfile = rusk_lockfile::load_lockfile(&lockfile_path)
        .map_err(|e| miette::miette!("failed to read rusk.lock: {}", e))?;

    if lockfile.packages.is_empty() {
        crate::output::print_info("No packages in lockfile.");
        return Ok(());
    }

    // Build a lookup from canonical ID -> (display_name, version, deps)
    let pkg_map: BTreeMap<String, PackageNode> = lockfile
        .packages
        .iter()
        .map(|(key, pkg)| {
            let display_name = format!("{}@{}", pkg.package.name, pkg.version);
            let dep_ids: Vec<String> = pkg
                .dependencies
                .iter()
                .map(|d| d.canonical_id.clone())
                .collect();
            (
                key.clone(),
                PackageNode {
                    display_name,
                    name: pkg.package.name.clone(),
                    version: pkg.version.to_string(),
                    dep_ids,
                },
            )
        })
        .collect();

    // Determine root packages (those not depended on by any other package)
    let all_dep_ids: HashSet<&str> = lockfile
        .packages
        .values()
        .flat_map(|pkg| pkg.dependencies.iter().map(|d| d.canonical_id.as_str()))
        .collect();

    let root_ids: Vec<&String> = lockfile
        .packages
        .keys()
        .filter(|key| !all_dep_ids.contains(key.as_str()))
        .collect();

    let max_depth = args.depth.unwrap_or(usize::MAX);

    if args.output == "json" {
        print_tree_json(&root_ids, &pkg_map, max_depth);
    } else {
        print_tree_text(&root_ids, &pkg_map, max_depth);
    }

    Ok(())
}

struct PackageNode {
    display_name: String,
    name: String,
    version: String,
    dep_ids: Vec<String>,
}

fn print_tree_text(
    root_ids: &[&String],
    pkg_map: &BTreeMap<String, PackageNode>,
    max_depth: usize,
) {
    for (i, root_id) in root_ids.iter().enumerate() {
        let mut visited = HashSet::new();
        let is_last = i == root_ids.len() - 1;
        if let Some(node) = pkg_map.get(*root_id) {
            println!("{}", node.display_name);
            print_children(
                &node.dep_ids,
                pkg_map,
                "",
                0,
                max_depth,
                &mut visited,
            );
            // Print a blank line between root packages, except after the last one
            if !is_last {
                println!();
            }
        }
    }
}

fn print_children(
    dep_ids: &[String],
    pkg_map: &BTreeMap<String, PackageNode>,
    prefix: &str,
    current_depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
) {
    if current_depth >= max_depth {
        return;
    }

    let count = dep_ids.len();
    for (i, dep_id) in dep_ids.iter().enumerate() {
        let is_last = i == count - 1;
        let connector = if is_last { "\u{2514}\u{2500}\u{2500} " } else { "\u{251c}\u{2500}\u{2500} " };
        let child_prefix = if is_last { "    " } else { "\u{2502}   " };

        if let Some(node) = pkg_map.get(dep_id) {
            let circular = visited.contains(dep_id);
            if circular {
                println!("{prefix}{connector}{} (circular)", node.display_name);
            } else {
                println!("{prefix}{connector}{}", node.display_name);
                visited.insert(dep_id.clone());
                print_children(
                    &node.dep_ids,
                    pkg_map,
                    &format!("{prefix}{child_prefix}"),
                    current_depth + 1,
                    max_depth,
                    visited,
                );
                visited.remove(dep_id);
            }
        } else {
            // Dependency not found in lockfile — print the raw ID
            println!("{prefix}{connector}{dep_id} (not in lockfile)");
        }
    }
}

fn print_tree_json(
    root_ids: &[&String],
    pkg_map: &BTreeMap<String, PackageNode>,
    max_depth: usize,
) {
    let mut roots: Vec<serde_json::Value> = Vec::new();
    for root_id in root_ids {
        let mut visited = HashSet::new();
        if let Some(node) = pkg_map.get(*root_id) {
            roots.push(build_json_node(node, pkg_map, 0, max_depth, &mut visited));
        }
    }
    let output = serde_json::to_string_pretty(&roots).unwrap_or_else(|_| "[]".to_string());
    println!("{output}");
}

fn build_json_node(
    node: &PackageNode,
    pkg_map: &BTreeMap<String, PackageNode>,
    current_depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
) -> serde_json::Value {
    let mut children: Vec<serde_json::Value> = Vec::new();

    if current_depth < max_depth {
        for dep_id in &node.dep_ids {
            if visited.contains(dep_id) {
                children.push(serde_json::json!({
                    "name": dep_id,
                    "circular": true,
                }));
                continue;
            }
            if let Some(child_node) = pkg_map.get(dep_id) {
                visited.insert(dep_id.clone());
                children.push(build_json_node(
                    child_node,
                    pkg_map,
                    current_depth + 1,
                    max_depth,
                    visited,
                ));
                visited.remove(dep_id);
            }
        }
    }

    serde_json::json!({
        "name": node.name,
        "version": node.version,
        "dependencies": children,
    })
}
