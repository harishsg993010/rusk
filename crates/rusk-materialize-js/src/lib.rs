//! node_modules materializer for rusk.
//!
//! Handles the layout and population of node_modules directories,
//! supporting both standard nested layout and a virtual store
//! (pnpm-style) layout for deduplication.

pub mod layout;
pub mod virtual_store;
pub mod hoisted;
pub mod bin_shims;
pub mod tarball;

pub use layout::{JsMaterializer, JsLayoutMode};
pub use virtual_store::VirtualStorePlanner;
pub use bin_shims::{BinEntry, install_bin_shims};
pub use tarball::extract_npm_tarball;
