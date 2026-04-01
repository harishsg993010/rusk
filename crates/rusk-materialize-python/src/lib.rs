//! site-packages materializer for rusk.
//!
//! Manages Python virtual environments and installs packages into
//! site-packages by unpacking wheels and recording metadata.

pub mod venv;
pub mod wheel_install;
pub mod dist_info;
pub mod scripts;

pub use venv::VenvManager;
pub use wheel_install::{extract_wheel, ExtractedWheel, WheelInstaller, WheelMetadata};
pub use dist_info::DistInfo;
pub use scripts::{EntryPoint, install_scripts};
