//! Linux namespace-based sandbox.
//!
//! On Linux, this module would use kernel namespaces (user, mount, network, PID)
//! for lightweight isolation without requiring a container runtime. Full namespace
//! isolation requires Linux-specific syscalls (`clone(2)` with `CLONE_NEWUSER`,
//! `CLONE_NEWNS`, `CLONE_NEWNET`, `CLONE_NEWPID`) and optionally seccomp-bpf
//! for syscall filtering and landlock for filesystem access control.
//!
//! Since these features are inherently Linux-only and require unsafe FFI to
//! kernel APIs, this module re-exports the [`ProcessSandbox`] as the
//! `LinuxSandbox` type on all platforms. On Linux, the `ProcessSandbox` still
//! provides environment isolation (clean env, working directory, timeout) and
//! output capture, which is a practical starting point.
//!
//! To implement full namespace isolation on Linux, one would:
//! 1. Use `clone(2)` with `CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET`
//!    to create an isolated process.
//! 2. Set up a minimal mount namespace with bind mounts for the source directory.
//! 3. Optionally apply seccomp-bpf filters to restrict syscalls.
//! 4. Optionally use landlock to restrict filesystem access.
//! 5. Drop all capabilities via `prctl(PR_SET_NO_NEW_PRIVS)`.
//!
//! These require the `libc` or `nix` crate and platform-specific code paths.

use crate::process::ProcessSandbox;

/// Linux namespace sandbox type.
///
/// Currently implemented as an alias for [`ProcessSandbox`], which provides
/// cross-platform environment isolation. On Linux, the process sandbox still
/// benefits from the OS's existing security mechanisms (user permissions,
/// filesystem permissions, etc.) even without explicit namespace calls.
///
/// For full namespace isolation, this type would wrap Linux-specific syscalls
/// for user/mount/PID/network namespace creation.
pub type LinuxSandbox = ProcessSandbox;

/// Create a new Linux sandbox instance.
///
/// Returns a [`ProcessSandbox`] that provides environment isolation.
/// On Linux, this is the starting point for builds. For stronger isolation,
/// use [`ContainerSandbox`](crate::container::ContainerSandbox) with Docker
/// or Podman.
pub fn new_linux_sandbox() -> LinuxSandbox {
    ProcessSandbox::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trait_def::Sandbox;

    #[test]
    fn linux_sandbox_is_available() {
        let sandbox = new_linux_sandbox();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.name(), "process");
    }
}
