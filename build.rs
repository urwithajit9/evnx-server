//! Stamps the binary with the commit it was built from.
//!
//! ─── Why ─────────────────────────────────────────────────────────────────────
//!
//! `/health` reported only `CARGO_PKG_VERSION`, which has been `0.1.0` since the
//! repo began and is not bumped by a code change. It therefore could not tell
//! any two builds apart: it said `0.1.0` before a deploy and `0.1.0` after.
//!
//! That matters more now than it used to. Images publish on `v*` tags rather
//! than on every push, so `main` and the deployed binary diverge **by design**
//! and the gap is expected to be non-zero. Twice in one day the question "is the
//! running code the code I am reading?" had to be answered by correlating
//! workflow run history against commit timestamps — which is slow, and was wrong
//! the first time.
//!
//! ─── Resolution order ────────────────────────────────────────────────────────
//!
//! 1. `EVNX_BUILD_SHA`, which CI passes as a Docker build arg. **Inside Docker
//!    this is the only option that can work**: `.dockerignore` excludes `.git/`,
//!    so no git command in the builder has a repository to read.
//! 2. `git rev-parse`, for a plain `cargo build` outside Docker.
//! 3. `"unknown"` — honest rather than misleading. A wrong SHA is worse than no
//!    SHA, because it would be believed.
//!
//! The value is public: the repository is public, and a commit hash reveals
//! nothing a reader could not already fetch.

use std::process::Command;

fn main() {
    // CI changes this on every commit, so the stamp is always current there.
    // Locally the git fallback can go stale until something else forces a
    // rebuild — acceptable, since only the CI value is ever deployed.
    println!("cargo:rerun-if-env-changed=EVNX_BUILD_SHA");

    let sha = std::env::var("EVNX_BUILD_SHA")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(git_head)
        .map(|s| s.trim().chars().take(7).collect::<String>())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=EVNX_BUILD_SHA={sha}");
}

fn git_head() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    // A non-zero status means this is not a git checkout — a release tarball, or
    // the Docker builder. Fall through to "unknown" rather than using stderr.
    out.status
        .success()
        .then(|| String::from_utf8(out.stdout).ok())
        .flatten()
}
