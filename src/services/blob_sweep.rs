// src/services/blob_sweep.rs

//! Find, and optionally delete, storage objects that no version row points to.
//!
//! Objects end up unreferenced when an upload is followed by a failed insert
//! whose cleanup also failed, when a re-key is staged and never committed, and
//! when a best-effort delete after a re-key or a version deletion did not
//! succeed. They hold ciphertext under a key that may since have been replaced,
//! so they are worth removing, but nothing depends on it happening promptly.
//!
//! Run it as `evnx-server sweep-blobs` (dry run) or `evnx-server sweep-blobs
//! --apply`.
//!
//! ## Why there is a minimum age
//!
//! A push uploads before it inserts its row, and a re-key stages blobs well
//! before the swap quotes them. Both look exactly like an orphan in between. An
//! object is only considered once it is older than the minimum age (24 hours by
//! default). The listing is read before the table, so anything written after the
//! listing is either too new to be listed or already referenced.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::collections::HashSet;

use crate::services::storage::{StorageError, StorageService};

/// What a sweep found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Objects under `vaults/`.
    pub listed: usize,
    /// Of those, the ones a version row points to.
    pub referenced: usize,
    /// Unreferenced, but newer than the minimum age.
    pub too_new: usize,
    /// Not shaped like a blob key; never touched.
    pub unrecognised: usize,
    /// Unreferenced and old enough to delete, sorted.
    pub orphans: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
}

/// Whether `key` looks like `vaults/{uuid}/{version:08}/{uuid}.enc`.
fn is_blob_shaped(key: &str) -> bool {
    let parts: Vec<&str> = key.split('/').collect();
    let [root, vault, version, file] = parts[..] else {
        return false;
    };
    root == "vaults"
        && uuid::Uuid::parse_str(vault).is_ok()
        && version.len() == 8
        && version.bytes().all(|c| c.is_ascii_digit())
        && file
            .strip_suffix(".enc")
            .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
}

/// List storage and the table, and work out which objects nothing points to.
pub async fn find_orphans(
    db: &PgPool,
    storage: &StorageService,
    min_age: Duration,
) -> Result<SweepReport, SweepError> {
    // Storage first, table second. See the module note.
    let objects = storage.list_blobs().await?;
    let referenced: HashSet<String> = sqlx::query_scalar("SELECT blob_key FROM vault_versions")
        .fetch_all(db)
        .await?
        .into_iter()
        .collect();

    let cutoff = Utc::now() - min_age;
    let mut report = SweepReport {
        listed: objects.len(),
        ..Default::default()
    };
    for o in objects {
        if !is_blob_shaped(&o.key) {
            report.unrecognised += 1;
        } else if referenced.contains(&o.key) {
            report.referenced += 1;
        } else if o.last_modified > cutoff {
            report.too_new += 1;
        } else {
            report.orphans.push(o.key);
        }
    }
    report.orphans.sort();
    Ok(report)
}

/// Delete `keys`, returning how many went and which did not. Deleting an object
/// that is already gone counts as success, so a repeated run is harmless.
pub async fn delete_all(storage: &StorageService, keys: &[String]) -> (usize, Vec<String>) {
    let mut deleted = 0;
    let mut failed = Vec::new();
    for key in keys {
        match storage.delete_blob(key).await {
            Ok(()) => deleted += 1,
            Err(e) => {
                tracing::warn!(blob_key = %key, error = %e, "could not delete an orphan blob");
                failed.push(key.clone());
            }
        }
    }
    (deleted, failed)
}

/// The `sweep-blobs` command: arguments after the subcommand name in, process
/// exit code out.
pub async fn run_command(db: &PgPool, storage: &StorageService, args: &[String]) -> i32 {
    let mut apply = false;
    let mut min_age_hours: i64 = 24;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--apply" => apply = true,
            "--min-age-hours" => match it.next().and_then(|v| v.parse::<i64>().ok()) {
                Some(h) if h >= 0 => min_age_hours = h,
                _ => {
                    eprintln!("--min-age-hours needs a whole number of hours, 0 or more");
                    return 2;
                }
            },
            other => {
                eprintln!(
                    "unknown argument {other:?}\n\
                     usage: evnx-server sweep-blobs [--apply] [--min-age-hours N]"
                );
                return 2;
            }
        }
    }

    let report = match find_orphans(db, storage, Duration::hours(min_age_hours)).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sweep failed: {e}");
            return 1;
        }
    };

    println!(
        "objects: {}  referenced: {}  too new (<{}h): {}  unrecognised: {}  orphans: {}",
        report.listed,
        report.referenced,
        min_age_hours,
        report.too_new,
        report.unrecognised,
        report.orphans.len()
    );
    for key in &report.orphans {
        println!("  {key}");
    }

    if !apply {
        if !report.orphans.is_empty() {
            println!("dry run: nothing deleted. Re-run with --apply to delete the objects above.");
        }
        return 0;
    }

    let (deleted, failed) = delete_all(storage, &report.orphans).await;
    println!("deleted: {deleted}  failed: {}", failed.len());
    for key in &failed {
        println!("  failed: {key}");
    }
    i32::from(!failed.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn only_blob_shaped_keys_are_recognised() {
        let v = Uuid::new_v4();
        let ok = format!("vaults/{v}/00000001/{}.enc", Uuid::new_v4());
        assert!(is_blob_shaped(&ok));
        for bad in [
            "vaults/readme.txt".to_string(),
            format!("vaults/{v}/00000001/notes.txt"),
            format!("vaults/{v}/1/{}.enc", Uuid::new_v4()),
            format!("other/{v}/00000001/{}.enc", Uuid::new_v4()),
            format!("vaults/{v}/00000001/{}.enc/x", Uuid::new_v4()),
        ] {
            assert!(!is_blob_shaped(&bad), "{bad}");
        }
    }
}
