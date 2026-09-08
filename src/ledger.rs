use std::path::Path;

use dusa_collection_utils::core::errors::{ErrorArrayItem, Errors};
use serde::Serialize;
use sqlx::{
    Row,
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
};
use tokio::sync::mpsc;

pub use crate::bundle::LEDGER_SECRET_TLV_TYPE;

fn sqlx_err(err: sqlx::Error) -> ErrorArrayItem {
    ErrorArrayItem::new(Errors::ConfigReading, err.to_string())
}

/// One usage event to record against an identity (a username or email). Deliberately
/// carries just enough to prove usage and lightly screen for spam — the "From"
/// (`identity`), the "To" (`recipient`), and the subject line — never the message body.
#[derive(Debug, Clone)]
pub struct UsageEvent {
    pub identity: String,
    pub recipient: String,
    pub subject: String,
    pub success: bool,
}

/// One row from [`Ledger::report`].
#[derive(Debug, Clone, Serialize)]
pub struct UsageRecord {
    pub recipient: String,
    pub subject: String,
    pub success: bool,
    pub occurred_at: String,
}

/// One row from [`Ledger::list_identities`].
#[derive(Debug, Clone, Serialize)]
pub struct IdentitySummary {
    pub identity: String,
    pub created_at: String,
}

/// A small SQLite (WAL-mode) database tracking issued identities and their usage.
#[derive(Clone)]
pub struct Ledger {
    pool: SqlitePool,
}

impl Ledger {
    /// Opens (creating if missing) the ledger database at `db_path`, enables WAL mode,
    /// and ensures its tables exist.
    pub async fn open(db_path: &Path) -> Result<Self, ErrorArrayItem> {
        if let Some(parent) = db_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|err| {
                ErrorArrayItem::new(Errors::OpeningFile, format!("{}: {err}", parent.display()))
            })?;
        }

        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .connect_with(options)
            .await
            .map_err(sqlx_err)?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identities (
                identity TEXT PRIMARY KEY,
                secret BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(&pool)
        .await
        .map_err(sqlx_err)?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS usage (
                id INTEGER PRIMARY KEY,
                identity TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                success INTEGER NOT NULL,
                occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(&pool)
        .await
        .map_err(sqlx_err)?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS usage_identity_occurred_at_idx
             ON usage (identity, occurred_at)",
        )
        .execute(&pool)
        .await
        .map_err(sqlx_err)?;

        Ok(Self { pool })
    }

    /// Generates a fresh random 32-bit secret for `identity` and records it, replacing
    /// any secret already issued to that identity (rotation-safe). The returned bytes
    /// are meant to be embedded into a personalized bundle via [`issue_bundle`].
    pub async fn issue_identity(&self, identity: &str) -> Result<[u8; 4], ErrorArrayItem> {
        let secret: [u8; 4] = rand::random();
        sqlx::query(
            "INSERT INTO identities (identity, secret) VALUES (?, ?)
             ON CONFLICT(identity) DO UPDATE SET secret = excluded.secret",
        )
        .bind(identity)
        .bind(secret.as_slice())
        .execute(&self.pool)
        .await
        .map_err(sqlx_err)?;
        Ok(secret)
    }

    /// Resolves an inbound `identity_secret` back to the identity it was issued to, if
    /// any. Returns `Ok(None)` for a well-formed but unrecognized/unissued secret.
    pub async fn identity_for_secret(
        &self,
        secret: [u8; 4],
    ) -> Result<Option<String>, ErrorArrayItem> {
        let row = sqlx::query("SELECT identity FROM identities WHERE secret = ?")
            .bind(secret.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?;

        Ok(row.map(|row| row.get::<String, _>("identity")))
    }

    /// Lists every issued identity, alphabetically. Never includes the secret itself
    /// — this is a directory listing, not a way to recover a lost bundle.
    pub async fn list_identities(&self) -> Result<Vec<IdentitySummary>, ErrorArrayItem> {
        let rows = sqlx::query("SELECT identity, created_at FROM identities ORDER BY identity")
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;

        Ok(rows
            .into_iter()
            .map(|row| IdentitySummary {
                identity: row.get::<String, _>("identity"),
                created_at: row.get::<String, _>("created_at"),
            })
            .collect())
    }

    /// Removes an identity and its secret from the ledger, so any bundle carrying its
    /// old secret is rejected from then on. Leaves that identity's `usage` history in
    /// place (it's an append-only audit log, not owned by the identity row). Returns
    /// whether an identity was actually found and removed.
    pub async fn revoke_identity(&self, identity: &str) -> Result<bool, ErrorArrayItem> {
        let result = sqlx::query("DELETE FROM identities WHERE identity = ?")
            .bind(identity)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
        Ok(result.rows_affected() > 0)
    }

    /// Records one usage event.
    pub async fn record_usage(&self, event: &UsageEvent) -> Result<(), ErrorArrayItem> {
        sqlx::query(
            "INSERT INTO usage (identity, recipient, subject, success) VALUES (?, ?, ?, ?)",
        )
        .bind(&event.identity)
        .bind(&event.recipient)
        .bind(&event.subject)
        .bind(event.success)
        .execute(&self.pool)
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    /// Returns every recorded usage event for `identity`, oldest first.
    pub async fn report(&self, identity: &str) -> Result<Vec<UsageRecord>, ErrorArrayItem> {
        let rows = sqlx::query(
            "SELECT recipient, subject, success, occurred_at FROM usage
             WHERE identity = ? ORDER BY occurred_at",
        )
        .bind(identity)
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_err)?;

        Ok(rows
            .into_iter()
            .map(|row| UsageRecord {
                recipient: row.get::<String, _>("recipient"),
                subject: row.get::<String, _>("subject"),
                success: row.get::<bool, _>("success"),
                occurred_at: row.get::<String, _>("occurred_at"),
            })
            .collect())
    }

    /// Splits this ledger into a cheap, cloneable [`LedgerHandle`] for recording usage
    /// events, and a [`LedgerWorker`] that actually writes them to SQLite. The caller
    /// (not this crate) is responsible for `tokio::spawn`ing [`LedgerWorker::run`] and
    /// owning its `JoinHandle` — this keeps the ledger's background task out of
    /// apostle_client's control, which matters when the caller already drives its own
    /// `tokio::select!` loop and needs to decide the task's lifetime itself.
    pub fn channel(self, buffer: usize) -> (LedgerHandle, LedgerWorker) {
        let (tx, rx) = mpsc::channel(buffer);
        (LedgerHandle { tx }, LedgerWorker { ledger: self, rx })
    }
}

/// A cheap, `Clone`-able handle for pushing usage events into a [`LedgerWorker`] that
/// the caller is running elsewhere.
#[derive(Clone)]
pub struct LedgerHandle {
    tx: mpsc::Sender<UsageEvent>,
}

impl LedgerHandle {
    /// Queues a usage event — the "From" (`identity`), "To" (`recipient`), and
    /// `subject`, never the message body. Fails only if the corresponding
    /// [`LedgerWorker`] is no longer running.
    pub async fn record(
        &self,
        identity: impl Into<String>,
        recipient: impl Into<String>,
        subject: impl Into<String>,
        success: bool,
    ) -> Result<(), ErrorArrayItem> {
        self.tx
            .send(UsageEvent {
                identity: identity.into(),
                recipient: recipient.into(),
                subject: subject.into(),
                success,
            })
            .await
            .map_err(|_| {
                ErrorArrayItem::new(
                    Errors::ConnectionError,
                    "ledger worker is not running".to_owned(),
                )
            })
    }
}

/// Drains [`UsageEvent`]s pushed through a [`LedgerHandle`] and writes them to SQLite.
/// The caller owns running this — see [`Ledger::channel`].
pub struct LedgerWorker {
    ledger: Ledger,
    rx: mpsc::Receiver<UsageEvent>,
}

impl LedgerWorker {
    /// Runs until every [`LedgerHandle`] clone has been dropped. A single failed write
    /// is logged and skipped rather than stopping the loop.
    pub async fn run(mut self) {
        while let Some(event) = self.rx.recv().await {
            if let Err(err) = self.ledger.record_usage(&event).await {
                dusa_collection_utils::log!(
                    dusa_collection_utils::core::logger::LogLevel::Error,
                    "ledger failed to record usage for '{}': {err}",
                    event.identity
                );
            }
        }
    }
}

/// Tuning knobs for acai_core's chunk builder, passed straight through to the
/// `chunk_padding`/`chunk_target_size` fields of its container-build request. `None`
/// keeps acai_core's own default for that field (`chunk_padding: true`,
/// `chunk_target_size` ~32MiB).
///
/// Note what this does *not* control: acai_core 0.9.0 reserves a fixed 50MiB chunk
/// *index* region up front in every container regardless of content size or these
/// options (`acai_core::chunk_index::INDEX_REGION_SIZE`, not exposed as a build
/// parameter at all) — that's the dominant contributor to a small bundle like ours
/// coming out ~50MB, and neither field here changes it.
#[derive(Debug, Clone, Copy, Default)]
pub struct BundleChunkOptions {
    pub chunk_padding: Option<bool>,
    pub chunk_target_size: Option<u64>,
}

fn secret_tlv_request(
    secret: [u8; 4],
    options: BundleChunkOptions,
) -> Result<Vec<u8>, ErrorArrayItem> {
    let mut request = serde_json::json!({
        "extra_tlvs": [{
            "ty": LEDGER_SECRET_TLV_TYPE,
            "immutable": true,
            "critical": false,
            "secret": true,
            "value": secret.to_vec(),
        }]
    });
    if let Some(padding) = options.chunk_padding {
        request["chunk_padding"] = serde_json::json!(padding);
    }
    if let Some(target_size) = options.chunk_target_size {
        request["chunk_target_size"] = serde_json::json!(target_size);
    }
    Ok(serde_json::to_vec(&request)?)
}

/// Writes `secret` into a fresh `.acai` bundle built from `source_dir` (which should
/// hold `config.json` + `mail_server_pub.der`, the same base files the shared bundle
/// uses), as an IMMUTABLE, SECRET-flagged, non-CRITICAL custom TLV. Rotation is just
/// calling this again with a new secret — the bundle is always built fresh, never
/// patched in place.
pub fn issue_bundle(
    source_dir: &Path,
    secret: [u8; 4],
    options: BundleChunkOptions,
    output_path: &Path,
) -> Result<(), ErrorArrayItem> {
    let request_bytes = secret_tlv_request(secret, options)?;
    acai_core::build_container_file_from_directory(source_dir, &request_bytes, output_path)
        .map_err(|err| ErrorArrayItem::new(Errors::ConfigReading, err.to_string()))
}

/// Same as [`issue_bundle`], but builds the container fully in memory and returns its
/// bytes instead of writing them to disk. Prefer this whenever the caller doesn't
/// specifically need a file on disk (e.g. handing the bundle back over a socket or
/// network connection) — the personalized bundle carries a per-identity secret, so
/// skipping a temp-file round trip means that secret never touches shared storage.
pub fn issue_bundle_bytes(
    source_dir: &Path,
    secret: [u8; 4],
    options: BundleChunkOptions,
) -> Result<Vec<u8>, ErrorArrayItem> {
    let request_bytes = secret_tlv_request(secret, options)?;
    acai_core::build_container_from_directory(source_dir, &request_bytes)
        .map_err(|err| ErrorArrayItem::new(Errors::ConfigReading, err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    async fn open_temp_ledger() -> (Ledger, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(&dir.path().join("ledger.sqlite3"))
            .await
            .unwrap();
        (ledger, dir)
    }

    #[tokio::test]
    async fn issues_identity_and_reports_usage() {
        let (ledger, _dir) = open_temp_ledger().await;

        let secret = ledger.issue_identity("dwhitfield@artisanhosting.net").await.unwrap();
        assert_eq!(secret.len(), 4);

        ledger
            .record_usage(&UsageEvent {
                identity: "dwhitfield@artisanhosting.net".to_owned(),
                recipient: "someone@example.com".to_owned(),
                subject: "Hello".to_owned(),
                success: true,
            })
            .await
            .unwrap();
        ledger
            .record_usage(&UsageEvent {
                identity: "dwhitfield@artisanhosting.net".to_owned(),
                recipient: "spam-target@example.com".to_owned(),
                subject: "Buy now".to_owned(),
                success: false,
            })
            .await
            .unwrap();

        let report = ledger.report("dwhitfield@artisanhosting.net").await.unwrap();
        assert_eq!(report.len(), 2);
        assert_eq!(report[0].recipient, "someone@example.com");
        assert_eq!(report[0].subject, "Hello");
        assert!(report[0].success);
        assert_eq!(report[1].recipient, "spam-target@example.com");
        assert!(!report[1].success);
    }

    #[tokio::test]
    async fn identity_for_secret_round_trips_and_rejects_unknown() {
        let (ledger, _dir) = open_temp_ledger().await;

        let secret = ledger.issue_identity("dwhitfield@artisanhosting.net").await.unwrap();
        let resolved = ledger.identity_for_secret(secret).await.unwrap();
        assert_eq!(resolved.as_deref(), Some("dwhitfield@artisanhosting.net"));

        let unissued = ledger.identity_for_secret([9, 9, 9, 9]).await.unwrap();
        assert_eq!(unissued, None);
    }

    #[tokio::test]
    async fn list_identities_lists_alphabetically() {
        let (ledger, _dir) = open_temp_ledger().await;

        ledger.issue_identity("zed@example.com").await.unwrap();
        ledger.issue_identity("anna@example.com").await.unwrap();

        let identities = ledger.list_identities().await.unwrap();
        let names: Vec<&str> = identities.iter().map(|i| i.identity.as_str()).collect();
        assert_eq!(names, vec!["anna@example.com", "zed@example.com"]);
        assert!(identities.iter().all(|i| !i.created_at.is_empty()));
    }

    #[tokio::test]
    async fn revoke_identity_removes_it_and_invalidates_its_secret() {
        let (ledger, _dir) = open_temp_ledger().await;

        let secret = ledger.issue_identity("someone@example.com").await.unwrap();
        assert!(ledger.revoke_identity("someone@example.com").await.unwrap());

        assert_eq!(ledger.identity_for_secret(secret).await.unwrap(), None);
        assert!(
            !ledger
                .list_identities()
                .await
                .unwrap()
                .iter()
                .any(|i| i.identity == "someone@example.com")
        );

        // Revoking again (or an identity that never existed) reports "nothing found"
        // rather than erroring.
        assert!(!ledger.revoke_identity("someone@example.com").await.unwrap());
    }

    #[tokio::test]
    async fn issuing_twice_rotates_the_secret() {
        let (ledger, _dir) = open_temp_ledger().await;
        let first = ledger.issue_identity("someone@example.com").await.unwrap();
        let second = ledger.issue_identity("someone@example.com").await.unwrap();
        // Astronomically unlikely to collide; if it does, the rotation logic (not luck)
        // is what this test is meant to exercise, so a spurious failure here would be
        // suspicious rather than expected.
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn channel_and_worker_deliver_events() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ledger.sqlite3");
        let ledger = Ledger::open(&db_path).await.unwrap();
        let (handle, worker) = ledger.channel(8);
        let join = tokio::spawn(worker.run());

        handle
            .record("a@example.com", "b@example.com", "Hi", true)
            .await
            .unwrap();
        handle
            .record("a@example.com", "c@example.com", "Also hi", true)
            .await
            .unwrap();
        drop(handle); // lets the worker's recv() loop end

        join.await.unwrap();

        // Re-open against the same file to confirm the worker actually persisted them
        // (the original `ledger` was moved into the worker by `channel`, so this is a
        // fresh connection pool, not the same in-memory handle).
        let reopened = Ledger::open(&db_path).await.unwrap();
        let report = reopened.report("a@example.com").await.unwrap();
        assert_eq!(report.len(), 2);
        assert!(report.iter().all(|r| r.success));
    }

    fn write_bundle_source(temp: &tempfile::TempDir) -> std::path::PathBuf {
        let source_dir = temp.path().join("source");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::File::create(source_dir.join("config.json"))
            .unwrap()
            .write_all(br#"{"addresses":["172.237.134.238:1827"]}"#)
            .unwrap();
        std::fs::File::create(source_dir.join("mail_server_pub.der"))
            .unwrap()
            .write_all(&[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00, 4, 174, 4,
                246, 179, 162, 129, 67, 40, 38, 19, 206, 110, 212, 181, 156, 135, 163, 139, 211,
                132, 147, 103, 80, 141, 7, 41, 46, 32, 80, 190, 84,
            ])
            .unwrap();
        source_dir
    }

    #[tokio::test]
    async fn issue_bundle_writes_a_readable_identity_secret() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = write_bundle_source(&temp);

        let secret = [1, 2, 3, 4];
        let output_path = temp.path().join("bundle.acai");
        issue_bundle(&source_dir, secret, BundleChunkOptions::default(), &output_path).unwrap();

        let bundle = crate::bundle::MailBundle::load(&output_path).unwrap();
        assert_eq!(bundle.identity_secret, Some(secret));
    }

    #[tokio::test]
    async fn issue_bundle_bytes_matches_the_file_based_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = write_bundle_source(&temp);

        let secret = [5, 6, 7, 8];
        let bytes = issue_bundle_bytes(&source_dir, secret, BundleChunkOptions::default()).unwrap();

        // MailBundle::load only reads from a path, so round-trip the in-memory bytes
        // through a temp file purely to reuse it for verification here.
        let readback_path = temp.path().join("bytes.acai");
        std::fs::write(&readback_path, &bytes).unwrap();
        let bundle = crate::bundle::MailBundle::load(&readback_path).unwrap();
        assert_eq!(bundle.identity_secret, Some(secret));
    }

    /// Documents (rather than just asserting in a doc comment) that
    /// `chunk_padding`/`chunk_target_size` do NOT shrink a tiny bundle like ours below
    /// ~50MB: the dominant cost is `acai_core::chunk_index::INDEX_REGION_SIZE`, a fixed
    /// 50MiB region reserved up front regardless of these options. If this test starts
    /// failing because a bundle got small, that's acai_core changing its indexing
    /// scheme -- worth knowing, not a regression to "fix" by tightening the assertion.
    #[tokio::test]
    async fn chunk_options_do_not_shrink_the_fixed_index_region() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = write_bundle_source(&temp);

        let secret = [9, 9, 9, 9];
        let bytes = issue_bundle_bytes(
            &source_dir,
            secret,
            BundleChunkOptions {
                chunk_padding: Some(false),
                chunk_target_size: Some(1),
            },
        )
        .unwrap();

        assert!(
            bytes.len() > 50_000_000,
            "expected the fixed index region to still dominate bundle size, got {} bytes",
            bytes.len()
        );
    }
}
