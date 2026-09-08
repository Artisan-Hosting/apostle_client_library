// re-exporting libs
pub use dusa_collection_utils;
pub use acai_core;
#[cfg(target_os = "linux")]
pub use simple_comms;

pub mod bundle;
pub mod email;
pub mod keys;
#[cfg(feature = "server-components")]
pub mod ledger;

pub use bundle::{MailBundle, MailServerConfig};
pub use email::Email;
#[cfg(feature = "server-components")]
pub use ledger::{
    BundleChunkOptions, IdentitySummary, Ledger, LedgerHandle, LedgerWorker, UsageEvent,
    UsageRecord,
};

#[path = "../src/tests/email.rs"]
mod email_test;
