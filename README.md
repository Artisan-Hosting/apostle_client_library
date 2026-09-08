# apostle_client

Standalone client for sending mail through the Artisan mail protocol.

This crate was split out of `artisan_middleware`'s `notifications` module
(the mail-protocol-v2 rework) so it can be versioned and consumed
independently of the rest of the middleware.

## Usage

```rust
use apostle_client::{Email, MailBundle};
use dusa_collection_utils::core::types::stringy::Stringy;

#[tokio::main]
async fn main() {
    let bundle = MailBundle::load("/etc/apostle_client/bundle.acai".as_ref())
        .expect("failed to load mail server bundle");

    let email = Email::new(
        Stringy::from("dwhitfield@artisanhosting.net"),
        Stringy::from("Subject"),
        Stringy::from("Body"),
    );

    if let Err(err) = email.send(&bundle).await {
        eprintln!("Failed to send email: {err}");
    }
}
```

`Email::send` is only available on Linux targets (it depends on
`simple_comms`, which is a Linux-only dependency here). Construction,
validation, and JSON (de)serialization work on every platform.

## Server bundle

The mail server's address(es)/domain and its pinned X25519 public key are no
longer compiled into this crate — they're read at runtime from a `.acai`
bundle (the container format defined by
[`acai-core`](https://docs.artisanhosting.net)), via [`MailBundle::load`].

**Source layout** — what you point `acai-core`'s writer at to build a bundle:

```
bundle-src/
├── config.json             # MailServerConfig JSON — see shapes below
└── mail_server_pub.der     # server's static X25519 public key (44-byte SPKI DER)
```

**Resulting bundle** — what `MailBundle::load` reads back out, and how:

```
bundle.acai                                  (one acai-core container)
├── Chunk Data Area  — read via acai_core::reader::read_file(bytes, path, None)
│   ├── config.json
│   └── mail_server_pub.der
└── State Section    — read via acai_core::reader::read_state_tlv(bytes, ty)
    └── TLV 0xc001 "identity secret" (4 bytes, IMMUTABLE + SECRET)
        only present on a bundle personalized via `ledger::issue_bundle` —
        absent (MailBundle::identity_secret == None) on the shared/base bundle
```

The two source files always live as regular files in the container (so
`config.json` and `mail_server_pub.der` are exactly what's on disk before
packing); the identity secret is metadata in the State Section instead, not a
file — that's why it's read with a different function and doesn't show up if
you `unpack_to_directory` a bundle.

`config.json` is either a fixed address list:
```json
{ "addresses": ["172.237.134.238:1827", "172.234.222.191:1827"] }
```
or a domain to resolve at connect time:
```json
{ "domain": "mail.artisanhosting.net", "port": 1827 }
```
`mail_server_pub.der` is produced with, e.g.,
`openssl pkey -in private.pem -pubout -outform der -out mail_server_pub.der`.

To build a shared/base bundle (server address + cert only, no identity) for
local testing, put both files in one directory (matching the source layout
above) and pack it with `acai-core`'s writer directly
(`build_container_file_from_directory`, or its Go CLI, `acai-cli`). To issue a
bundle personalized for a specific user, use [`ledger::issue_bundle`] instead
(see below) — it wraps the same writer with an extra per-identity secret TLV.

There is no fallback: if no bundle is supplied, or it's missing either file,
`MailBundle::load` returns an error rather than using a stale default.

## Usage ledger (`server-components` feature)

The usage ledger — `Ledger`, `LedgerHandle`, `LedgerWorker`, and
`ledger::issue_bundle` — is gated behind the `server-components` Cargo
feature, off by default:

```toml
apostle_client = { version = "...", features = ["server-components"] }
```

This is server/issuance-only surface (it pulls in `sqlx` and `rand`, and can
generate and store identity secrets). A plain mail-sending client build
never links those dependencies or contains this code path at all — only
`identity_secret: Option<[u8; 4]>` on `MailBundle` (reading a secret already
baked into a bundle) is available unconditionally, since any client may need
that regardless of whether it's also acting as an issuer.

`apostle_client::Ledger` is a small SQLite (WAL-mode) database tracking issued
identities (a username or email, each with a randomly generated 32-bit secret)
and usage events recorded against them. Each usage event deliberately carries
just enough to prove usage and lightly screen for spam — the "From"
(`identity`), the "To" (`recipient`), and the `subject` line — and never the
message body:

```rust
use apostle_client::Ledger;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let ledger = Ledger::open("/etc/apostle_client/ledger.sqlite3".as_ref()).await?;

// Issue a new identity, then bake its secret into a personalized bundle built
// from a directory holding config.json + mail_server_pub.der.
let secret = ledger.issue_identity("dwhitfield@artisanhosting.net").await?;
apostle_client::ledger::issue_bundle(
    "/etc/apostle_client/base".as_ref(),
    secret,
    "/etc/apostle_client/dwhitfield.acai".as_ref(),
)?;

// Split into a cheap, cloneable handle and a worker task. apostle_client never
// spawns the worker itself — the caller owns tokio::spawn and its JoinHandle,
// since a server's own tokio::select! loop usually needs to decide that
// lifetime itself.
let (handle, worker) = ledger.channel(64);
let worker_task = tokio::spawn(worker.run());

handle
    .record("dwhitfield@artisanhosting.net", "someone@example.com", "Hi", true)
    .await?;

drop(handle);
worker_task.await?;
# Ok(())
# }
```

A bundle built via `issue_bundle` carries its secret as an IMMUTABLE, SECRET-
flagged custom TLV (`acai_core`'s `0x8000-0xFFFF` "private" range) —
`MailBundle::load` surfaces it as `identity_secret: Option<[u8; 4]>` (`None`
for a shared/base bundle with no identity baked in).

`Email::send` transmits `identity_secret` (when present) as an extra
`identity_secret` field alongside the email data — `Email`'s own fields are
flattened at the top level, so the JSON is byte-for-byte identical to plain
`Email::to_json()` when no secret is present, and a server that doesn't yet
understand the field just ignores it (standard serde behavior for an unknown
field). What this crate does **not** do is check the secret against
anything — actually verifying it against a server's own ledger (accepting or
rejecting a send based on it) is separate, server-side work.

## Status

This is a fresh copy of the mail logic from `artisan_lib`, kept here to be
tweaked ahead of a full split. `artisan_middleware` still carries its own
copy of this logic for now; nothing there depends on this crate yet.
