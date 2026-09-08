use std::{net::SocketAddr, path::Path};

use dusa_collection_utils::core::errors::{ErrorArrayItem, Errors};
use serde::{Deserialize, Serialize};

use crate::keys::parse_x25519_spki_der;

/// File name of the JSON config entry inside a mail server `.acai` bundle.
const CONFIG_ENTRY: &str = "config.json";
/// File name of the X25519 public key (DER `SubjectPublicKeyInfo`) entry inside a
/// mail server `.acai` bundle.
const KEY_ENTRY: &str = "mail_server_pub.der";

/// TLV type used for a bundle's per-identity secret, in acai-core's
/// "Private / application-defined" range (`0x8000..=0xFFFF`). Lives here (rather than
/// in the `server-components`-gated `ledger` module) because every client — not just
/// server/issuance builds — needs to read it back out of its own bundle.
pub const LEDGER_SECRET_TLV_TYPE: u16 = 0xc001;

/// Where to reach the mail server: either a fixed list of `host:port` addresses,
/// or a domain name (plus port) to resolve at connect time.
///
/// # JSON shapes
///
/// ```json
/// { "addresses": ["172.237.134.238:1827", "172.234.222.191:1827"] }
/// ```
/// ```json
/// { "domain": "mail.artisanhosting.net", "port": 1827 }
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MailServerConfig {
    Addresses { addresses: Vec<String> },
    Domain { domain: String, port: u16 },
}

impl MailServerConfig {
    /// Resolves this config into one or more candidate [`SocketAddr`]s, in order.
    pub async fn resolve(&self) -> Result<Vec<SocketAddr>, ErrorArrayItem> {
        match self {
            Self::Addresses { addresses } => addresses
                .iter()
                .map(|addr| {
                    addr.parse::<SocketAddr>().map_err(|err| {
                        ErrorArrayItem::new(
                            Errors::ConfigParsing,
                            format!("invalid address '{addr}': {err}"),
                        )
                    })
                })
                .collect(),
            Self::Domain { domain, port } => {
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host((domain.as_str(), *port))
                    .await
                    .map_err(|err| {
                        ErrorArrayItem::new(
                            Errors::ConnectionError,
                            format!("failed to resolve '{domain}': {err}"),
                        )
                    })?
                    .collect();

                if addrs.is_empty() {
                    return Err(ErrorArrayItem::new(
                        Errors::NotFound,
                        format!("no addresses found for '{domain}'"),
                    ));
                }

                Ok(addrs)
            }
        }
    }
}

/// The mail server's connection info and pinned static public key, read out of an
/// `.acai` bundle produced by `acai_core`. `identity_secret` is present only for a
/// bundle personalized for a specific user via [`crate::ledger::issue_bundle`] — a
/// shared/base bundle has no such TLV and loads with `identity_secret: None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailBundle {
    pub server_config: MailServerConfig,
    pub server_pub_key: [u8; 32],
    pub identity_secret: Option<[u8; 4]>,
}

impl MailBundle {
    /// Loads a bundle from the `.acai` container at `bundle_path`, reading out
    /// [`CONFIG_ENTRY`] and [`KEY_ENTRY`] via `acai_core::reader::read_file`, plus the
    /// optional identity secret TLV via `acai_core::reader::read_state_tlv`. None of
    /// this crate's bundles are encrypted, so `read_file`'s passphrase is always `None`.
    pub fn load(bundle_path: &Path) -> Result<Self, ErrorArrayItem> {
        let bytes = std::fs::read(bundle_path).map_err(|err| {
            ErrorArrayItem::new(
                Errors::OpeningFile,
                format!("{}: {err}", bundle_path.display()),
            )
        })?;

        let config_bytes = acai_core::reader::read_file(&bytes, CONFIG_ENTRY, None)
            .map_err(|err| ErrorArrayItem::new(Errors::ConfigReading, err.to_string()))?;
        let key_bytes = acai_core::reader::read_file(&bytes, KEY_ENTRY, None)
            .map_err(|err| ErrorArrayItem::new(Errors::ConfigReading, err.to_string()))?;
        let secret_bytes = acai_core::reader::read_state_tlv(&bytes, LEDGER_SECRET_TLV_TYPE)
            .map_err(|err| ErrorArrayItem::new(Errors::ConfigReading, err.to_string()))?;

        let server_config: MailServerConfig = serde_json::from_slice(&config_bytes)?;
        let server_pub_key = parse_x25519_spki_der(&key_bytes)?;
        let identity_secret = secret_bytes
            .map(|v| {
                <[u8; 4]>::try_from(v.as_slice()).map_err(|_| {
                    ErrorArrayItem::new(
                        Errors::ConfigParsing,
                        "identity secret TLV was not 4 bytes".to_owned(),
                    )
                })
            })
            .transpose()?;

        Ok(Self {
            server_config,
            server_pub_key,
            identity_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_addresses_shape() {
        let json = r#"{"addresses":["172.237.134.238:1827","172.234.222.191:1827"]}"#;
        let cfg: MailServerConfig = serde_json::from_str(json).expect("should deserialize");
        match cfg {
            MailServerConfig::Addresses { addresses } => assert_eq!(addresses.len(), 2),
            _ => panic!("expected Addresses variant"),
        }
    }

    #[test]
    fn deserializes_domain_shape() {
        let json = r#"{"domain":"mail.artisanhosting.net","port":1827}"#;
        let cfg: MailServerConfig = serde_json::from_str(json).expect("should deserialize");
        match cfg {
            MailServerConfig::Domain { domain, port } => {
                assert_eq!(domain, "mail.artisanhosting.net");
                assert_eq!(port, 1827);
            }
            _ => panic!("expected Domain variant"),
        }
    }

    #[tokio::test]
    async fn resolves_addresses_without_network() {
        let cfg = MailServerConfig::Addresses {
            addresses: vec!["172.237.134.238:1827".to_owned(), "172.234.222.191:1827".to_owned()],
        };
        let addrs = cfg.resolve().await.expect("should resolve");
        assert_eq!(addrs.len(), 2);
    }
}
