#[cfg(target_os = "linux")]
use colored::Colorize;
use dusa_collection_utils::{
    core::errors::{ErrorArrayItem, Errors},
    core::logger::LogLevel,
    core::types::stringy::Stringy,
    log,
};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use simple_comms::{
    network::send_receive::{establish_connection_initiator, send_message},
    protocol::{flags::ConnectionParams, message::ConnectionCtx, proto::Proto},
};
use std::fmt;
#[cfg(target_os = "linux")]
use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
use crate::bundle::MailBundle;

/// Represents an email message containing a subject and a body.
///
/// # Overview
///
/// - **Subject** (`Stringy`): The headline or topic of the email.
/// - **Body** (`Stringy`): The main content of the email.
///
/// This struct provides methods for creating, validating, converting to/from JSON,
/// and sending the email over a TCP stream to a mail server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Email {
    pub destination: Stringy,
    /// The subject of the email message.
    pub subject: Stringy,
    /// The body content of the email message.
    pub body: Stringy,
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "To: {}, Subject: {}, Body: {}",
            self.destination.bold().green(),
            self.subject.bold().blue(),
            self.body.bold().blue()
        )
    }
}

impl Email {
    /// Creates a new `Email` instance with the provided subject and body.
    ///
    /// # Arguments
    ///
    /// * `subject` - A [`Stringy`] value representing the email's subject line.
    /// * `body` - A [`Stringy`] value representing the email's main content.
    ///
    /// # Example
    /// ```rust
    /// # use dusa_collection_utils::core::types::stringy::Stringy;
    /// # use apostle_client::Email;
    /// let destination = Stringy::from("dwhitfield@artisanhosting.net");
    /// let subject = Stringy::from("Greetings");
    /// let body = Stringy::from("Hello, how are you?");
    /// let email = Email::new(destination, subject, body);
    /// ```
    pub fn new(destination: Stringy, subject: Stringy, body: Stringy) -> Self {
        Email {
            destination,
            subject,
            body,
        }
    }

    /// Checks if the `Email` fields are valid (i.e., not empty).
    ///
    /// # Returns
    ///
    /// * `true` if both `subject` and `body` are non-empty.
    /// * `false` otherwise.
    ///
    /// # Example
    /// ```rust
    /// # use apostle_client::Email;
    /// let email = Email::new("dwhitfield@artisanhosting.net".into(), "Subject".into(), "Body".into());
    /// assert!(email.is_valid());
    /// ```
    pub fn is_valid(&self) -> bool {
        !self.subject.is_empty() && !self.body.is_empty() && !self.destination.is_empty()
    }

    /// Converts this `Email` instance to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorArrayItem`] if the serialization fails.
    ///
    /// # Example
    /// ```rust
    /// # use apostle_client::Email;
    /// let email = Email::new("dwhitfield@artisanhosting.net".into(), "Subject".into(), "Body".into());
    /// match email.to_json() {
    ///     Ok(json_str) => println!("JSON: {}", json_str),
    ///     Err(err) => eprintln!("Could not serialize email: {}", err),
    /// }
    /// ```
    pub fn to_json(&self) -> Result<String, ErrorArrayItem> {
        serde_json::to_string(self).map_err(ErrorArrayItem::from)
    }

    /// Creates an `Email` instance from a JSON string.
    ///
    /// # Arguments
    ///
    /// * `json_data` - The JSON representation of an `Email`.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorArrayItem`] if deserialization fails.
    ///
    /// # Example
    /// ```rust
    /// # use apostle_client::Email;
    /// let json_data = r#"{"destination":"dwhitfield@artisanhosting.net","subject":"Hello","body":"World"}"#;
    /// match Email::from_json(json_data) {
    ///     Ok(email) => println!("Email Subject: {}", email.subject),
    ///     Err(err) => eprintln!("Could not deserialize email: {}", err),
    /// }
    /// ```
    pub fn from_json(json_data: &str) -> Result<Self, ErrorArrayItem> {
        serde_json::from_str(json_data).map_err(ErrorArrayItem::from)
    }
}

/// Wire payload for one `send()` call. `Email`'s own fields are flattened at the top
/// level so the JSON shape is byte-for-byte identical to plain `Email::to_json()` when
/// `identity_secret` is absent — a server that doesn't yet understand identity secrets
/// (or a bundle with none baked in, e.g. the shared/base bundle) sees exactly the same
/// payload as before this field existed.
#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct MailRequest<'a> {
    #[serde(flatten)]
    email: &'a Email,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_secret: Option<[u8; 4]>,
}

#[cfg(target_os = "linux")]
impl Email {
    /// Sends this `Email` over a TCP stream to the mail server described by `bundle`.
    ///
    /// `bundle`'s [`MailServerConfig`](crate::bundle::MailServerConfig) is resolved into
    /// one or more candidate addresses, which are tried in order until one connects.
    /// `bundle.server_pub_key` pins the server's static Noise identity. If `bundle` was
    /// personalized via `ledger::issue_bundle`, `bundle.identity_secret` is sent
    /// alongside the email data as an extra `identity_secret` field (see
    /// [`MailRequest`]) — this crate only transmits it; checking it against a server's
    /// own ledger is separate, server-side work.
    ///
    /// # Errors
    ///
    /// - **`Errors::GeneralError`** if `subject` or `body` is empty.
    /// - **`Errors::ConnectionError`** if none of the candidate addresses could be reached,
    ///   or if resolving a domain-based config fails.
    /// - **Other** potential errors based on serialization or the underlying protocol.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use tokio::runtime::Runtime;
    /// # use dusa_collection_utils::core::types::stringy::Stringy;
    /// # use apostle_client::{Email, MailBundle};
    /// # let rt = Runtime::new().unwrap();
    /// # rt.block_on(async {
    /// let bundle = MailBundle::load("/etc/apostle_client/bundle.acai".as_ref()).unwrap();
    /// let email = Email::new(Stringy::from("dwhitfield@artisanhosting.net"), Stringy::from("Test Subject"), Stringy::from("Test Body"));
    /// let result = email.send(&bundle).await;
    /// match result {
    ///     Ok(_) => println!("Email sent successfully!"),
    ///     Err(err) => eprintln!("Failed to send email: {}", err),
    /// }
    /// # });
    /// ```
    #[rustfmt::skip]
    pub async fn send(&self, bundle: &MailBundle) -> Result<(), ErrorArrayItem> {
        // Validate email fields
        if !self.is_valid() {
            return Err(ErrorArrayItem::new(
                Errors::GeneralError,
                "Invalid Email Data".to_owned(),
            ));
        }

        let candidates = bundle.server_config.resolve().await?;

        let mut stream: TcpStream = {
            let mut last_err: Option<ErrorArrayItem> = None;
            let mut connected: Option<TcpStream> = None;

            for addr in &candidates {
                match TcpStream::connect(addr).await {
                    Ok(res) => {
                        log!{LogLevel::Trace, "Connected to: {:#?}", res.peer_addr()?};
                        connected = Some(res);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(ErrorArrayItem::new(Errors::ConnectionError,
                            format!("Failed to connect to mailserver: {}. {}", addr, e)));
                    }
                }
            }

            connected.ok_or_else(|| last_err.unwrap_or_else(|| ErrorArrayItem::new(
                Errors::ConnectionError,
                "no mailserver addresses to try".to_owned(),
            )))?
        };

        let mut conn: ConnectionCtx = establish_connection_initiator(&mut stream, &bundle.server_pub_key, ConnectionParams::OPTIMIZED).await?;

        let request = MailRequest {
            email: self,
            identity_secret: bundle.identity_secret,
        };
        let email_data: String = serde_json::to_string(&request).map_err(ErrorArrayItem::from)?;

        let _: () = send_message(&mut stream, email_data, Proto::TCP, &mut conn).await?;

        Ok(())
    }

    pub fn validate_destination(destination: &str) -> Result<(), ErrorArrayItem> {
        let trimmed = destination.trim();
        if trimmed.is_empty() {
            return Err(ErrorArrayItem::new(
                Errors::GeneralError,
                "email destination cannot be empty",
            ));
        }

        if trimmed.len() > 254 {
            return Err(ErrorArrayItem::new(
                Errors::GeneralError,
                "email destination is too long",
            ));
        }

        if trimmed.contains(' ') {
            return Err(ErrorArrayItem::new(
                Errors::GeneralError,
                "email destination contains whitespace",
            ));
        }

        let mut parts = trimmed.split('@');
        let local = parts.next().unwrap_or("");
        let domain = parts.next().unwrap_or("");

        if local.is_empty() || domain.is_empty() || parts.next().is_some() {
            return Err(ErrorArrayItem::new(
                Errors::GeneralError,
                "email destination is not a valid address",
            ));
        }

        if !domain.contains('.') {
            return Err(ErrorArrayItem::new(
                Errors::GeneralError,
                "email destination domain must contain a dot",
            ));
        }

        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod wire_payload_tests {
    use super::*;

    fn sample_email() -> Email {
        Email::new(
            Stringy::from("dwhitfield@artisanhosting.net"),
            Stringy::from("sub"),
            Stringy::from("body"),
        )
    }

    #[test]
    fn omits_identity_secret_when_absent() {
        let email = sample_email();
        let request = MailRequest {
            email: &email,
            identity_secret: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(json, email.to_json().unwrap());
        assert!(!json.contains("identity_secret"));
    }

    #[test]
    fn includes_identity_secret_when_present() {
        let email = sample_email();
        let request = MailRequest {
            email: &email,
            identity_secret: Some([1, 2, 3, 4]),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains(r#""identity_secret":[1,2,3,4]"#));
        // The email's own fields are still flattened at the top level, not nested.
        assert!(json.contains(r#""destination":"dwhitfield@artisanhosting.net""#));
    }
}
