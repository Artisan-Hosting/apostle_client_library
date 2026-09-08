//! Small manual test harness for `apostle_client::Email`.
//!
//! Usage:
//!   cargo run --example test_email -- <destination> <bundle_path> [subject] [body]
//!
//! `bundle_path` points at a `.acai` bundle (built by `acai_core`) containing
//! `config.json` (mail server address(es)/domain) and `mail_server_pub.der`
//! (the server's pinned X25519 public key). See the crate README for how to
//! build one.
//!
//! Examples:
//!   cargo run --example test_email -- someone@example.com ./bundle.acai
//!   cargo run --example test_email -- someone@example.com ./bundle.acai "Hi" "Test body"

use apostle_client::Email;
use dusa_collection_utils::core::types::stringy::Stringy;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);

    let destination = args
        .next()
        .unwrap_or_else(|| "test@example.com".to_string());
    let bundle_path = args.next();
    let subject = args
        .next()
        .unwrap_or_else(|| "Test Subject".to_string());
    let body = args
        .next()
        .unwrap_or_else(|| "Test body from test_email example".to_string());

    let email = Email::new(
        Stringy::from(destination),
        Stringy::from(subject),
        Stringy::from(body),
    );

    println!("Constructed: {}", email);
    println!("is_valid(): {}", email.is_valid());

    let json = email.to_json().expect("failed to serialize email");
    println!("to_json(): {}", json);

    let round_tripped = Email::from_json(&json).expect("failed to deserialize email");
    println!("from_json() round trip: {}", round_tripped);
    assert_eq!(email.destination, round_tripped.destination);
    assert_eq!(email.subject, round_tripped.subject);
    assert_eq!(email.body, round_tripped.body);
    println!("Round trip OK.");

    #[cfg(target_os = "linux")]
    {
        use apostle_client::MailBundle;

        let Some(bundle_path) = bundle_path else {
            eprintln!("Usage: test_email -- <destination> <bundle_path> [subject] [body]");
            return;
        };

        match MailBundle::load(bundle_path.as_ref()) {
            Ok(bundle) => {
                println!("Loaded bundle from {bundle_path}, sending...");
                match email.send(&bundle).await {
                    Ok(()) => println!("Email sent successfully!"),
                    Err(err) => eprintln!("Failed to send email: {err}"),
                }
            }
            Err(err) => eprintln!("Failed to load bundle: {err}"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = bundle_path;
        println!("send() is only available on Linux targets; skipping.");
    }
}
