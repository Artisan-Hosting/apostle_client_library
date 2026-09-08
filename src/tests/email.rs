#[cfg(test)]
mod tests {
    use crate::Email;
    use dusa_collection_utils::core::types::stringy::Stringy;

    #[test]
    fn test_email_validation() {
        let email = Email::new(
            Stringy::from("dwhitfield@artisanhosting.net"),
            Stringy::from("sub"),
            Stringy::from("body"),
        );
        assert!(email.is_valid());
        let invalid = Email::new(
            Stringy::from("dwhitfield@artisanhosting.net"),
            Stringy::from(""),
            Stringy::from(""),
        );
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_email_json_roundtrip() {
        let email = Email::new(
            Stringy::from("dwhitfield@artisanhosting.net"),
            Stringy::from("hello"),
            Stringy::from("world"),
        );
        let json = email.to_json().unwrap();
        let parsed = Email::from_json(&json).unwrap();
        assert_eq!(email.subject, parsed.subject);
        assert_eq!(email.body, parsed.body);
    }
}
