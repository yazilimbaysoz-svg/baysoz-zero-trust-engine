//! BAYSOZ YAZILIM - Zero-Trust Cryptographic Command Authentication Core
//! Standard: 2026-2027 Memory-Safe Production Rust

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDirective {
    pub department_code: String,
    pub payload: String,
    pub signature_hex: String,
}

pub fn sign_directive(department_code: &str, payload: &str, secret_key: &[u8]) -> SignedDirective {
    let mut hasher = Sha256::new();
    hasher.update(department_code.as_bytes());
    hasher.update(b"::");
    hasher.update(payload.as_bytes());
    hasher.update(b"::");
    hasher.update(secret_key);
    let digest = hasher.finalize();

    SignedDirective {
        department_code: department_code.to_string(),
        payload: payload.to_string(),
        signature_hex: hex::encode(digest),
    }
}

pub fn verify_directive(directive: &SignedDirective, secret_key: &[u8]) -> bool {
    let expected = sign_directive(&directive.department_code, &directive.payload, secret_key);
    expected.signature_hex == directive.signature_hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_directive_authentication() {
        let key = b"BAYSOZ-ZERO-TRUST-MASTER-KEY-2026";
        let signed = sign_directive("08-CYBER-SEC", "EXECUTE_SANDBOX_SCAN", key);
        assert!(verify_directive(&signed, key));
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let key = b"BAYSOZ-ZERO-TRUST-MASTER-KEY-2026";
        let mut signed = sign_directive("08-CYBER-SEC", "EXECUTE_SANDBOX_SCAN", key);
        signed.payload = "UNAUTHORIZED_EXFILTRATION".to_string();
        assert!(!verify_directive(&signed, key));
    }
}
