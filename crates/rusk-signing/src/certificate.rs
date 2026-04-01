//! X.509 certificate handling for signature verification.
//!
//! Provides utilities for parsing and validating X.509 certificates
//! used in code signing, particularly for Sigstore/Fulcio certificates.

use chrono::{DateTime, TimeZone, Utc};
use x509_cert::der::Decode;
use x509_cert::certificate::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;

/// Parsed certificate information relevant to signature verification.
#[derive(Clone, Debug)]
pub struct CertificateInfo {
    /// Subject common name.
    pub subject_cn: Option<String>,
    /// Issuer common name.
    pub issuer_cn: Option<String>,
    /// Not valid before.
    pub not_before: DateTime<Utc>,
    /// Not valid after.
    pub not_after: DateTime<Utc>,
    /// OIDC issuer from SAN extension (if present).
    pub oidc_issuer: Option<String>,
    /// OIDC subject from SAN extension (if present).
    pub oidc_subject: Option<String>,
    /// GitHub workflow ref (if present).
    pub github_workflow_ref: Option<String>,
    /// Public key algorithm.
    pub key_algorithm: String,
    /// DER-encoded subject public key bytes.
    pub public_key_der: Vec<u8>,
    /// SAN email addresses extracted from the certificate.
    pub san_emails: Vec<String>,
    /// SAN URIs extracted from the certificate.
    pub san_uris: Vec<String>,
    /// SAN DNS names extracted from the certificate.
    pub san_dns_names: Vec<String>,
}

impl CertificateInfo {
    /// Check if the certificate is valid at the given time.
    pub fn is_valid_at(&self, time: &DateTime<Utc>) -> bool {
        *time >= self.not_before && *time <= self.not_after
    }

    /// Check if this is a Fulcio-issued certificate (short-lived, OIDC-bound).
    pub fn is_fulcio_cert(&self) -> bool {
        self.oidc_issuer.is_some() && self.oidc_subject.is_some()
    }
}

/// Convert an x509-cert `Time` value to a `chrono::DateTime<Utc>`.
fn x509_time_to_chrono(time: &x509_cert::time::Time) -> Result<DateTime<Utc>, String> {
    let dt = time.to_date_time();
    Utc.with_ymd_and_hms(
        dt.year() as i32,
        dt.month().into(),
        dt.day().into(),
        dt.hour().into(),
        dt.minutes().into(),
        dt.seconds().into(),
    )
    .single()
    .ok_or_else(|| "ambiguous or invalid datetime conversion".to_string())
}

/// Extract the Common Name (CN) from an X.501 Name (RDN sequence).
///
/// Iterates over the RDN sequence looking for the OID 2.5.4.3 (id-at-commonName).
fn extract_cn(name: &x509_cert::name::Name) -> Option<String> {
    // OID for commonName: 2.5.4.3
    let cn_oid = x509_cert::der::oid::ObjectIdentifier::new_unwrap("2.5.4.3");

    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == cn_oid {
                // The value is a DER-encoded ANY; try to decode as common string types.
                let raw_bytes = atv.value.value();
                // Try decoding as UTF8String
                if let Ok(s) = x509_cert::der::asn1::Utf8StringRef::from_der(raw_bytes) {
                    return Some(s.as_str().to_string());
                }
                // Try decoding as PrintableString
                if let Ok(s) = x509_cert::der::asn1::PrintableStringRef::from_der(raw_bytes) {
                    return Some(s.as_str().to_string());
                }
                // Try decoding as IA5String
                if let Ok(s) = x509_cert::der::asn1::Ia5StringRef::from_der(raw_bytes) {
                    return Some(s.as_str().to_string());
                }
                // Fallback: treat the raw value bytes as lossy UTF-8.
                return Some(String::from_utf8_lossy(raw_bytes).to_string());
            }
        }
    }
    None
}

/// Determine the public key algorithm name from the SPKI algorithm identifier.
fn algorithm_name(alg_id: &x509_cert::spki::AlgorithmIdentifierOwned) -> String {
    let oid_str = alg_id.oid.to_string();
    match oid_str.as_str() {
        // RSA PKCS#1
        "1.2.840.113549.1.1.1" => "RSA".to_string(),
        // id-ecPublicKey
        "1.2.840.10045.2.1" => {
            // Check curve parameter OID if available
            if let Some(params) = &alg_id.parameters {
                let param_bytes = params.value();
                if let Ok(curve_oid) =
                    x509_cert::der::oid::ObjectIdentifier::from_der(param_bytes)
                {
                    let curve = curve_oid.to_string();
                    return match curve.as_str() {
                        "1.2.840.10045.3.1.7" => "ECDSA-P256".to_string(),
                        "1.3.132.0.34" => "ECDSA-P384".to_string(),
                        "1.3.132.0.35" => "ECDSA-P521".to_string(),
                        _ => format!("ECDSA({})", curve),
                    };
                }
                "ECDSA".to_string()
            } else {
                "ECDSA".to_string()
            }
        }
        // Ed25519
        "1.3.101.112" => "Ed25519".to_string(),
        // Ed448
        "1.3.101.113" => "Ed448".to_string(),
        other => format!("Unknown({})", other),
    }
}

/// Decode a PEM-encoded string to DER bytes.
///
/// Strips the PEM header/footer and decodes the base64 payload.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let pem = pem.trim();

    // Find the base64 content between the PEM boundaries
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = pem
        .find(start_marker)
        .ok_or("missing PEM BEGIN marker")?
        + start_marker.len();
    let end = pem.find(end_marker).ok_or("missing PEM END marker")?;

    let b64_content: String = pem[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // Simple base64 decode (RFC 4648 standard alphabet)
    base64_decode(&b64_content).map_err(|e| format!("base64 decode error: {}", e))
}

/// Minimal base64 decoder (standard alphabet, no padding required).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 128] = &{
        let mut table = [255u8; 128];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            table[alphabet[i] as usize] = i as u8;
            i += 1;
        }
        table[b'=' as usize] = 0; // padding
        table
    };

    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in bytes {
        if b == b'=' {
            break;
        }
        if b > 127 {
            return Err("invalid base64 character".to_string());
        }
        let val = TABLE[b as usize];
        if val == 255 {
            return Err(format!("invalid base64 character: {}", b as char));
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

/// Parse certificate information from DER-encoded bytes.
pub fn parse_certificate_der(der_bytes: &[u8]) -> Result<CertificateInfo, String> {
    let cert = Certificate::from_der(der_bytes)
        .map_err(|e| format!("failed to parse DER certificate: {}", e))?;

    let tbs = &cert.tbs_certificate;

    let subject_cn = extract_cn(&tbs.subject);
    let issuer_cn = extract_cn(&tbs.issuer);

    let not_before = x509_time_to_chrono(&tbs.validity.not_before)?;
    let not_after = x509_time_to_chrono(&tbs.validity.not_after)?;

    let key_algorithm = algorithm_name(&tbs.subject_public_key_info.algorithm);
    let public_key_der = tbs
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec();

    // Extract SAN extension
    let mut san_emails = Vec::new();
    let mut san_uris = Vec::new();
    let mut san_dns_names = Vec::new();
    let mut oidc_issuer = None;
    let mut oidc_subject = None;
    let mut github_workflow_ref = None;

    if let Ok(Some((_critical, san))) = tbs.get::<SubjectAltName>() {
        for name in san.0.iter() {
            match name {
                GeneralName::Rfc822Name(email) => {
                    let email_str = email.as_str().to_string();
                    // In Fulcio certificates, the email SAN is the OIDC subject
                    if oidc_subject.is_none() {
                        oidc_subject = Some(email_str.clone());
                    }
                    san_emails.push(email_str);
                }
                GeneralName::UniformResourceIdentifier(uri) => {
                    let uri_str = uri.as_str().to_string();
                    // Fulcio certificates may encode OIDC issuer as a URI SAN.
                    // GitHub Actions tokens produce URIs like
                    // https://github.com/owner/repo/.github/workflows/...
                    if uri_str.contains("github.com") && uri_str.contains(".github/workflows") {
                        github_workflow_ref = Some(uri_str.clone());
                    }
                    if oidc_subject.is_none() {
                        oidc_subject = Some(uri_str.clone());
                    }
                    san_uris.push(uri_str);
                }
                GeneralName::DnsName(dns) => {
                    san_dns_names.push(dns.as_str().to_string());
                }
                _ => {}
            }
        }
    }

    // Fulcio certificates encode the OIDC issuer in extension OID
    // 1.3.6.1.4.1.57264.1.1 (Fulcio OIDC Issuer).
    // We look for it in the raw extensions.
    let fulcio_issuer_oid =
        x509_cert::der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");
    if let Some(exts) = &tbs.extensions {
        for ext in exts.iter() {
            if ext.extn_id == fulcio_issuer_oid {
                // The value is a DER-encoded UTF8String or IA5String.
                let raw = ext.extn_value.as_bytes();
                if let Ok(s) = x509_cert::der::asn1::Utf8StringRef::from_der(raw) {
                    oidc_issuer = Some(s.as_str().to_string());
                } else if let Ok(s) = x509_cert::der::asn1::Ia5StringRef::from_der(raw) {
                    oidc_issuer = Some(s.as_str().to_string());
                } else if let Ok(s) = std::str::from_utf8(raw) {
                    // Some certs may have raw string bytes without ASN.1 wrapping
                    oidc_issuer = Some(s.to_string());
                }
            }
        }
    }

    // If we found a subject but no explicit Fulcio issuer, check the
    // certificate issuer CN for a Fulcio indicator.
    if oidc_issuer.is_none() {
        if let Some(ref cn) = issuer_cn {
            if cn.contains("fulcio") || cn.contains("sigstore") {
                oidc_issuer = Some(format!("urn:fulcio:issuer:{}", cn));
            }
        }
    }

    Ok(CertificateInfo {
        subject_cn,
        issuer_cn,
        not_before,
        not_after,
        oidc_issuer,
        oidc_subject,
        github_workflow_ref,
        key_algorithm,
        public_key_der,
        san_emails,
        san_uris,
        san_dns_names,
    })
}

/// Parse basic certificate information from a PEM-encoded certificate.
pub fn parse_certificate_info(pem: &str) -> Result<CertificateInfo, String> {
    let der_bytes = pem_to_der(pem)?;
    parse_certificate_der(&der_bytes)
}

/// Validate that two certificates form a valid issuer-subject chain link.
///
/// Checks that the subject's issuer name matches the issuer's subject name,
/// and that the subject certificate's validity falls within the issuer's validity.
pub fn validate_chain_link(
    issuer_info: &CertificateInfo,
    subject_info: &CertificateInfo,
) -> Result<(), String> {
    // Check that the issuer names match
    if issuer_info.subject_cn != subject_info.issuer_cn {
        return Err(format!(
            "issuer name mismatch: issuer subject CN is {:?}, but child issuer CN is {:?}",
            issuer_info.subject_cn, subject_info.issuer_cn
        ));
    }

    // Check that the subject certificate's validity period is within the issuer's
    if subject_info.not_before < issuer_info.not_before {
        return Err(format!(
            "subject not_before ({}) precedes issuer not_before ({})",
            subject_info.not_before, issuer_info.not_before
        ));
    }

    if subject_info.not_after > issuer_info.not_after {
        return Err(format!(
            "subject not_after ({}) exceeds issuer not_after ({})",
            subject_info.not_after, issuer_info.not_after
        ));
    }

    Ok(())
}

/// Check if a certificate is currently within its validity period.
pub fn is_certificate_valid_now(info: &CertificateInfo) -> bool {
    info.is_valid_at(&Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let encoded = "SGVsbG8gV29ybGQ=";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_validity_check() {
        let info = CertificateInfo {
            subject_cn: Some("test".to_string()),
            issuer_cn: Some("issuer".to_string()),
            not_before: Utc::now() - chrono::Duration::hours(1),
            not_after: Utc::now() + chrono::Duration::hours(1),
            oidc_issuer: None,
            oidc_subject: None,
            github_workflow_ref: None,
            key_algorithm: "ECDSA-P256".to_string(),
            public_key_der: vec![],
            san_emails: vec![],
            san_uris: vec![],
            san_dns_names: vec![],
        };

        assert!(info.is_valid_at(&Utc::now()));
        assert!(!info.is_valid_at(&(Utc::now() + chrono::Duration::hours(2))));
    }

    #[test]
    fn test_fulcio_cert_detection() {
        let info = CertificateInfo {
            subject_cn: None,
            issuer_cn: None,
            not_before: Utc::now(),
            not_after: Utc::now(),
            oidc_issuer: Some("https://accounts.google.com".to_string()),
            oidc_subject: Some("user@example.com".to_string()),
            github_workflow_ref: None,
            key_algorithm: "ECDSA-P256".to_string(),
            public_key_der: vec![],
            san_emails: vec!["user@example.com".to_string()],
            san_uris: vec![],
            san_dns_names: vec![],
        };

        assert!(info.is_fulcio_cert());
    }

    #[test]
    fn test_chain_link_validation() {
        let issuer = CertificateInfo {
            subject_cn: Some("Issuer CA".to_string()),
            issuer_cn: Some("Root CA".to_string()),
            not_before: Utc::now() - chrono::Duration::days(365),
            not_after: Utc::now() + chrono::Duration::days(365),
            oidc_issuer: None,
            oidc_subject: None,
            github_workflow_ref: None,
            key_algorithm: "ECDSA-P256".to_string(),
            public_key_der: vec![],
            san_emails: vec![],
            san_uris: vec![],
            san_dns_names: vec![],
        };

        let subject = CertificateInfo {
            subject_cn: Some("leaf@example.com".to_string()),
            issuer_cn: Some("Issuer CA".to_string()),
            not_before: Utc::now() - chrono::Duration::hours(1),
            not_after: Utc::now() + chrono::Duration::hours(1),
            oidc_issuer: None,
            oidc_subject: None,
            github_workflow_ref: None,
            key_algorithm: "ECDSA-P256".to_string(),
            public_key_der: vec![],
            san_emails: vec![],
            san_uris: vec![],
            san_dns_names: vec![],
        };

        assert!(validate_chain_link(&issuer, &subject).is_ok());
    }

    #[test]
    fn test_chain_link_name_mismatch() {
        let issuer = CertificateInfo {
            subject_cn: Some("Wrong CA".to_string()),
            issuer_cn: None,
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(365),
            oidc_issuer: None,
            oidc_subject: None,
            github_workflow_ref: None,
            key_algorithm: "RSA".to_string(),
            public_key_der: vec![],
            san_emails: vec![],
            san_uris: vec![],
            san_dns_names: vec![],
        };

        let subject = CertificateInfo {
            subject_cn: Some("leaf".to_string()),
            issuer_cn: Some("Expected CA".to_string()),
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::hours(1),
            oidc_issuer: None,
            oidc_subject: None,
            github_workflow_ref: None,
            key_algorithm: "RSA".to_string(),
            public_key_der: vec![],
            san_emails: vec![],
            san_uris: vec![],
            san_dns_names: vec![],
        };

        assert!(validate_chain_link(&issuer, &subject).is_err());
    }
}
