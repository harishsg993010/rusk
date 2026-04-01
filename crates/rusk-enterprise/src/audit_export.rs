//! Audit log export for compliance.
//!
//! Generates structured audit records of all trust-related operations
//! for export to enterprise compliance systems (SIEM, SBOM, etc.).
//! Supports JSON Lines, SPDX 2.3, and CycloneDX 1.5 export formats.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Format for exported audit records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// JSON Lines format (one record per line).
    #[default]
    JsonLines,
    /// SPDX SBOM format.
    Spdx,
    /// CycloneDX SBOM format.
    CycloneDx,
}

/// A single audit record capturing a trust-related event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique record ID.
    pub id: String,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Event type.
    pub event_type: AuditEventType,
    /// Package identifier (if applicable).
    pub package: Option<String>,
    /// Version (if applicable).
    pub version: Option<String>,
    /// The trust decision made.
    pub decision: String,
    /// Detailed event data.
    pub details: serde_json::Value,
}

/// Types of auditable events.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// A package was installed.
    Install,
    /// A package version was resolved.
    Resolve,
    /// Signature verification was performed.
    SignatureVerify,
    /// Provenance was checked.
    ProvenanceCheck,
    /// Policy was evaluated.
    PolicyEval,
    /// A revocation check was performed.
    RevocationCheck,
    /// Transparency log was consulted.
    TransparencyCheck,
}

/// Exports audit records to the configured destination.
pub struct AuditExporter {
    format: ExportFormat,
    records: Vec<AuditRecord>,
}

impl AuditExporter {
    /// Create a new exporter with the given format.
    pub fn new(format: ExportFormat) -> Self {
        Self {
            format,
            records: Vec::new(),
        }
    }

    /// Record an audit event.
    pub fn record(&mut self, record: AuditRecord) {
        tracing::debug!(
            event_type = ?record.event_type,
            package = ?record.package,
            "audit record"
        );
        self.records.push(record);
    }

    /// Export all records as a string in the configured format.
    pub fn export(&self) -> String {
        match self.format {
            ExportFormat::JsonLines => {
                self.records
                    .iter()
                    .filter_map(|r| serde_json::to_string(r).ok())
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            ExportFormat::Spdx => self.export_spdx(),
            ExportFormat::CycloneDx => self.export_cyclonedx(),
        }
    }

    /// Number of recorded events.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Get all records.
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Generate a valid SPDX 2.3 JSON document from the audit records.
    ///
    /// The document follows the SPDX 2.3 specification:
    /// - `spdxVersion`: "SPDX-2.3"
    /// - `dataLicense`: "CC0-1.0" (required by spec)
    /// - `SPDXID`: "SPDXRef-DOCUMENT"
    /// - `documentNamespace`: unique URI for this document
    /// - `packages`: one entry per install/resolve record with package info
    fn export_spdx(&self) -> String {
        let now = Utc::now().to_rfc3339();
        let doc_namespace = format!(
            "https://spdx.org/spdxdocs/rusk-audit-{}",
            uuid_v4_from_timestamp()
        );

        // Collect unique packages from audit records.
        let packages: Vec<serde_json::Value> = self
            .records
            .iter()
            .filter(|r| r.package.is_some())
            .enumerate()
            .map(|(idx, record)| {
                let pkg_name = record.package.as_deref().unwrap_or("unknown");
                let pkg_version = record.version.as_deref().unwrap_or("0.0.0");
                let spdx_id = format!("SPDXRef-Package-{}", idx);

                // Extract hash from details if available.
                let checksums = if let Some(hash) = record.details.get("sha256").and_then(|v| v.as_str()) {
                    serde_json::json!([{
                        "algorithm": "SHA256",
                        "checksumValue": hash
                    }])
                } else {
                    serde_json::json!([])
                };

                // Extract license from details if available.
                let license = record
                    .details
                    .get("license")
                    .and_then(|v| v.as_str())
                    .unwrap_or("NOASSERTION");

                serde_json::json!({
                    "SPDXID": spdx_id,
                    "name": pkg_name,
                    "versionInfo": pkg_version,
                    "downloadLocation": record.details.get("download_url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("NOASSERTION"),
                    "filesAnalyzed": false,
                    "checksums": checksums,
                    "licenseConcluded": license,
                    "licenseDeclared": license,
                    "copyrightText": "NOASSERTION",
                    "supplier": record.details.get("supplier")
                        .and_then(|v| v.as_str())
                        .map(|s| format!("Organization: {}", s))
                        .unwrap_or_else(|| "NOASSERTION".to_string()),
                    "externalRefs": [{
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": record.details.get("purl")
                            .and_then(|v| v.as_str())
                            .unwrap_or_else(|| "")
                    }]
                })
            })
            .collect();

        // Build the relationships: DOCUMENT DESCRIBES each package.
        let relationships: Vec<serde_json::Value> = packages
            .iter()
            .filter_map(|pkg| {
                pkg.get("SPDXID").and_then(|id| id.as_str()).map(|id| {
                    serde_json::json!({
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": id
                    })
                })
            })
            .collect();

        let spdx_doc = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "rusk-audit-sbom",
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": now,
                "creators": [
                    "Tool: rusk-enterprise",
                    "Organization: rusk"
                ],
                "licenseListVersion": "3.22"
            },
            "packages": packages,
            "relationships": relationships,
            "documentDescribes": packages.iter()
                .filter_map(|p| p.get("SPDXID").and_then(|v| v.as_str()))
                .collect::<Vec<&str>>()
        });

        serde_json::to_string_pretty(&spdx_doc).unwrap_or_else(|_| "{}".to_string())
    }

    /// Generate a valid CycloneDX 1.5 JSON document from the audit records.
    ///
    /// The document follows the CycloneDX 1.5 specification:
    /// - `bomFormat`: "CycloneDX"
    /// - `specVersion`: "1.5"
    /// - `serialNumber`: unique URN for this BOM
    /// - `components`: one entry per package with type, name, version, hashes, licenses
    fn export_cyclonedx(&self) -> String {
        let now = Utc::now().to_rfc3339();
        let serial_number = format!("urn:uuid:{}", uuid_v4_from_timestamp());

        // Collect components from audit records.
        let components: Vec<serde_json::Value> = self
            .records
            .iter()
            .filter(|r| r.package.is_some())
            .map(|record| {
                let pkg_name = record.package.as_deref().unwrap_or("unknown");
                let pkg_version = record.version.as_deref().unwrap_or("0.0.0");

                // Build hashes array.
                let mut hashes = Vec::new();
                if let Some(sha256) = record.details.get("sha256").and_then(|v| v.as_str()) {
                    hashes.push(serde_json::json!({
                        "alg": "SHA-256",
                        "content": sha256
                    }));
                }
                if let Some(sha512) = record.details.get("sha512").and_then(|v| v.as_str()) {
                    hashes.push(serde_json::json!({
                        "alg": "SHA-512",
                        "content": sha512
                    }));
                }

                // Build licenses array.
                let licenses = if let Some(license) = record.details.get("license").and_then(|v| v.as_str()) {
                    serde_json::json!([{
                        "license": {
                            "id": license
                        }
                    }])
                } else {
                    serde_json::json!([])
                };

                // Determine component type.
                let component_type = record
                    .details
                    .get("component_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("library");

                // Build purl if available.
                let purl = record.details.get("purl").and_then(|v| v.as_str());

                let mut component = serde_json::json!({
                    "type": component_type,
                    "name": pkg_name,
                    "version": pkg_version,
                    "hashes": hashes,
                    "licenses": licenses,
                });

                if let Some(purl_str) = purl {
                    component.as_object_mut().unwrap().insert(
                        "purl".to_string(),
                        serde_json::Value::String(purl_str.to_string()),
                    );
                }

                // Add supplier/author info if available.
                if let Some(supplier) = record.details.get("supplier").and_then(|v| v.as_str()) {
                    component.as_object_mut().unwrap().insert(
                        "supplier".to_string(),
                        serde_json::json!({ "name": supplier }),
                    );
                }

                // Add scope (required/optional/excluded).
                if let Some(scope) = record.details.get("scope").and_then(|v| v.as_str()) {
                    component
                        .as_object_mut()
                        .unwrap()
                        .insert("scope".to_string(), serde_json::Value::String(scope.to_string()));
                }

                component
            })
            .collect();

        let cdx_doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "timestamp": now,
                "tools": [{
                    "vendor": "rusk",
                    "name": "rusk-enterprise",
                    "version": env!("CARGO_PKG_VERSION")
                }],
                "component": {
                    "type": "application",
                    "name": "rusk-project",
                    "version": "0.0.0"
                }
            },
            "components": components
        });

        serde_json::to_string_pretty(&cdx_doc).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Generate a deterministic UUID-like string from the current timestamp.
/// This is not a true UUID v4 but provides uniqueness for document identifiers.
fn uuid_v4_from_timestamp() -> String {
    let now = Utc::now();
    let nanos = now.timestamp_nanos_opt().unwrap_or(0) as u64;
    // Mix bits for better distribution
    let a = (nanos >> 32) as u32;
    let b = (nanos & 0xFFFF_FFFF) as u32;
    let c = a.wrapping_mul(2654435761); // Knuth multiplicative hash
    let d = b.wrapping_mul(2246822519);
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        a,
        (b >> 16) & 0xFFFF,
        c & 0x0FFF,
        0x8000 | (d & 0x3FFF),
        (nanos ^ (c as u64) ^ (d as u64)) & 0xFFFF_FFFF_FFFF
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_install_record(name: &str, version: &str) -> AuditRecord {
        AuditRecord {
            id: format!("rec-{}-{}", name, version),
            timestamp: Utc::now(),
            event_type: AuditEventType::Install,
            package: Some(name.to_string()),
            version: Some(version.to_string()),
            decision: "allowed".to_string(),
            details: serde_json::json!({
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "license": "MIT",
                "purl": format!("pkg:npm/{}@{}", name, version),
                "supplier": "npm-registry"
            }),
        }
    }

    #[test]
    fn json_lines_export() {
        let mut exporter = AuditExporter::new(ExportFormat::JsonLines);
        exporter.record(make_install_record("express", "4.18.2"));
        exporter.record(make_install_record("lodash", "4.17.21"));

        let output = exporter.export();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON.
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("package").is_some());
        }
    }

    #[test]
    fn spdx_export_structure() {
        let mut exporter = AuditExporter::new(ExportFormat::Spdx);
        exporter.record(make_install_record("express", "4.18.2"));
        exporter.record(make_install_record("lodash", "4.17.21"));

        let output = exporter.export();
        let doc: serde_json::Value = serde_json::from_str(&output).unwrap();

        // Validate SPDX 2.3 required fields.
        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        assert_eq!(doc["dataLicense"], "CC0-1.0");
        assert_eq!(doc["SPDXID"], "SPDXRef-DOCUMENT");
        assert!(doc["documentNamespace"].as_str().unwrap().starts_with("https://spdx.org/"));

        // Validate packages.
        let packages = doc["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0]["name"], "express");
        assert_eq!(packages[0]["versionInfo"], "4.18.2");
        assert_eq!(packages[0]["licenseConcluded"], "MIT");

        // Validate checksums.
        let checksums = packages[0]["checksums"].as_array().unwrap();
        assert!(!checksums.is_empty());
        assert_eq!(checksums[0]["algorithm"], "SHA256");

        // Validate relationships.
        let relationships = doc["relationships"].as_array().unwrap();
        assert_eq!(relationships.len(), 2);
        assert_eq!(relationships[0]["relationshipType"], "DESCRIBES");

        // Validate creation info.
        assert!(doc["creationInfo"]["created"].as_str().is_some());
    }

    #[test]
    fn cyclonedx_export_structure() {
        let mut exporter = AuditExporter::new(ExportFormat::CycloneDx);
        exporter.record(make_install_record("express", "4.18.2"));
        exporter.record(make_install_record("lodash", "4.17.21"));

        let output = exporter.export();
        let doc: serde_json::Value = serde_json::from_str(&output).unwrap();

        // Validate CycloneDX 1.5 required fields.
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.5");
        assert!(doc["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"));
        assert_eq!(doc["version"], 1);

        // Validate metadata.
        assert!(doc["metadata"]["timestamp"].as_str().is_some());
        let tools = doc["metadata"]["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        assert_eq!(tools[0]["name"], "rusk-enterprise");

        // Validate components.
        let components = doc["components"].as_array().unwrap();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0]["name"], "express");
        assert_eq!(components[0]["version"], "4.18.2");
        assert_eq!(components[0]["type"], "library");

        // Validate hashes.
        let hashes = components[0]["hashes"].as_array().unwrap();
        assert!(!hashes.is_empty());
        assert_eq!(hashes[0]["alg"], "SHA-256");

        // Validate licenses.
        let licenses = components[0]["licenses"].as_array().unwrap();
        assert!(!licenses.is_empty());
        assert_eq!(licenses[0]["license"]["id"], "MIT");

        // Validate purl.
        assert_eq!(components[0]["purl"], "pkg:npm/express@4.18.2");
    }

    #[test]
    fn empty_export_produces_valid_output() {
        // SPDX with no records should still be valid JSON.
        let exporter = AuditExporter::new(ExportFormat::Spdx);
        let output = exporter.export();
        let doc: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        assert_eq!(doc["packages"].as_array().unwrap().len(), 0);

        // CycloneDX with no records.
        let exporter = AuditExporter::new(ExportFormat::CycloneDx);
        let output = exporter.export();
        let doc: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["components"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn records_without_package_excluded_from_sbom() {
        let mut exporter = AuditExporter::new(ExportFormat::Spdx);

        // Record with no package should not appear in packages array.
        exporter.record(AuditRecord {
            id: "rec-policy".to_string(),
            timestamp: Utc::now(),
            event_type: AuditEventType::PolicyEval,
            package: None,
            version: None,
            decision: "passed".to_string(),
            details: serde_json::json!({}),
        });

        exporter.record(make_install_record("express", "4.18.2"));

        let output = exporter.export();
        let doc: serde_json::Value = serde_json::from_str(&output).unwrap();
        let packages = doc["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 1); // Only the record with a package
    }

    #[test]
    fn uuid_v4_from_timestamp_is_valid_format() {
        let uuid = uuid_v4_from_timestamp();
        // Should have 5 groups separated by hyphens.
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5);
        // Third group should start with '4' (version 4).
        assert!(parts[2].starts_with('4'));
    }
}
