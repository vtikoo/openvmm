// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Simple SPDM Certificate Chain parsing for TDISP attestation.
//! This module provides basic parsing for SPDM GET_CERTIFICATE response messages.

use asn1::{Implicit, OwnedBitString};
use der::Decode;
use der::oid::ObjectIdentifier;
use openssl::x509::{X509, X509VerifyResult};
use std::mem::size_of;
use thiserror::Error;
use x509_cert::Certificate;
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// SPDM GET_CERTIFICATE response code
pub const SPDM_GET_CERTIFICATE_RESPONSE_CODE: u8 = 0x02;

/// Maximum number of certificate slots (0-7 inclusive)
pub const MAX_CERTIFICATE_SLOTS: u8 = 8;

/// SHA-384 hash length in bytes
pub const SHA384_HASH_LEN: usize = 48;

/// Errors that can occur when processing SPDM certificates
#[derive(Debug, Error)]
pub enum SpdmCertificateError {
    /// Buffer is too short for the expected data
    #[error("Buffer too short: expected at least {expected} bytes, got {actual} bytes")]
    BufferTooShort {
        /// Expected buffer size
        expected: usize,
        /// Actual buffer size
        actual: usize
    },
    /// Invalid SPDM response code received
    #[error("Invalid SPDM response code: expected 0x02, got 0x{actual:02x}")]
    InvalidResponseCode {
        /// Actual response code received
        actual: u8
    },
    /// Invalid certificate slot ID
    #[error("Invalid slot ID: {slot_id} (must be 0-7)")]
    InvalidSlotId {
        /// The invalid slot ID value
        slot_id: u8
    },
    /// Certificate chain length in header doesn't match actual data
    #[error(
        "Certificate chain length mismatch: header says {header_length}, but only {actual_length} bytes available"
    )]
    CertChainLengthMismatch {
        /// Length specified in header
        header_length: u16,
        /// Actual data length available
        actual_length: usize,
    },
    /// Zerocopy deserialization failed
    #[error("Zerocopy deserialization error: {0}")]
    ZerocopyError(String),
    /// Certificate chain header is too short
    #[error(
        "Certificate chain too short: expected at least {expected} bytes for header, got {actual} bytes"
    )]
    CertChainHeaderTooShort {
        /// Expected header size
        expected: usize,
        /// Actual header size
        actual: usize
    },
    /// Certificate chain validation failed
    #[error("Certificate chain validation error: {0}")]
    CertificateChainValidation(#[from] CertificateChainValidationError),
    /// DER to X509 conversion failed
    #[error("Failed to convert DER bytes to X509 certificate: {0}")]
    DerToX509Conversion(#[source] openssl::error::ErrorStack),
}

/// Errors that can occur during certificate chain validation
#[derive(Debug, Error)]
pub enum CertificateChainValidationError {
    /// Certificate chain contains no certificates
    #[error("certificate chain is empty")]
    CertChainIsEmpty,
    /// Failed to extract public key from certificate
    #[error("failed to get public key from the certificate")]
    GetPublicKeyFromCertificate(#[source] openssl::error::ErrorStack),
    /// Failed to verify child certificate signature
    #[error("failed to verify the child certificate signature with parent public key")]
    VerifyChildSignatureWithParentPublicKey(#[source] openssl::error::ErrorStack),
    /// Certificate signature verification failed
    #[error("certificate chain signature mismatch")]
    CertChainSignatureMismatch,
    /// Certificate subject/issuer chain is broken
    #[error("certificate chain subject/issuer mismatch")]
    CertChainSubjectIssuerMismatch,
}

/// SPDM GET_CERTIFICATE response message header (Table 32)
#[derive(Debug, KnownLayout, FromBytes, Immutable)]
#[repr(C)]
struct SpdmGetCertificateResponseSerialized {
    /// SPDM version
    pub spdm_version: u8,
    /// Request/Response code (should be 0x02 for CERTIFICATE)
    pub request_response_code: u8,
    /// Param1: Bits [3:0] = SlotID, Bits [7:4] = Reserved
    pub param1: u8,
    /// Param2: Reserved
    pub param2: u8,
    /// Number of bytes of this portion of certificate chain
    pub portion_length: u16,
    /// Number of bytes remaining after this response
    pub remainder_length: u16,
    // Variable-length certificate chain data follows
}

static_assertions::const_assert_eq!(size_of::<SpdmGetCertificateResponseSerialized>(), 8);

/// Certificate chain format header (Table 28)
#[derive(Debug, KnownLayout, FromBytes, Immutable)]
#[repr(C)]
struct CertificateChainHeaderSerialized {
    /// Total length of the certificate chain in bytes (little endian)
    pub length: u16,
    /// Reserved field
    pub reserved: u16,
    // Note: RootHash and Certificates fields follow this header
    // RootHash: H bytes (where H is hash algorithm output size)
    // Certificates: (Length - (4 + H)) bytes
}

static_assertions::const_assert_eq!(size_of::<CertificateChainHeaderSerialized>(), 4);

/// Parsed certificate chain data
#[derive(Debug, Clone)]
pub struct CertificateChain {
    /// Total length of the certificate chain
    pub length: u16,
    /// Digest of the Root Certificate
    pub root_hash: Vec<u8>,
    /// Complete certificate chain (ASN.1 DER-encoded X.509 v3 certificates)
    pub certificates: Vec<u8>,
}

impl CertificateChain {
    /// Parse individual X.509 certificates from the certificate chain data
    ///
    /// The certificate chain is a concatenation of DER-encoded X.509 certificates.
    /// OpenSSL can parse each certificate and tell us where it ends, so we don't
    /// need to manually parse ASN.1 DER structures.
    pub fn parse_x509_certificates(&self) -> Result<Vec<X509>, SpdmCertificateError> {
        let mut certificates = Vec::new();
        let mut remaining = &self.certificates[..];
        let mut cert_index = 0;

        while !remaining.is_empty() {
            // Check if this looks like a DER certificate (should start with 0x30)
            if remaining[0] != 0x30 {
                tracing::warn!(
                    "Certificate #{} doesn't start with DER SEQUENCE tag (0x30), got 0x{:02x}",
                    cert_index,
                    remaining[0]
                );
                if certificates.is_empty() {
                    return Err(SpdmCertificateError::DerToX509Conversion(
                        openssl::error::ErrorStack::get(),
                    ));
                }
                break;
            }

            // Try to parse an X.509 certificate from the remaining data
            match X509::from_der(remaining) {
                Ok(cert) => {
                    let subject = cert
                        .subject_name()
                        .entries()
                        .filter_map(|e| e.data().as_utf8().ok())
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");

                    // Calculate how many bytes were consumed
                    let cert_der = cert
                        .to_der()
                        .map_err(SpdmCertificateError::DerToX509Conversion)?;
                    let consumed = cert_der.len();
                    if consumed > remaining.len() {
                        tracing::error!(
                            "Certificate #{} claims to consume {} bytes but only {} available",
                            cert_index,
                            consumed,
                            remaining.len()
                        );
                        break;
                    }

                    certificates.push(cert);
                    remaining = &remaining[consumed..];
                    cert_index += 1;
                }
                Err(ssl_err) => {
                    tracing::error!("Failed to parse certificate #{}: {:?}", cert_index, ssl_err);

                    // If we can't parse a certificate and we have certificates already,
                    // we're done. If we have no certificates yet, this is an error.
                    if certificates.is_empty() {
                        let preview_len = std::cmp::min(16, remaining.len());
                        tracing::error!(
                            "No valid certificates found. First {} bytes: {:02x?}",
                            preview_len,
                            &remaining[..preview_len]
                        );
                        return Err(SpdmCertificateError::DerToX509Conversion(ssl_err));
                    }
                    tracing::warn!(
                        "Stopping certificate parsing after {} valid certificates due to parse error",
                        certificates.len()
                    );
                    break;
                }
            }
        }
        tracing::debug!(
            "Parsed {} X.509 certificates from certificate chain",
            certificates.len()
        );
        Ok(certificates)
    }

    /// Validate the certificate chain using OpenSSL
    /// Returns the root certificate if validation succeeds
    pub fn validate_certificate_chain(&self) -> Result<X509, SpdmCertificateError> {
        tracing::debug!(
            "Starting certificate chain validation with {} bytes of certificate data",
            self.certificates.len()
        );

        // First check if we have any certificate data
        if self.certificates.is_empty() {
            return Err(SpdmCertificateError::CertificateChainValidation(
                CertificateChainValidationError::CertChainIsEmpty,
            ));
        }

        // Try to parse X.509 certificates
        let x509_certs = match self.parse_x509_certificates() {
            Ok(certs) => {
                certs
            }
            Err(e) => {
                tracing::error!("Failed to parse X.509 certificates: {:?}", e);
                return Err(e);
            }
        };

        if x509_certs.is_empty() {
            tracing::error!("No valid X.509 certificates found in certificate data");
            return Err(SpdmCertificateError::CertificateChainValidation(
                CertificateChainValidationError::CertChainIsEmpty,
            ));
        }

        // Validate the certificate chain
        match validate_cert_chain(&x509_certs, &self.root_hash) {
            Ok(root_cert) => {
                let subject_entries: Vec<String> = root_cert
                    .subject_name()
                    .entries()
                    .filter_map(|e| e.data().as_utf8().ok())
                    .map(|s| s.to_string())
                    .collect();
                tracing::debug!(
                    "Certificate chain validation successful, root certificate subject: {:?}",
                    subject_entries
                );
                Ok(root_cert)
            }
            Err(e) => {
                tracing::error!("Certificate chain validation failed: {:?}", e);
                Err(SpdmCertificateError::CertificateChainValidation(e))
            }
        }
    }
}

/// Parsed SPDM GET_CERTIFICATE response
#[derive(Debug, Clone)]
pub struct SpdmGetCertificateResponse {
    /// SPDM protocol version
    pub spdm_version: u8,
    /// Request/response code
    pub request_response_code: u8,
    /// Certificate slot ID (0-7)
    pub slot_id: u8,
    /// Length of this portion of the certificate chain
    pub portion_length: u16,
    /// Length of remaining certificate chain data
    pub remainder_length: u16,
    /// The certificate chain data
    pub certificate_chain: CertificateChain,
}

/// Deserialize an SPDM GET_CERTIFICATE response from raw bytes.
pub fn deserialize_spdm_certificate_response(
    data: &[u8],
) -> Result<SpdmGetCertificateResponse, SpdmCertificateError> {
    // Check minimum size for header
    if data.len() < size_of::<SpdmGetCertificateResponseSerialized>() {
        return Err(SpdmCertificateError::BufferTooShort {
            expected: size_of::<SpdmGetCertificateResponseSerialized>(),
            actual: data.len(),
        });
    }

    // Deserialize the static part of the response.
    let response_header = SpdmGetCertificateResponseSerialized::read_from_prefix(data)
        .map_err(|e| SpdmCertificateError::ZerocopyError(format!("{:?}", e)))?;
    let variable_portion_offset = response_header.1;
    let header = response_header.0;

    // Validate response code
    if header.request_response_code != SPDM_GET_CERTIFICATE_RESPONSE_CODE {
        return Err(SpdmCertificateError::InvalidResponseCode {
            actual: header.request_response_code,
        });
    }

    // Extract slot ID and validate
    let slot_id = header.param1 & 0x0F;
    if slot_id >= MAX_CERTIFICATE_SLOTS {
        return Err(SpdmCertificateError::InvalidSlotId { slot_id });
    }

    // Validate that remainder_length is 0 (complete certificate chain)
    if header.remainder_length != 0 {
        return Err(SpdmCertificateError::BufferTooShort {
            expected: header.portion_length as usize + header.remainder_length as usize,
            actual: header.portion_length as usize,
        });
    }

    // Check if we have enough data for the certificate chain
    let chain_length = header.portion_length as usize;
    if variable_portion_offset.len() < chain_length {
        return Err(SpdmCertificateError::BufferTooShort {
            expected: chain_length,
            actual: variable_portion_offset.len(),
        });
    }

    // Extract complete certificate chain
    let certificate_chain_data = &variable_portion_offset[..chain_length];

    let certificate_chain = deserialize_certificate_chain(certificate_chain_data, SHA384_HASH_LEN)?;

    Ok(SpdmGetCertificateResponse {
        spdm_version: header.spdm_version,
        request_response_code: header.request_response_code,
        slot_id,
        portion_length: header.portion_length,
        remainder_length: header.remainder_length,
        certificate_chain,
    })
}

/// Deserialize a certificate chain from raw bytes.
pub fn deserialize_certificate_chain(
    data: &[u8],
    hash_size: usize,
) -> Result<CertificateChain, SpdmCertificateError> {
    // Check minimum size for certificate chain header
    if data.len() < size_of::<CertificateChainHeaderSerialized>() {
        return Err(SpdmCertificateError::CertChainHeaderTooShort {
            expected: size_of::<CertificateChainHeaderSerialized>(),
            actual: data.len(),
        });
    }

    // Deserialize the certificate chain header
    let cert_chain_header = CertificateChainHeaderSerialized::read_from_prefix(data)
        .map_err(|e| SpdmCertificateError::ZerocopyError(format!("{:?}", e)))?;
    let remaining_data = cert_chain_header.1;
    let header = cert_chain_header.0;

    // Validate total length
    let expected_total_length = header.length as usize;
    if data.len() != expected_total_length {
        return Err(SpdmCertificateError::CertChainLengthMismatch {
            header_length: header.length,
            actual_length: data.len(),
        });
    }

    // Calculate expected remaining data length
    let expected_remaining_length =
        expected_total_length - size_of::<CertificateChainHeaderSerialized>();
    if remaining_data.len() != expected_remaining_length {
        return Err(SpdmCertificateError::CertChainLengthMismatch {
            header_length: expected_remaining_length as u16,
            actual_length: remaining_data.len(),
        });
    }

    // Check if we have enough data for root hash
    if remaining_data.len() < hash_size {
        return Err(SpdmCertificateError::BufferTooShort {
            expected: hash_size,
            actual: remaining_data.len(),
        });
    }

    // Extract root hash
    let root_hash = remaining_data[..hash_size].to_vec();

    // Extract certificates (everything after the root hash)
    let certificates = remaining_data[hash_size..].to_vec();

    Ok(CertificateChain {
        length: header.length,
        root_hash,
        certificates,
    })
}

/// Helper function for X.509 certificate chain validation using OpenSSL.
/// Adapted from key_release.rs validate_cert_chain function.
/// Also validates that the provided root hash (SHA-384) matches the actual root certificate.
pub fn validate_cert_chain(
    cert_chain: &[X509],
    expected_root_hash: &[u8],
) -> Result<X509, CertificateChainValidationError> {
    // Mandate SHA-384 hash size
    if expected_root_hash.len() != SHA384_HASH_LEN {
        return Err(CertificateChainValidationError::CertChainSignatureMismatch); // Reuse existing error for hash validation
    }
    if cert_chain.is_empty() {
        return Err(CertificateChainValidationError::CertChainIsEmpty);
    }

    tracing::debug!(
        "Validating certificate chain with {} certificates",
        cert_chain.len()
    );

    // Determine chain order by checking if first certificate is self-signed (root)
    let is_root_first = if !cert_chain.is_empty() {
        let first_cert = &cert_chain[0];
        // Compare the DER-encoded subject and issuer names
        let subject_der = first_cert.subject_name().to_der().unwrap_or_default();
        let issuer_der = first_cert.issuer_name().to_der().unwrap_or_default();
        subject_der == issuer_der
    } else {
        false
    };


    // Validate the certificate chain based on its order
    // Only validate the subject-issuer pair and signature (without validity)
    // assuming there is no trusted time source
    for i in 0..cert_chain.len() {
        if i < cert_chain.len() - 1 {
            let (child, parent, child_idx, parent_idx) = if is_root_first {
                // Chain goes: root (0) -> intermediate(s) -> leaf (last)
                // So parent is at i, child is at i+1
                (&cert_chain[i + 1], &cert_chain[i], i + 1, i)
            } else {
                // Chain goes: leaf (0) -> intermediate(s) -> root (last)
                // So child is at i, parent is at i+1
                (&cert_chain[i], &cert_chain[i + 1], i, i + 1)
            };

            tracing::debug!(
                "Validating certificate {} (child) against certificate {} (parent)",
                child_idx,
                parent_idx
            );

            // Get parent public key
            let public_key = parent
                .public_key()
                .map_err(CertificateChainValidationError::GetPublicKeyFromCertificate)?;

            // Perform signature verification
            let verified = child.verify(&public_key).map_err(
                CertificateChainValidationError::VerifyChildSignatureWithParentPublicKey,
            )?;

            if !verified {
                tracing::error!(
                    "Signature verification failed for certificate {} with parent {}",
                    child_idx,
                    parent_idx
                );
                return Err(CertificateChainValidationError::CertChainSignatureMismatch);
            }

            // Check subject/issuer relationship
            let issued = parent.issued(child);

            if issued != X509VerifyResult::OK {
                tracing::error!(
                    "Subject/issuer verification failed for certificate {} with parent {}: {:?}",
                    child_idx,
                    parent_idx,
                    issued
                );
                return Err(CertificateChainValidationError::CertChainSubjectIssuerMismatch);
            }

            tracing::debug!(
                "Validated certificate {} against parent {}",
                child_idx,
                parent_idx
            );
        }
    }

    // Return the root certificate (depends on chain order)
    let root_cert = if is_root_first {
        // Root is first in chain
        cert_chain[0].clone()
    } else {
        // Root is last in chain
        cert_chain[cert_chain.len() - 1].clone()
    };

    // Validate that the expected root hash matches the actual root certificate
    let root_cert_der = root_cert
        .to_der()
        .map_err(|_| CertificateChainValidationError::CertChainSignatureMismatch)?;

    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha384())
        .map_err(|_| CertificateChainValidationError::CertChainSignatureMismatch)?;
    hasher
        .update(&root_cert_der)
        .map_err(|_| CertificateChainValidationError::CertChainSignatureMismatch)?;
    let computed_hash = hasher
        .finish()
        .map_err(|_| CertificateChainValidationError::CertChainSignatureMismatch)?;

    if expected_root_hash != computed_hash.as_ref() {
        tracing::error!("Root hash mismatch");
        return Err(CertificateChainValidationError::CertChainSignatureMismatch);
    }

    tracing::info!("Certificate chain validation completed successfully");
    Ok(root_cert)
}

#[derive(Debug, asn1::Asn1Read, asn1::Asn1Write)]
struct FwidRef<'a> {
    hash_alg: asn1::ObjectIdentifier,
    digest: &'a [u8],
}

/// FWID structure representing a firmware identifier per DICE specification
/// FWID ::== SEQUENCE {
///     hashAlg OBJECT IDENTIFIER,
///     digest OCTET STRING
/// }
#[derive(Debug, Clone)]
pub struct Fwid {
    /// Hash algorithm used for the digest
    pub hash_alg: String,
    /// The digest value
    pub digest: Vec<u8>,
}

/// DICE TCBInfo structure representing parsed ASN.1 data
/// Production structure with all 11 fields per TCG DICE Layered Attestation
#[derive(Debug, Clone)]
pub struct DiceTcbInfo {
    /// The entity that created the measurement (e.g., vendor name)
    pub vendor: Option<String>,
    /// The product name associated with the measurement
    pub model: Option<String>,
    /// The revision string associated with the Target Environment
    pub version: Option<String>,
    /// The security version number associated with the Target Environment
    pub svn: Option<u64>,
    /// The DICE layer associated with this measurement
    pub layer: Option<u64>,
    /// Value that distinguishes different instances of the same type
    pub index: Option<u64>,
    /// List of FWID values (firmware identifiers) per DICE specification
    pub fwids: Vec<Fwid>,
    /// Optional flags
    pub flags: Option<OwnedBitString>,
    /// Vendor supplied values for device specific state
    pub vendor_info: Option<Vec<u8>>,
    /// Machine readable description of the measurement
    pub measurement_type: Option<Vec<u8>>,
    /// List of named digests (integrity registers)
    pub integrity_registers: Vec<IntegrityRegister>,
}

/// Integrity Register from DICE TCBInfo specification
#[derive(Debug, Clone)]
pub struct IntegrityRegister {
    /// Textual name of the register
    pub register_name: Option<String>,
    /// Numeric identifier of the register
    pub register_num: Option<u64>,
    /// List of digest values for this register (following FWID structure)
    pub register_digests: Vec<Fwid>,
}

/// Extract DICE TCBInfo from X.509 certificate extension
/// OID: 2.23.133.5.4.1 (tcg-dice-TcbInfo)
pub fn extract_dice_tcb_info(cert: &X509) -> Result<Option<DiceTcbInfo>, anyhow::Error> {
    // DICE TCBInfo OID: 2.23.133.5.4.1
    // tcg(2.23.133) + platformClass(5) + dice(4) + tcbinfo(1)
    const DICE_TCBINFO_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.5.4.1");

    // Get the certificate as DER bytes for extension parsing
    let cert_der = cert.to_der()?;

    // Look for the DICE TCBInfo extension in the certificate extensions
    if let Some(tcb_info_der) = find_dice_extension(&cert_der, &DICE_TCBINFO_OID)? {
        let tcb_info = parse_dice_tcb_info_asn1(&tcb_info_der)?;
        return Ok(Some(tcb_info));
    }

    tracing::debug!("No DICE TCBInfo extension found in certificate");
    Ok(None)
}

/// ASN.1 structures for DICE TCBInfo parsing
/// Based on TCG DICE Layered Attestation Architecture specification
#[derive(Debug, Clone)]
pub struct DiceTcbInfoAsn1 {
    /// Vendor name
    pub vendor: Option<String>,
    /// Model identifier
    pub model: Option<String>,
    /// Version string
    pub version: Option<String>,
    /// Security version number
    pub svn: Option<u64>,
    /// TCB layer number
    pub layer: Option<u64>,
    /// Index within the layer
    pub index: Option<u64>,
    /// Firmware identifiers (digests)
    pub fwids: Vec<Fwid>,
    /// Optional flags bitstring
    pub flags: Option<OwnedBitString>,
    /// Vendor-specific information
    pub vendor_info: Option<Vec<u8>>,
    /// Measurement type identifier
    pub measurement_type: Option<Vec<u8>>,
    /// Integrity register values
    pub integrity_registers: Vec<IntegrityRegisterAsn1>,
}

/// ASN.1 structure for Integrity Register
#[derive(Debug, Clone)]
pub struct IntegrityRegisterAsn1 {
    /// Name of the register
    pub register_name: Option<String>,
    /// Register number
    pub register_num: Option<u64>,
    /// Digests contained in the register
    pub register_digests: Vec<Fwid>,
}

/// Parse DICE TCBInfo from ASN.1 DER encoded data
/// Production implementation with full ASN.1 parsing exactly like aivaee.rs
pub fn parse_dice_tcb_info_asn1(data: &[u8]) -> Result<DiceTcbInfo, anyhow::Error> {
    tracing::debug!("Parsing DICE TCBInfo ASN.1 data: {} bytes", data.len());

    // Use exact same approach as aivaee.rs
    let result: Result<DiceTcbInfo, asn1::ParseError> = asn1::parse(data, |d| {
        return d.read_element::<asn1::Sequence<'_>>()?.parse(|d| {
            // Parse fields using UTF8String per DICE Attestation Architecture v1.2
            let vendor = d.read_element::<Option<Implicit<asn1::Utf8String<'_>, 0>>>()?;
            let model = d.read_element::<Option<Implicit<asn1::Utf8String<'_>, 1>>>()?;
            let version = d.read_element::<Option<Implicit<asn1::Utf8String<'_>, 2>>>()?;
            let svn = d.read_element::<Option<Implicit<i64, 3>>>()?;
            let layer = d.read_element::<Option<Implicit<i64, 4>>>()?;
            let index = d.read_element::<Option<Implicit<i64, 5>>>()?;

            let fwids = d.read_element::<Option<Implicit<asn1::SequenceOf<'_, FwidRef<'_>>, 6>>>()?;

            let flags = d.read_element::<Option<Implicit<OwnedBitString, 7>>>()?;
            let vendor_info = d.read_element::<Option<Implicit<&[u8], 8>>>()?;
            let measurement_type = d.read_element::<Option<Implicit<&[u8], 9>>>()?;

            // Parse integrityRegisters field (new in DICE Attestation Architecture v1.2)
            let integrity_registers: Option<Vec<IntegrityRegisterAsn1>> =
                d.read_element::<Option<Implicit<asn1::SequenceOf<'_, asn1::Sequence<'_>>, 10>>>()?
                    .map(|seq_list| {
                        seq_list.into_inner()
                            .into_iter()
                            .filter_map(|seq| {
                                seq.parse(|d| -> Result<IntegrityRegisterAsn1, asn1::ParseError> {
                                    let register_name = d.read_element::<Option<Implicit<asn1::IA5String<'_>, 0>>>()?;
                                    let register_num = d.read_element::<Option<Implicit<i64, 1>>>()?;
                                    let register_digests = d.read_element::<Option<Implicit<asn1::SequenceOf<'_, FwidRef<'_>>, 2>>>()?;

                                    Ok(IntegrityRegisterAsn1 {
                                        register_name: register_name.map(|n| n.as_inner().as_str().to_string()),
                                        register_num: register_num.map(|n| n.into_inner() as u64),
                                        register_digests: register_digests
                                            .map(|fwids| {
                                                fwids.into_inner()
                                                    .into_iter()
                                                    .map(|f| Fwid {
                                                        hash_alg: f.hash_alg.to_string(),
                                                        digest: f.digest.to_vec(),
                                                    })
                                                    .collect()
                                            })
                                            .unwrap_or_else(Vec::new),
                                    })
                                }).ok()
                            })
                            .collect()
                    });

            return Ok(DiceTcbInfo {
                vendor: vendor.map(|v| v.as_inner().as_str().to_string()),
                model: model.map(|m| m.as_inner().as_str().to_string()),
                version: version.map(|v| v.as_inner().as_str().to_string()),
                svn: svn.map(|s| s.into_inner() as u64),
                layer: layer.map(|l| l.into_inner() as u64),
                index: index.map(|i| i.into_inner() as u64),
                fwids: fwids.map(|f| {
                    f.into_inner()
                        .into_iter()
                        .map(|f| Fwid {
                            hash_alg: f.hash_alg.to_string(),
                            digest: f.digest.to_vec(),
                        })
                        .collect()
                }).unwrap_or_else(Vec::new),
                flags: flags.map(|f| f.into_inner()),
                vendor_info: vendor_info.map(|v| v.as_inner().to_vec()),
                measurement_type: measurement_type.map(|t| t.as_inner().to_vec()),
                integrity_registers: integrity_registers.unwrap_or_else(Vec::new).into_iter().map(|reg| IntegrityRegister {
                    register_name: reg.register_name,
                    register_num: reg.register_num,
                    register_digests: reg.register_digests,
                }).collect(),
            });
        });
    });

    match result {
        Ok(tcb_info) => {
            Ok(tcb_info)
        }
        Err(e) => {
            tracing::error!("Failed to parse DICE TCBInfo with asn1 crate: {}", e);
            Err(anyhow::anyhow!("DICE TCBInfo parse error: {}", e))
        }
    }
}

/// Format DiceTcbInfo for validation and logging
pub fn format_dice_tcb_info(tcb_info: &DiceTcbInfo) -> String {
    let mut parts = Vec::new();

    if let Some(ref vendor) = tcb_info.vendor {
        parts.push(format!("vendor={}", vendor));
    }
    if let Some(ref model) = tcb_info.model {
        parts.push(format!("model={}", model));
    }
    if let Some(ref version) = tcb_info.version {
        parts.push(format!("version={}", version));
    }
    if let Some(svn) = tcb_info.svn {
        parts.push(format!("svn={}", svn));
    }
    if let Some(layer) = tcb_info.layer {
        parts.push(format!("layer={}", layer));
    }
    if let Some(index) = tcb_info.index {
        parts.push(format!("index={}", index));
    }

    if !tcb_info.fwids.is_empty() {
        let fwid_count = tcb_info.fwids.len();
        parts.push(format!("fwids_count={}", fwid_count));
    }

    if !tcb_info.integrity_registers.is_empty() {
        let ir_count = tcb_info.integrity_registers.len();
        parts.push(format!("integrity_registers_count={}", ir_count));
    }

    format!("DICE_TCBInfo[{}]", parts.join(", "))
}

/// Find DICE TCBInfo extension in X.509 certificate using OpenSSL
/// This approach is simpler and more reliable than manual ASN.1 parsing
fn find_dice_extension(
    cert_der: &[u8],
    _dice_oid: &ObjectIdentifier,
) -> Result<Option<Vec<u8>>, anyhow::Error> {
    // Parse certificate using x509-cert crate (same as demo-attest-report working implementation)
    let cert = Certificate::from_der(cert_der)?;

    // Get the OID string for lookup
    let dice_oid_str = "2.23.133.5.4.1";

    // Look through extensions for the DICE TCBInfo OID
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions {
            let oid_str = ext.extn_id.to_string();
            if oid_str == dice_oid_str {
                // Get the extension data as raw OCTET STRING bytes
                let ext_data = ext.extn_value.as_bytes();
                return Ok(Some(ext_data.to_vec()));
            }
        }
    }

    tracing::debug!("No DICE TCBInfo extension found");
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real certificate data from ASP response (starts at byte 52 after header+hash)
    const MOCK_TSM_GET_CERT_RSP: &[u8] = &[
        0x11, 0x08, 0x00, 0x00, 0x6c, 0xf4, 0xd3, 0x06, 0xf1, 0x4f, 0x7e, 0xa5, 0xe0, 0x73, 0x10,
        0xed, 0x88, 0xdb, 0xb7, 0x9c, 0xab, 0x9c, 0xe4, 0x2d, 0x7f, 0x4a, 0x4a, 0x19, 0x36, 0xcd,
        0x18, 0x41, 0x97, 0x08, 0xb7, 0x03, 0x96, 0xfd, 0x69, 0xab, 0x41, 0x16, 0xd6, 0x96, 0xdb,
        0xa7, 0xd8, 0x4c, 0xfa, 0x7b, 0xa0, 0x32, 0x30, 0x82, 0x05, 0x34, 0x30, 0x82, 0x04, 0xba,
        0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0x80, 0x9c, 0xd2, 0xcc, 0x51, 0xeb, 0x8b,
        0x97, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x4b,
        0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x40, 0x67, 0x4a, 0x7a, 0x53,
        0x7a, 0x46, 0x48, 0x72, 0x69, 0x35, 0x66, 0x47, 0x37, 0x76, 0x30, 0x6e, 0x6e, 0x6c, 0x73,
        0x2f, 0x76, 0x6a, 0x76, 0x57, 0x70, 0x4e, 0x61, 0x48, 0x5a, 0x52, 0x6d, 0x35, 0x65, 0x6c,
        0x63, 0x50, 0x56, 0x65, 0x76, 0x7a, 0x35, 0x41, 0x51, 0x46, 0x36, 0x31, 0x2b, 0x78, 0x47,
        0x4d, 0x79, 0x34, 0x75, 0x42, 0x42, 0x47, 0x54, 0x72, 0x4c, 0x71, 0x65, 0x32, 0x2b, 0x58,
        0x30, 0x20, 0x17, 0x0d, 0x31, 0x38, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35,
        0x39, 0x35, 0x39, 0x5a, 0x30, 0x4b, 0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x40, 0x67, 0x4a, 0x7a, 0x53, 0x7a, 0x46, 0x48, 0x72, 0x69, 0x35, 0x66, 0x47, 0x37,
        0x76, 0x30, 0x6e, 0x6e, 0x6c, 0x73, 0x2f, 0x76, 0x6a, 0x76, 0x57, 0x70, 0x4e, 0x61, 0x48,
        0x5a, 0x52, 0x6d, 0x35, 0x65, 0x6c, 0x63, 0x50, 0x56, 0x65, 0x76, 0x7a, 0x35, 0x41, 0x51,
        0x46, 0x36, 0x31, 0x2b, 0x78, 0x47, 0x4d, 0x79, 0x34, 0x75, 0x42, 0x42, 0x47, 0x54, 0x72,
        0x4c, 0x71, 0x65, 0x32, 0x2b, 0x58, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
        0x51, 0x56, 0x71, 0x7a, 0xee, 0xde, 0x62, 0xed, 0x48, 0x79, 0xa5, 0x6a, 0xbf, 0xa1, 0x04,
        0xd2, 0xab, 0x76, 0x8b, 0x72, 0xf2, 0x24, 0x7f, 0x95, 0x30, 0x1f, 0x8f, 0x4f, 0x32, 0xce,
        0xd2, 0xb6, 0xcc, 0x1b, 0x71, 0x19, 0x10, 0x99, 0x5e, 0xdf, 0xde, 0xf6, 0x9a, 0xe9, 0xf8,
        0xbc, 0x75, 0x4a, 0x54, 0x2a, 0x4f, 0x8a, 0x70, 0x1b, 0xae, 0xd6, 0x6f, 0xd6, 0xc6, 0xfc,
        0x05, 0xd5, 0x12, 0x04, 0x16, 0xb4, 0xe1, 0x16, 0x44, 0xcd, 0xfd, 0xd0, 0x12, 0x88, 0xa9,
        0x6c, 0xb5, 0x8a, 0x66, 0x1a, 0xbb, 0xf1, 0x74, 0xb2, 0x29, 0x67, 0x13, 0x17, 0xf0, 0xcb,
        0xe2, 0x54, 0xf1, 0xb8, 0xec, 0x30, 0xa3, 0x82, 0x03, 0x66, 0x30, 0x82, 0x03, 0x62, 0x30,
        0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xf4, 0x7b, 0x2b, 0x78, 0x48,
        0x38, 0x3d, 0xe9, 0x7b, 0x91, 0xe6, 0x0c, 0x21, 0x64, 0xf6, 0xed, 0x51, 0x53, 0xd0, 0x94,
        0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xf4, 0x7b,
        0x2b, 0x78, 0x48, 0x38, 0x3d, 0xe9, 0x7b, 0x91, 0xe6, 0x0c, 0x21, 0x64, 0xf6, 0xed, 0x51,
        0x53, 0xd0, 0x94, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
        0x03, 0x02, 0x02, 0x04, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
        0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x62, 0x06, 0x06, 0x67, 0x81,
        0x05, 0x05, 0x04, 0x01, 0x04, 0x58, 0x30, 0x56, 0x82, 0x10, 0x33, 0x2e, 0x33, 0x2e, 0x35,
        0x2e, 0x30, 0x2d, 0x35, 0x30, 0x37, 0x30, 0x31, 0x30, 0x30, 0x31, 0x83, 0x01, 0x00, 0xa6,
        0x3f, 0x30, 0x3d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04,
        0x30, 0x99, 0x1b, 0x10, 0x46, 0x1b, 0x45, 0x82, 0x61, 0xa7, 0x95, 0x86, 0x24, 0xd5, 0xf9,
        0x80, 0x0c, 0x2e, 0xda, 0xad, 0x4e, 0x3c, 0xb8, 0x98, 0xba, 0xa1, 0x2d, 0x38, 0xaf, 0xe2,
        0x2b, 0x26, 0x5c, 0x9e, 0xd7, 0xcf, 0x1f, 0x32, 0x7d, 0x71, 0xa7, 0xf6, 0x60, 0x42, 0xc2,
        0xf3, 0x84, 0x65, 0x12, 0x30, 0x1e, 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x04, 0x04,
        0x14, 0x30, 0x12, 0x04, 0x10, 0x10, 0x69, 0x6d, 0x83, 0x3d, 0x77, 0xd5, 0xcf, 0x5c, 0xa8,
        0x9e, 0x11, 0xde, 0x0c, 0x7a, 0xc6, 0x30, 0x82, 0x02, 0x76, 0x06, 0x0a, 0x2b, 0x06, 0x01,
        0x04, 0x01, 0x82, 0x37, 0x66, 0x03, 0x01, 0x04, 0x82, 0x02, 0x66, 0x30, 0x82, 0x02, 0x62,
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x6d, 0xd9, 0x96, 0xde, 0xa2, 0xff,
        0x82, 0x98, 0xb8, 0x40, 0x22, 0x12, 0x87, 0x58, 0x57, 0x8a, 0x37, 0x90, 0x81, 0x18, 0xfa,
        0xb3, 0x00, 0xae, 0x70, 0x7d, 0xda, 0x1e, 0x82, 0x0e, 0x53, 0xd5, 0x39, 0x6b, 0x8f, 0x05,
        0x77, 0x88, 0x69, 0x65, 0xd7, 0x95, 0x63, 0x2e, 0x12, 0xbb, 0x6a, 0xa6, 0x99, 0x3b, 0x8a,
        0x46, 0x32, 0x23, 0xef, 0x52, 0x1b, 0x4d, 0xe0, 0xf2, 0x63, 0x84, 0x9f, 0x42, 0x6a, 0x98,
        0x67, 0x58, 0xf7, 0xee, 0x3d, 0x2b, 0x10, 0xde, 0x0f, 0x42, 0xac, 0x21, 0x55, 0x94, 0xae,
        0xa8, 0xcb, 0x46, 0x62, 0xaa, 0xe9, 0x60, 0x9b, 0xe7, 0xd6, 0x91, 0x20, 0xbc, 0xfa, 0x8f,
        0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x03, 0x02, 0x08, 0x04, 0x82,
        0x01, 0x50, 0x11, 0x10, 0x57, 0x40, 0x39, 0x5a, 0xbf, 0xfb, 0x55, 0xda, 0x31, 0xc6, 0xb9,
        0xb9, 0x8b, 0x37, 0x65, 0x7f, 0x5a, 0x63, 0x2c, 0xf1, 0xca, 0xa9, 0x2a, 0xf6, 0x98, 0x73,
        0xad, 0xcf, 0x84, 0xcd, 0x31, 0xd7, 0x37, 0x4c, 0x04, 0x3c, 0xeb, 0x04, 0x8b, 0xbf, 0xa1,
        0xc8, 0x54, 0xcc, 0x6e, 0x1b, 0x02, 0xe0, 0xf6, 0xdc, 0x49, 0x16, 0x4a, 0xae, 0x5f, 0xa1,
        0xc2, 0xed, 0x47, 0x4b, 0xcf, 0x3d, 0x69, 0x8f, 0xea, 0x97, 0x6c, 0x2f, 0x43, 0x75, 0x88,
        0x1e, 0x83, 0x88, 0xd7, 0x13, 0x7e, 0x74, 0x3f, 0xb6, 0x5f, 0x62, 0x1b, 0xf1, 0x62, 0xae,
        0x9a, 0x98, 0xc7, 0x27, 0x83, 0x7a, 0x64, 0xc8, 0x0f, 0xbc, 0xdf, 0xe4, 0x28, 0x42, 0xd2,
        0x9c, 0xff, 0x62, 0x6b, 0xfa, 0x23, 0xb3, 0x33, 0xe6, 0xae, 0xe2, 0x8f, 0x4f, 0x59, 0x6f,
        0xa9, 0xa7, 0x42, 0x55, 0xaf, 0x4a, 0xd5, 0x94, 0xe3, 0x5c, 0x32, 0xae, 0x94, 0xe2, 0x9f,
        0xca, 0xb5, 0xcc, 0x89, 0x46, 0x52, 0xbb, 0x9b, 0xfb, 0x31, 0x6f, 0xb3, 0x43, 0x24, 0xc9,
        0x56, 0x4c, 0x42, 0x48, 0xe7, 0x46, 0x37, 0x36, 0x86, 0x55, 0xb8, 0xf4, 0xd4, 0x50, 0x43,
        0x9d, 0x4a, 0x5d, 0x81, 0xe8, 0xe4, 0x44, 0x8f, 0x56, 0x8b, 0x29, 0x03, 0x2c, 0x76, 0x80,
        0x75, 0x22, 0x6b, 0xac, 0x6c, 0xaa, 0x96, 0xa5, 0xcf, 0x3f, 0x9a, 0x81, 0x5c, 0x82, 0x0d,
        0x85, 0x87, 0xb3, 0x3a, 0x60, 0x41, 0x19, 0x67, 0xbe, 0x43, 0x6c, 0x08, 0x0a, 0x68, 0xb0,
        0x90, 0xad, 0xf5, 0x28, 0xe5, 0x98, 0xa9, 0xc8, 0x04, 0x2a, 0x40, 0xf9, 0xee, 0xe9, 0xa7,
        0x5d, 0x27, 0x0b, 0x24, 0xe0, 0x58, 0xd8, 0x45, 0xec, 0xd0, 0x45, 0xe3, 0xb6, 0xcc, 0xfe,
        0x3c, 0xde, 0xbe, 0x46, 0x0d, 0xf6, 0xdc, 0x2c, 0x1b, 0xe6, 0xae, 0xe8, 0xb0, 0xbd, 0x05,
        0xbf, 0x1a, 0x84, 0x0e, 0x6f, 0x05, 0xa3, 0x38, 0x33, 0xdc, 0xf4, 0x2b, 0x49, 0xc7, 0x73,
        0xc3, 0x62, 0xfe, 0x43, 0x1c, 0xab, 0xad, 0x3a, 0x24, 0x5b, 0x9c, 0xa6, 0x39, 0xe3, 0x81,
        0x52, 0x8e, 0x1f, 0x05, 0x66, 0x1e, 0x6b, 0xfe, 0x5c, 0x0e, 0xb3, 0xae, 0x35, 0x6b, 0xc0,
        0xb4, 0xa0, 0x5e, 0x0f, 0xcc, 0x3a, 0xc8, 0x4d, 0x51, 0x64, 0x38, 0x3d, 0x45, 0xad, 0x8e,
        0xc8, 0xee, 0x07, 0xd1, 0x34, 0x6f, 0xd1, 0x00, 0x35, 0xec, 0x64, 0x03, 0x5c, 0x41, 0x54,
        0x0b, 0x4e, 0x76, 0x36, 0x4e, 0x59, 0x65, 0xc0, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x67, 0x00, 0x30, 0x64, 0x02, 0x30, 0x6e, 0x3a, 0xcb,
        0xef, 0xde, 0x68, 0xd3, 0x9f, 0x20, 0xe3, 0x0f, 0xab, 0xe3, 0x6f, 0xa6, 0xa0, 0xf1, 0x94,
        0xcd, 0x20, 0x07, 0xda, 0x9b, 0x43, 0x4d, 0x4a, 0x8d, 0x30, 0xae, 0xec, 0x8a, 0x2e, 0xca,
        0x31, 0x97, 0x42, 0xa9, 0xcc, 0x96, 0xa9, 0x65, 0x01, 0x46, 0xed, 0x6c, 0x53, 0xbd, 0xaf,
        0x02, 0x30, 0x0d, 0x4e, 0xd6, 0x1b, 0xb3, 0xe5, 0x3e, 0xcd, 0x8b, 0x25, 0x76, 0x2a, 0x61,
        0x41, 0x1b, 0x24, 0x33, 0x34, 0xc3, 0x65, 0xaf, 0x3a, 0xb7, 0xbe, 0xe6, 0x76, 0xb2, 0x2a,
        0xc8, 0x5b, 0xc8, 0xe9, 0x92, 0xd0, 0x82, 0xd9, 0x4b, 0x03, 0x6b, 0xc0, 0xe4, 0xc8, 0x6b,
        0xd7, 0x61, 0x75, 0x88, 0x46, 0x80, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x66,
        0x01, 0x32, 0x01, 0x81, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x30, 0x05,
        0xc6, 0xd8, 0x9f, 0x3e, 0xc9, 0x19, 0xa7, 0xad, 0x10, 0xc3, 0xe9, 0x7e, 0xce, 0x7f, 0x3c,
        0xc4, 0xfb, 0xef, 0x4d, 0x53, 0x50, 0x22, 0x6d, 0x73, 0xe8, 0xb2, 0x32, 0x6f, 0x33, 0xa3,
        0xa9, 0x3b, 0xc5, 0x11, 0xe0, 0xaf, 0x7b, 0x8a, 0x54, 0x8f, 0x13, 0xf9, 0xac, 0x4a, 0x02,
        0xaa, 0x29, 0x02, 0x31, 0x00, 0xf7, 0xf6, 0xfc, 0x77, 0xa7, 0x6a, 0xae, 0x12, 0xa4, 0x91,
        0x1a, 0x9a, 0x5b, 0xf9, 0x8f, 0x84, 0xe3, 0x37, 0xfb, 0xd1, 0xd5, 0xc0, 0xd3, 0xfd, 0x4e,
        0x82, 0xd9, 0x63, 0x47, 0x13, 0xe9, 0xc9, 0xf4, 0x20, 0x43, 0x97, 0x1f, 0x68, 0xea, 0x3b,
        0x67, 0xe3, 0xfd, 0x91, 0x30, 0xf2, 0x82, 0x5a, 0x30, 0x82, 0x02, 0xa1, 0x30, 0x82, 0x02,
        0x28, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x3a, 0x8b, 0x31, 0xc9, 0xeb, 0xb5, 0x83,
        0x56, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x4b,
        0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x40, 0x67, 0x4a, 0x7a, 0x53,
        0x7a, 0x46, 0x48, 0x72, 0x69, 0x35, 0x66, 0x47, 0x37, 0x76, 0x30, 0x6e, 0x6e, 0x6c, 0x73,
        0x2f, 0x76, 0x6a, 0x76, 0x57, 0x70, 0x4e, 0x61, 0x48, 0x5a, 0x52, 0x6d, 0x35, 0x65, 0x6c,
        0x63, 0x50, 0x56, 0x65, 0x76, 0x7a, 0x35, 0x41, 0x51, 0x46, 0x36, 0x31, 0x2b, 0x78, 0x47,
        0x4d, 0x79, 0x34, 0x75, 0x42, 0x42, 0x47, 0x54, 0x72, 0x4c, 0x71, 0x65, 0x32, 0x2b, 0x58,
        0x30, 0x20, 0x17, 0x0d, 0x31, 0x38, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35,
        0x39, 0x35, 0x39, 0x5a, 0x30, 0x4b, 0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x40, 0x4f, 0x6f, 0x73, 0x78, 0x79, 0x65, 0x75, 0x31, 0x67, 0x31, 0x61, 0x68, 0x6c,
        0x6b, 0x5a, 0x42, 0x58, 0x59, 0x62, 0x61, 0x53, 0x4e, 0x6a, 0x46, 0x5a, 0x48, 0x31, 0x58,
        0x4a, 0x6f, 0x46, 0x36, 0x53, 0x31, 0x51, 0x2b, 0x36, 0x69, 0x71, 0x75, 0x50, 0x71, 0x46,
        0x6a, 0x75, 0x2b, 0x41, 0x4a, 0x70, 0x75, 0x78, 0x2b, 0x56, 0x77, 0x79, 0x6d, 0x6c, 0x72,
        0x74, 0x34, 0x43, 0x54, 0x46, 0x75, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
        0xae, 0xd8, 0x49, 0xc4, 0xd5, 0x1b, 0x1c, 0xf5, 0x84, 0xc2, 0x56, 0xb4, 0xe8, 0xf5, 0xf3,
        0xcb, 0xdd, 0x9d, 0x37, 0xf0, 0x34, 0x60, 0x62, 0x3c, 0xa3, 0x44, 0xa7, 0x50, 0xae, 0xc0,
        0xdd, 0x06, 0x76, 0x37, 0x6b, 0x37, 0x18, 0x6e, 0x0a, 0x7e, 0xd4, 0x00, 0xb3, 0xe2, 0x0c,
        0x6d, 0x8b, 0x03, 0x45, 0xd3, 0xea, 0xab, 0x62, 0xd1, 0xb9, 0x58, 0xcb, 0x92, 0x87, 0xcd,
        0x82, 0x57, 0xa1, 0x3f, 0x1e, 0xfa, 0x7a, 0x67, 0xfc, 0x78, 0xa5, 0x7f, 0x5b, 0x93, 0x6d,
        0x84, 0x81, 0x85, 0xce, 0xdd, 0x43, 0xb9, 0x48, 0xc0, 0xbb, 0xec, 0xd6, 0x11, 0x8d, 0xcb,
        0x93, 0x20, 0x68, 0xa0, 0xf7, 0x6f, 0xa3, 0x81, 0xd6, 0x30, 0x81, 0xd3, 0x30, 0x1d, 0x06,
        0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xa8, 0x9b, 0x64, 0xd5, 0x87, 0x5a, 0x6f,
        0xf8, 0xa8, 0xee, 0x2b, 0xf3, 0x95, 0x89, 0x24, 0x17, 0x03, 0xf7, 0xd5, 0xce, 0x30, 0x1f,
        0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xf4, 0x7b, 0x2b, 0x78,
        0x48, 0x38, 0x3d, 0xe9, 0x7b, 0x91, 0xe6, 0x0c, 0x21, 0x64, 0xf6, 0xed, 0x51, 0x53, 0xd0,
        0x94, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
        0x03, 0x88, 0x30, 0x16, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x01, 0x01, 0xff, 0x04, 0x0c, 0x30,
        0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x69, 0x06, 0x06,
        0x67, 0x81, 0x05, 0x05, 0x04, 0x01, 0x04, 0x5f, 0x30, 0x5d, 0x82, 0x17, 0x30, 0x2e, 0x30,
        0x2e, 0x30, 0x2e, 0x30, 0x2d, 0x35, 0x30, 0x37, 0x32, 0x35, 0x32, 0x31, 0x35, 0x62, 0x65,
        0x74, 0x61, 0x28, 0x58, 0x29, 0x83, 0x01, 0x00, 0xa6, 0x3f, 0x30, 0x3d, 0x06, 0x09, 0x60,
        0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30, 0x8c, 0xd9, 0x25, 0x0a, 0xba,
        0x28, 0x28, 0xe1, 0x0b, 0x51, 0x65, 0xeb, 0xdd, 0xac, 0x47, 0xf0, 0x29, 0x9a, 0xa4, 0x56,
        0x34, 0x53, 0xa5, 0xb8, 0x83, 0x2f, 0x7c, 0x2a, 0x50, 0x32, 0x3b, 0x6e, 0x0d, 0xa5, 0xc0,
        0xb1, 0xfc, 0x44, 0x6c, 0xb1, 0x72, 0xfe, 0x9a, 0x99, 0x72, 0x9e, 0x9c, 0x58, 0x30, 0x0a,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x67, 0x00, 0x30, 0x64,
        0x02, 0x30, 0x4f, 0x45, 0x0d, 0xb7, 0xcd, 0xf3, 0xff, 0x7a, 0xe9, 0x7c, 0xd6, 0x1a, 0x28,
        0x58, 0x25, 0x53, 0x37, 0x35, 0x61, 0x0d, 0x1d, 0xcd, 0x7a, 0x22, 0x2c, 0x97, 0x64, 0x4d,
        0x57, 0x4c, 0x7d, 0x87, 0x03, 0x80, 0x14, 0x32, 0x62, 0x80, 0xea, 0x7b, 0x15, 0xd2, 0x91,
        0x38, 0x01, 0x09, 0x38, 0x0b, 0x02, 0x30, 0x10, 0x56, 0xa8, 0xc7, 0x62, 0x4f, 0xb4, 0x3b,
        0xa2, 0xcc, 0x6f, 0x61, 0x17, 0x06, 0x97, 0xb8, 0x10, 0x8f, 0x90, 0x90, 0x7e, 0xd1, 0xc2,
        0x0f, 0x84, 0xf3, 0xae, 0xda, 0xcd, 0x0b, 0x57, 0xcb, 0xf2, 0xd4, 0x79, 0xfb, 0xd3, 0x58,
        0x86, 0xbb, 0x44, 0xee, 0x0b, 0x5b, 0xb3, 0xa3, 0x47, 0x08,
    ];
    #[test]
    fn test_real_asp_certificate_chain_validation() {
        println!("🔍 Testing real certificate validation that's failing in the system...");
        println!(
            "Certificate data length: {} bytes",
            MOCK_TSM_GET_CERT_RSP.len()
        );
        println!("First 32 bytes: {:02x?}", &MOCK_TSM_GET_CERT_RSP[..32]);

        match deserialize_certificate_chain(MOCK_TSM_GET_CERT_RSP, SHA384_HASH_LEN) {
            Ok(cert_chain) => {
                println!("✓ Successfully parsed the certificate chain.");

                // Validate the certificate chain signatures and structure
                cert_chain
                    .validate_certificate_chain()
                    .expect("Certificate chain validation failed");

                println!("🎉 Test completed successfully! Certificate chain validation passed.");
            }
            Err(e) => {
                println!("✗ Failed to parse the certificate chain: {:?}", e);
                panic!("Test failed due to parsing error");
            }
        };
    }

    #[test]
    fn test_simple_dice_parsing() {
        // Test parsing DICE TCBInfo from both real Microsoft Azure certificates
        let test_certs = [
            "src/tdisp/test_certs/3437_cert.cer",
            "src/tdisp/test_certs/3437_hsm_alias.der",
        ];

        for cert_path in &test_certs {
            println!("Testing certificate: {}", cert_path);
            let cert_data = std::fs::read(cert_path).expect("Failed to read certificate file");

            // Use x509-cert crate for extension parsing
            let cert_x509 =
                Certificate::from_der(&cert_data).expect("Failed to parse with x509-cert");
            let extensions = cert_x509.tbs_certificate.extensions.as_ref();
            let mut found_dice_ext = false;

            if let Some(extensions) = extensions {
                for ext in extensions {
                    let ext_oid = ext.extn_id.to_string();
                    if ext_oid == "2.23.133.5.4.1" {
                        found_dice_ext = true;
                        let ext_data = ext.extn_value.as_bytes();
                        println!("Found DICE extension, data length: {}", ext_data.len());

                        // X.509 extension values are OCTET STRINGs, extract the inner content
                        let inner_data = match asn1::parse(ext_data, |d| d.read_element::<&[u8]>())
                        {
                            Ok(data) => data,
                            Err(_) => {
                                println!(
                                    "Failed to extract OCTET STRING content, trying direct parse"
                                );
                                ext_data
                            }
                        };

                        // Try parsing the inner ASN.1 data
                        match parse_dice_tcb_info_asn1(inner_data) {
                            Ok(dice_info) => {
                                println!("✓ Successfully parsed DICE TCBInfo:");
                                println!("  Vendor: {:?}", dice_info.vendor);
                                println!("  Model: {:?}", dice_info.model);
                                println!("  Version: {:?}", dice_info.version);
                                println!("  SVN: {:?}", dice_info.svn);
                                println!("  Layer: {:?}", dice_info.layer);
                                println!("  Index: {:?}", dice_info.index);
                                println!("  FWIDs count: {}", dice_info.fwids.len());
                                for (i, fwid) in dice_info.fwids.iter().enumerate() {
                                    println!(
                                        "    FWID[{}]: alg={}, digest={} bytes - {}",
                                        i,
                                        fwid.hash_alg,
                                        fwid.digest.len(),
                                        hex::encode(
                                            &fwid.digest[..std::cmp::min(16, fwid.digest.len())]
                                        )
                                    );
                                }
                                println!(
                                    "  Flags: {:?}",
                                    dice_info.flags.as_ref().map(|_| "present")
                                );
                                println!(
                                    "  Vendor Info: {:?}",
                                    dice_info
                                        .vendor_info
                                        .as_ref()
                                        .map(|v| format!("{} bytes", v.len()))
                                );
                                println!(
                                    "  Measurement Type: {:?}",
                                    dice_info
                                        .measurement_type
                                        .as_ref()
                                        .map(|m| format!("{} bytes", m.len()))
                                );
                                println!(
                                    "  Integrity Registers count: {}",
                                    dice_info.integrity_registers.len()
                                );
                                for (i, reg) in dice_info.integrity_registers.iter().enumerate() {
                                    println!(
                                        "    Register[{}]: name={:?}, num={:?}, digests={}",
                                        i,
                                        reg.register_name,
                                        reg.register_num,
                                        reg.register_digests.len()
                                    );
                                }
                            }
                            Err(e) => {
                                println!("✗ Failed to parse: {:?}", e);
                            }
                        }
                        break;
                    }
                }
            }

            assert!(
                found_dice_ext,
                "Should find DICE extension in {}",
                cert_path
            );
            println!();
        }

        // Now also test parsing DICE TCBInfo from MOCK_TSM_GET_CERT_RSP certificate chain
        println!("🔍 Testing DICE parsing from MOCK_TSM_GET_CERT_RSP certificate chain...");

        match deserialize_certificate_chain(MOCK_TSM_GET_CERT_RSP, SHA384_HASH_LEN) {
            Ok(cert_chain) => {
                println!("✓ Successfully parsed certificate chain from MOCK_TSM_GET_CERT_RSP");

                // Compute and print root certificate thumbprint (SHA-384)
                use openssl::hash::{MessageDigest, hash};
                let root_cert = cert_chain
                    .validate_certificate_chain()
                    .expect("Failed to validate certificate chain");
                let root_cert_der = root_cert
                    .to_der()
                    .expect("Failed to serialize root certificate to DER");
                let root_thumbprint_sha384 = hash(MessageDigest::sha384(), &root_cert_der)
                    .expect("Failed to compute SHA-384 hash");

                println!("\n📌 Root Certificate Thumbprint (SHA-384):");
                println!("   Hex: {}", hex::encode(root_thumbprint_sha384.as_ref()));
                println!(
                    "   Raw bytes: [{}]",
                    root_thumbprint_sha384
                        .as_ref()
                        .iter()
                        .map(|b| format!("0x{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!("   Length: {} bytes", root_thumbprint_sha384.len());
                println!(
                    "   (This is the expected thumbprint to include in CORIM identity triple)\n"
                );

                // Parse individual certificates from the chain
                match cert_chain.parse_x509_certificates() {
                    Ok(certificates) => {
                        println!(
                            "✓ Parsed {} certificates from the chain",
                            certificates.len()
                        );
                        let mut total_dice_extensions = 0;

                        // Check each certificate for DICE extensions
                        for (cert_index, cert) in certificates.iter().enumerate() {
                            println!(
                                "\n📋 Examining certificate #{} for DICE extensions...",
                                cert_index
                            );

                            // Get the subject for identification
                            let subject = cert
                                .subject_name()
                                .entries()
                                .filter_map(|e| e.data().as_utf8().ok())
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                                .join(", ");
                            println!("  Subject: {}", subject);

                            // Look for DICE extension using existing helper function
                            match extract_dice_tcb_info(cert) {
                                Ok(Some(dice_info)) => {
                                    total_dice_extensions += 1;
                                    println!(
                                        "✅ Found DICE TCBInfo extension in certificate #{}:",
                                        cert_index
                                    );
                                    println!("  Vendor: {:?}", dice_info.vendor);
                                    println!("  Model: {:?}", dice_info.model);
                                    println!("  Version: {:?}", dice_info.version);
                                    println!("  SVN: {:?}", dice_info.svn);
                                    println!("  Layer: {:?}", dice_info.layer);
                                    println!("  Index: {:?}", dice_info.index);
                                    println!("  FWIDs count: {}", dice_info.fwids.len());
                                    for (i, fwid) in dice_info.fwids.iter().enumerate() {
                                        println!(
                                            "    FWID[{}]: alg={}, digest={} bytes - {}",
                                            i,
                                            fwid.hash_alg,
                                            fwid.digest.len(),
                                            hex::encode(
                                                &fwid.digest
                                                    [..std::cmp::min(16, fwid.digest.len())]
                                            )
                                        );
                                    }
                                    println!(
                                        "  Flags: {:?}",
                                        dice_info.flags.as_ref().map(|_| "present")
                                    );
                                    println!(
                                        "  Vendor Info: {:?}",
                                        dice_info
                                            .vendor_info
                                            .as_ref()
                                            .map(|v| format!("{} bytes", v.len()))
                                    );
                                    println!(
                                        "  Measurement Type: {:?}",
                                        dice_info
                                            .measurement_type
                                            .as_ref()
                                            .map(|m| format!("{} bytes", m.len()))
                                    );
                                    println!(
                                        "  Integrity Registers count: {}",
                                        dice_info.integrity_registers.len()
                                    );
                                    for (i, reg) in dice_info.integrity_registers.iter().enumerate()
                                    {
                                        println!(
                                            "    Register[{}]: name={:?}, num={:?}, digests={}",
                                            i,
                                            reg.register_name,
                                            reg.register_num,
                                            reg.register_digests.len()
                                        );
                                    }
                                }
                                Ok(None) => {
                                    println!(
                                        "  No DICE TCBInfo extension found in certificate #{}",
                                        cert_index
                                    );
                                }
                                Err(e) => {
                                    println!(
                                        "  ❌ Error checking for DICE extension in certificate #{}: {:?}",
                                        cert_index, e
                                    );
                                }
                            }
                        }

                        println!(
                            "\n📊 Summary: Found {} DICE extensions across {} certificates in MOCK_TSM_GET_CERT_RSP",
                            total_dice_extensions,
                            certificates.len()
                        );
                    }
                    Err(e) => {
                        println!(
                            "❌ Failed to parse individual certificates from chain: {:?}",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                println!(
                    "❌ Failed to deserialize certificate chain from MOCK_TSM_GET_CERT_RSP: {:?}",
                    e
                );
            }
        }
    }
}
