// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use anyhow::Context;
use base64::Engine;
use corim_rs::{Corim, HashAlgorithm};
use hex;
use openhcl_tdisp_resources::VpciTdispInterface;
use openssl::sha::Sha384;
use openssl::x509::X509;
use sev_guest_device::ioctl::SevGuestDevice;
use sev_guest_device::protocol::TioMsgTdiInfoRsp;
use std::collections::HashMap;
use tdisp::{TdispDeviceReport, TdispDeviceReportType};
use tracing::Instrument;
use vpci_client::VpciDevice;

pub mod cert_generator;
pub mod corim_generator;
pub mod spdmcertchain;
pub mod spdmmeasurements;

/// Structure to hold both authenticity and trust CORIMs
#[allow(missing_docs)]
pub struct CorimPair<'a> {
    pub authenticity: Corim<'a>,
    pub trust: Corim<'a>,
}

/// TDISP verifier that manages CORIM mappings for device attestation
pub struct TdispVerifier<'a> {
    /// Map from (vendor_id, device_id) pairs to CORIM pairs (Authenticity and Trust)
    corims: HashMap<(u16, u16), CorimPair<'a>>,
}

impl<'a> TdispVerifier<'a> {
    /// Create a new TdispVerifier with an empty CORIM map
    pub fn new() -> Self {
        Self {
            corims: HashMap::new(),
        }
    }

    /// Add both Authenticity and Trust CORIMs for a specific vendor/device ID pair
    pub fn add_corim_pair(
        &mut self,
        vendor_id: u16,
        device_id: u16,
        authenticity: Corim<'a>,
        trust: Corim<'a>,
    ) {
        let corim_pair = CorimPair {
            authenticity,
            trust,
        };
        self.corims.insert((vendor_id, device_id), corim_pair);
    }

    /// Get the CORIM pair for a specific vendor/device ID pair
    pub fn get_corim_pair(&self, vendor_id: u16, device_id: u16) -> Option<&CorimPair<'a>> {
        self.corims.get(&(vendor_id, device_id))
    }

    /// Get the Authenticity CORIM for a specific vendor/device ID pair
    pub fn get_authenticity_corim(&self, vendor_id: u16, device_id: u16) -> Option<&Corim<'a>> {
        self.corims
            .get(&(vendor_id, device_id))
            .map(|pair| &pair.authenticity)
    }

    /// Get the Trust CORIM for a specific vendor/device ID pair
    pub fn get_trust_corim(&self, vendor_id: u16, device_id: u16) -> Option<&Corim<'a>> {
        self.corims
            .get(&(vendor_id, device_id))
            .map(|pair| &pair.trust)
    }

    /// Remove a CORIM pair for a specific vendor/device ID pair
    pub fn remove_corim_pair(&mut self, vendor_id: u16, device_id: u16) -> Option<CorimPair<'a>> {
        self.corims.remove(&(vendor_id, device_id))
    }

    /// Check if CORIMs exist for a specific vendor/device ID pair
    pub fn has_corims(&self, vendor_id: u16, device_id: u16) -> bool {
        self.corims.contains_key(&(vendor_id, device_id))
    }

    /// Add CORIMs with validity period validation
    /// Returns Ok(()) if both CORIMs are valid, Err otherwise
    pub fn add_corim_pair_with_validation(
        &mut self,
        vendor_id: u16,
        device_id: u16,
        authenticity_corim: Corim<'a>,
        trust_corim: Corim<'a>,
    ) -> Result<(), String> {
        // TODO: Validate signature and signer against authority in TDISP policy
        // Validate CORIM validity periods against current time
        // For now, skip validity period validation since the API might not be available
        // TODO: Implement CORIM validity period checking once the API is available
        // Check authenticity CORIM validity
        // if let (Some(not_before), Some(not_after)) = (authenticity_corim.validity_not_before(), authenticity_corim.validity_not_after()) {
        //     if current_time < not_before {
        //         return Err("Authenticity CORIM not yet valid (before not-before time)".to_string());
        //     }
        //     if current_time > not_after {
        //         return Err("Authenticity CORIM expired (after not-after time)".to_string());
        //     }
        // }

        // Check trust CORIM validity
        // if let (Some(not_before), Some(not_after)) = (trust_corim.validity_not_before(), trust_corim.validity_not_after()) {
        //     if current_time < not_before {
        //         return Err("Trust CORIM not yet valid (before not-before time)".to_string());
        //     }
        //     if current_time > not_after {
        //         return Err("Trust CORIM expired (after not-after time)".to_string());
        //     }
        // }

        // If all validations pass, store the CORIMs
        self.add_corim_pair(vendor_id, device_id, authenticity_corim, trust_corim);
        Ok(())
    }
}


/// Initialize TdispVerifier from VTL2 Settings TdispDeviceRims
///
/// This function reads the TDISP device RIMs from VTL2 settings and populates
/// the TdispVerifier with the authenticity and trust CORIMs for each device.
pub fn init_tdisp_verifier_from_settings(
    tdisp_device_rims: Option<&underhill_config::TdispDeviceRims>,
) -> Result<TdispVerifier<'static>, anyhow::Error> {
    let mut verifier = TdispVerifier::new();

    let Some(device_rims) = tdisp_device_rims else {
        tracing::info!("No TDISP device RIMs configured in VTL2 settings");
        return Ok(verifier);
    };

    tracing::info!(
        "Initializing TDISP verifier with {} device RIM(s) from VTL2 settings",
        device_rims.devices.len()
    );

    for device_rim in &device_rims.devices {
        tracing::debug!(
            "Loading CORIMs for device: vendor_id={:#x}, device_id={:#x}, name='{}'",
            device_rim.vendor_id,
            device_rim.device_id,
            device_rim.device_name
        );

        // Decode base64-encoded authenticity CORIM
        let auth_corim_bytes = base64::engine::general_purpose::STANDARD
            .decode(&device_rim.auth_rim)
            .with_context(|| {
                format!(
                    "Failed to decode authenticity RIM for device {}",
                    device_rim.device_name
                )
            })?;

        // Decode base64-encoded trust CORIM
        let trust_corim_bytes = base64::engine::general_purpose::STANDARD
            .decode(&device_rim.trust_rim)
            .with_context(|| {
                format!(
                    "Failed to decode trust RIM for device {}",
                    device_rim.device_name
                )
            })?;

        // Parse CORIMs from CBOR data
        // Note: We leak the memory here to get 'static lifetime for the CORIMs
        // This is acceptable since the verifier lives for the entire VM lifetime
        let auth_corim_bytes_static: &'static [u8] = Box::leak(auth_corim_bytes.into_boxed_slice());
        let trust_corim_bytes_static: &'static [u8] = Box::leak(trust_corim_bytes.into_boxed_slice());

        let auth_corim = parse_corim_from_cbor(auth_corim_bytes_static).with_context(|| {
            format!(
                "Failed to parse authenticity CORIM for device {}",
                device_rim.device_name
            )
        })?;

        let trust_corim = parse_corim_from_cbor(trust_corim_bytes_static).with_context(|| {
            format!(
                "Failed to parse trust CORIM for device {}",
                device_rim.device_name
            )
        })?;

        // Add CORIMs to verifier with validation
        verifier
            .add_corim_pair_with_validation(
                device_rim.vendor_id,
                device_rim.device_id,
                auth_corim,
                trust_corim,
            )
            .map_err(|e| anyhow::anyhow!(e))
            .with_context(|| {
                format!(
                    "Failed to register CORIMs for device {} (vendor_id={:#x}, device_id={:#x})",
                    device_rim.device_name, device_rim.vendor_id, device_rim.device_id
                )
            })?;

        tracing::info!(
            "Successfully loaded CORIMs for device '{}' (vendor_id={:#x}, device_id={:#x})",
            device_rim.device_name,
            device_rim.vendor_id,
            device_rim.device_id
        );
    }

    tracing::info!(
        "TDISP verifier initialized with {} device(s)",
        device_rims.devices.len()
    );

    Ok(verifier)
}

/// Helper function to parse CORIM from CBOR data
fn parse_corim_from_cbor(cbor_data: &[u8]) -> Result<Corim<'_>, anyhow::Error> {
    use coset::{CoseSign1, TaggedCborSerializable};

    // First try to parse as COSE-wrapped CoRIM (signed)
    match CoseSign1::from_tagged_slice(cbor_data) {
        Ok(cose_sign1) => {
            // Convert CoseSign1 to SignedCorim using TryFrom
            let signed_corim: corim_rs::SignedCorim = cose_sign1.try_into()
                .context("Failed to convert CoseSign1 to SignedCorim")?;

            // Create TaggedSignedCorim from SignedCorim
            let tagged_signed = corim_rs::TaggedSignedCorim::new(signed_corim);
            Ok(corim_rs::ConciseRimTypeChoice::Signed(tagged_signed))
        }
        Err(_) => {
            // If not COSE-wrapped, try parsing as unsigned CorimMap
            let corim_map: corim_rs::CorimMap<'_> = ciborium::de::from_reader(cbor_data)
                .context("Failed to parse unsigned CorimMap")?;

            Ok(corim_rs::ConciseRimTypeChoice::Unsigned(corim_rs::TaggedUnsignedCorim::from(corim_map)))
        }
    }
}

/// Main TDISP device attestation entry point
///
/// Returns Ok(()) if attestation succeeds, Err if it fails
pub async fn attest_device(
    vpci_device: std::sync::Arc<VpciDevice>,
    verifier: &TdispVerifier<'_>,
) -> Result<(), anyhow::Error> {
    // Get the device vendor/device IDs from the VPCI device
    let vendor_id = vpci_device.vendor_id();
    let device_id = vpci_device.device_id();

    async {
        tracing::info!("Starting TDISP device attestation");

        // Check if we have CORIMs for this device
        if !verifier.has_corims(vendor_id, device_id) {
            tracing::warn!("No CORIMs registered — MMIO/DMA will be blocked");
            vpci_device.set_attestation_passed(false);
            return Ok(());
        }

        // Perform local attestation
        tracing::info!("Performing local attestation");

        let (authentic, tcb_up_to_date) =
            local_attestation(&vpci_device, verifier).await;

        let passed = authentic && tcb_up_to_date;

        // Store the rolled-up attestation result — enforcement happens at MMIO/DMA enable time
        vpci_device.set_attestation_passed(passed);

        if passed {
            tracing::info!("TDISP device attestation passed");
        } else {
            tracing::warn!(
                authentic,
                tcb_up_to_date,
                "TDISP device attestation failed — MMIO/DMA will be blocked"
            );
        }

        Ok(())
    }
    .instrument(tracing::info_span!(
        "attest_device",
        vendor_id = format!("{:#x}", vendor_id),
        device_id = format!("{:#x}", device_id),
    ))
    .await
}

/// Performs local attestation of a TDISP device
///
/// Returns a tuple of (identity_verified, measurements_verified)
pub async fn local_attestation(
    vpci_device: &VpciDevice,
    verifier: &TdispVerifier<'_>,
) -> (bool, bool) {
    let vendor_id = vpci_device.vendor_id();
    let device_id = vpci_device.device_id();

    let corim_pair = match verifier.get_corim_pair(vendor_id, device_id) {
        Some(pair) => pair,
        None => {
            tracing::error!("No CORIMs found for device");
            return (false, false);
        }
    };

    tracing::debug!("Retrieved CORIMs for device");

    // TODO: Verify CORIM validity periods

    // Get TDI_INFO response from TSM directly via TIO_MSG_TDI_INFO_REQ guest message
    let tdi_info = match get_tdi_info_from_tsm(vpci_device).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("Failed to get TDI_INFO from TSM: {}", e);
            return (false, false);
        }
    };

    tracing::debug!(
        "TDI_INFO retrieved: guest_device_id={}, tdi_status={:#x}, certs_digest={:02x?}, meas_digest={:02x?}",
        tdi_info.guest_device_id,
        tdi_info.tdi_status,
        &tdi_info.certs_digest[..8],
        &tdi_info.meas_digest[..8]
    );

    // Get device certificate chain from host
    let cert_chain_response = match get_certchain_from_host(vpci_device).await {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!("Failed to get certificate chain from VPCI device: {}", e);
            return (false, false);
        }
    };

    // Verify digest of certificate chain response against TDI_INFO.certs_digest
    let cert_chain_digest = sha_384(&cert_chain_response);
    if cert_chain_digest != tdi_info.certs_digest {
        tracing::error!("Certificate chain digest mismatch - untrusted host response detected!");
        tracing::debug!("Expected digest (SHA-384): {:02x?}", tdi_info.certs_digest);
        tracing::debug!("Actual digest (SHA-384): {:02x?}", cert_chain_digest);
        return (false, false);
    }

    tracing::debug!(
        "Certificate chain digest verification passed (SHA-384): {:02x?}",
        &cert_chain_digest[..8]
    );

    if cert_chain_response.len() >= 2 {
        let response_code = cert_chain_response[1]; // SPDM response code is at offset 1
        tracing::debug!("SPDM response code: 0x{:02x}", response_code);
        if response_code == 0x08 {
            tracing::warn!(
                "Device returned GET_MEASUREMENTS response (0x08) instead of GET_CERTIFICATE response (0x02)"
            );
        }
    }

    // The ASP returns the CertificateChain structure directly, not wrapped in SPDM
    // Parse it directly using the deserialize_certificate_chain function
    let certificate_chain =
        match spdmcertchain::deserialize_certificate_chain(&cert_chain_response, spdmcertchain::SHA384_HASH_LEN) {
            Ok(chain) => chain,
            Err(e) => {
                tracing::error!("Failed to parse certificate chain: {}", e);
                return (false, false);
            }
        };

    tracing::debug!(
        "Parsed certificate chain: length={}, root_hash_len={}, certificates_len={}",
        certificate_chain.length,
        certificate_chain.root_hash.len(),
        certificate_chain.certificates.len()
    );

    // Validate certificate chain consistency and thumbprint matching
    match validate_certificate_chain(&certificate_chain, &corim_pair.authenticity).await {
        Ok(_) => {},
        Err(e) => {
            tracing::error!("Failed to validate certificate chain: {}", e);
            return (false, false);
        }
    };

    // Validate TCBInfo values against CORIMs
    let (authentic, tcb_up_to_date) = match validate_tcb_info(&certificate_chain, corim_pair).await
    {
        Ok((auth, tcb)) => (auth, tcb),
        Err(e) => {
            tracing::error!("Failed to validate TCBInfo: {}", e);
            (false, false)
        }
    };

    if !authentic || !tcb_up_to_date {
        tracing::error!(
            "Certificate TCBInfo validation failed: authentic={}, tcb_up_to_date={}",
            authentic,
            tcb_up_to_date
        );
        return (authentic, tcb_up_to_date);
    }

    tracing::debug!(
        "Certificate TCBInfo validation completed: authentic={}, tcb_up_to_date={}",
        authentic,
        tcb_up_to_date
    );

    // Get measurements from host
    let measurements_response = match get_measurements_from_host(vpci_device).await {
        Ok(measurements) => measurements,
        Err(e) => {
            tracing::error!("Failed to get measurements from VPCI device: {}", e);
            return (false, false);
        }
    };

    // Verify digest of measurements response against TDI_INFO.meas_digest
    let measurements_digest = sha_384(&measurements_response);
    if measurements_digest != tdi_info.meas_digest {
        tracing::error!("Measurements digest mismatch - untrusted host response detected!");
        tracing::debug!("Expected digest (SHA-384): {:02x?}", tdi_info.meas_digest);
        tracing::debug!("Actual digest (SHA-384): {:02x?}", measurements_digest);
        return (false, false);
    }

    tracing::debug!(
        "Measurements digest verification passed (SHA-384): {:02x?}",
        &measurements_digest[..8]
    );

    // Step 6: Measurement report validation
    let (measurements_authentic, measurements_up_to_date) =
        match validate_measurements(&measurements_response, corim_pair).await {
            Ok((auth, up_to_date)) => (auth, up_to_date),
            Err(e) => {
                tracing::error!("Failed to validate measurements: {}", e);
                return (false, false);
            }
        };

    if !measurements_authentic || !measurements_up_to_date {
        tracing::error!(
            "Measurements validation failed: authentic={}, up_to_date={}",
            measurements_authentic,
            measurements_up_to_date
        );
        return (measurements_authentic, measurements_up_to_date);
    }

    tracing::debug!(
        "Measurements validation completed: authentic={}, up_to_date={}",
        measurements_authentic,
        measurements_up_to_date
    );

    // TODO: what about device interface report?
    (true, true)
}

/// Helper function to get TDI_INFO response from TSM via TIO_MSG_TDI_INFO_REQ
async fn get_tdi_info_from_tsm(vpci_device: &VpciDevice) -> anyhow::Result<TioMsgTdiInfoRsp> {
    let guest_device_id = vpci_device
        .tdisp_get_tdi_device_id()
        .await
        .context("Failed to get TDI device ID")?;

    tracing::debug!("Got guest device ID: {}", guest_device_id);

    let mut sev_dev = SevGuestDevice::open().context("Failed to open /dev/sev-guest")?;

    let tdi_info = sev_dev
        .tio_msg_tdi_info_req(guest_device_id as u16)
        .context("Failed to issue TIO_MSG_TDI_INFO_REQ to TSM")?;

    Ok(tdi_info)
}

/// Helper function to get certificate chain from VPCI device
async fn get_certchain_from_host(vpci_device: &VpciDevice) -> anyhow::Result<Vec<u8>> {
    // Request certificate chain report from the VPCI device
    /*
    The firmware sends the GET_CERTIFICATES request to the device to request the certificate chain of the device using the SlotID used to establish the SPDM connection. The firmware fills the SPDM output buffer with an SPDM Certificates Object defined in Chapter 6. The firmware also stores the SHA-384 digest of the retrieved certificates in the device context page, replacing any previously saved digest.

    6.1 Certificates Object
    TIO_DEV_CERTIFICATES returns a certificate chain retrieved from the device using the GET_CERTIFICATES SPDM request message. The SEV firmware returns the X.509 certificate chain provided by the device unaltered.
    */
    let cert_chain_data = vpci_device
        .tdisp_get_device_report(&TdispDeviceReportType::DeviceReport(
            TdispDeviceReport::DeviceInfoCertificateChain,
        ))
        .await
        .context("Failed to get certificate chain from VPCI device")?;

    tracing::debug!(
        "Certificate chain retrieved from device: {} bytes",
        cert_chain_data.len()
    );

    Ok(cert_chain_data)
}

/// Helper function to get measurements from VPCI device
async fn get_measurements_from_host(vpci_device: &VpciDevice) -> anyhow::Result<Vec<u8>> {
    // Request measurements report from the VPCI device
    /*
    Get_measurements SPDM report from the VPCI device - TdispDeviceReport::DeviceMeasurements
    The firmware sends the GET_MEASUREMENTS request to the device and returns the measurements
    in the SPDM format. The SEV firmware also stores the SHA-384 digest of the retrieved
    measurements in the device context page, replacing any previously saved digest.
    */
    let measurements_data = vpci_device
        .tdisp_get_device_report(&TdispDeviceReportType::DeviceReport(
            TdispDeviceReport::DeviceInfoMeasurements,
        ))
        .await
        .context("Failed to get measurements from VPCI device")?;

    tracing::debug!(
        "Measurements retrieved from device: {} bytes",
        measurements_data.len()
    );

    Ok(measurements_data)
}

/// Helper function to compute SHA-384 digest
fn sha_384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finish()
}

/// Validate certificate chain consistency from SPDM certificate chain response
///
/// 
/// 1. Verify certificate chain is consistent (signatures and subject/issuer matching)
/// 2. Compare root certificate thumbprint against CORIM device identity triple
async fn validate_certificate_chain(
    cert_chain: &spdmcertchain::CertificateChain,
    authenticity_corim: &Corim<'_>,
) -> Result<bool, anyhow::Error> {
    use openssl::hash::{MessageDigest, hash};

    tracing::debug!(
        "Validating SPDM certificate chain: length={}, root_hash_size={}",
        cert_chain.length,
        cert_chain.root_hash.len()
    );

    // Validate the X.509 certificate chain structure and signatures
    let root_cert = cert_chain
        .validate_certificate_chain()
        .context("Certificate chain validation failed")?;

    // Get the root certificate DER encoding
    let root_cert_der = root_cert
        .to_der()
        .context("Failed to serialize root certificate to DER")?;

    // Extract CorimMap from the Corim enum
    let corim_map: &corim_rs::CorimMap<'_> = match authenticity_corim {
        corim_rs::ConciseRimTypeChoice::Unsigned(tagged) => tagged,
        corim_rs::ConciseRimTypeChoice::Signed(signed) => &signed.corim_map,
    };

    // Loop over COMID tags for dev-identity-keys triple (IdentityTripleRecord)
    // TODO: Look for triple with environment.instance as base64(SPDM_certificate)
    for tag in &corim_map.tags {
        // Check if this tag is a CoMID (Concise Module Identity)
        if let corim_rs::ConciseTagTypeChoice::Mid(comid_tag) = tag {
            let comid = &**comid_tag;

            // Get identity triples from the CoMID triples
            if let Some(ref identity_triples) = comid.triples.identity_triples {
                for triple in identity_triples {
                    // Iterate through the key_list in the IdentityTripleRecord
                    for crypto_key in &triple.key_list {
                        // Check if this is a CertThumbprint variant
                        if let Some(cert_thumbprint) = crypto_key.as_ref_cert_thumbprint() {
                            // CertThumbprintType wraps a Digest, access it
                            let digest = cert_thumbprint.as_ref();

                            // Use the digest algorithm from the identity triple to compute thumbprint
                            let message_digest = match digest.alg {
                                HashAlgorithm::Sha256 => MessageDigest::sha256(),
                                HashAlgorithm::Sha384 => MessageDigest::sha384(),
                                HashAlgorithm::Sha512 => MessageDigest::sha512(),
                                _ => {
                                    tracing::debug!(
                                        "Unsupported hash algorithm in identity triple: {:?}",
                                        digest.alg
                                    );
                                    continue;
                                }
                            };

                            // Compute thumbprint using the algorithm from the identity triple
                            let root_thumbprint = hash(message_digest, &root_cert_der)
                                .context("Failed to compute root certificate hash")?;

                            // Get the expected digest value bytes from CORIM
                            let expected_thumbprint = digest.val.as_ref();

                            // Compare thumbprints
                            if root_thumbprint.as_ref() == expected_thumbprint {
                                tracing::debug!(
                                    "Root certificate thumbprint matches CORIM device identity using {:?}",
                                    digest.alg
                                );
                                return Ok(true);
                            } else {
                                tracing::debug!(
                                    "Thumbprint mismatch ({}): computed={}, expected={}",
                                    format!("{:?}", digest.alg).to_uppercase(),
                                    hex::encode(root_thumbprint.as_ref()),
                                    hex::encode(expected_thumbprint)
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    anyhow::bail!("Root certificate thumbprint does not match any device identity in CORIM");
}

/// Validate TCBInfo values from certificate chain against CORIM reference values and Trust CORIM endorsements
///
/// Steps:
/// 4c. Apply all TCBInfo reference value triples from the Authenticity CORIM to the certificate chain
/// 4d. Verify TCBInfo values against Trust CORIM conditional endorsement series
async fn validate_tcb_info(
    cert_chain: &spdmcertchain::CertificateChain,
    corim_pair: &CorimPair<'_>,
) -> Result<(bool, bool), anyhow::Error> {
    // Parse X.509 certificates to extract TCBInfo extensions
    let x509_certs = cert_chain
        .parse_x509_certificates()
        .context("Failed to parse X.509 certificates for TCBInfo extraction")?;

    if x509_certs.is_empty() {
        anyhow::bail!("Certificate chain is empty - cannot extract TCBInfo");
    }

    tracing::debug!(
        "Extracted {} certificates from certificate chain for TCBInfo validation",
        x509_certs.len()
    );

    // Step 4c: Apply all TCBInfo reference value triples from the Authenticity CORIM
    // Process CORIM reference triples first and match against corresponding certificate layers
    let authenticity_valid =
        validate_tcb_against_authenticity_corim(&x509_certs, &corim_pair.authenticity)?;

    if !authenticity_valid {
        tracing::error!("TCBInfo validation failed against Authenticity CORIM reference values");
        return Ok((false, false));
    }

    tracing::debug!("TCBInfo validation passed against Authenticity CORIM");

    // Step 4d: Verify TCBInfo values against Trust CORIM conditional endorsement series
    let tcb_up_to_date = validate_tcb_against_trust_corim(&x509_certs, &corim_pair.trust)?;

    if !tcb_up_to_date {
        tracing::warn!("TCBInfo is not up-to-date according to Trust CORIM endorsements");
        return Ok((true, false)); // Authentic but not up-to-date
    }

    tracing::debug!("TCBInfo is up-to-date according to Trust CORIM");

    Ok((true, true))
}

/// Validate TCBInfo values against Authenticity CORIM reference value triples
/// Now processes CORIM reference triples first and matches against certificate layers
fn validate_tcb_against_authenticity_corim(
    x509_certs: &[X509],
    authenticity_corim: &Corim<'_>,
) -> Result<bool, anyhow::Error> {
    use crate::tdisp::spdmcertchain::extract_dice_tcb_info;

    // Extract CorimMap from the Corim enum
    let corim_map: &corim_rs::CorimMap<'_> = match authenticity_corim {
        corim_rs::ConciseRimTypeChoice::Unsigned(tagged) => tagged,
        corim_rs::ConciseRimTypeChoice::Signed(signed) => &signed.corim_map,
    };

    let mut validated_layers = 0;
    let mut total_tcb_triples = 0;

    // Process all reference triples looking for TCBInfo entries
    for tag in &corim_map.tags {
        if let corim_rs::ConciseTagTypeChoice::Mid(comid_tag) = tag {
            let comid = &**comid_tag;

            if let Some(ref reference_triples) = comid.triples.reference_triples {
                for triple in reference_triples {
                    // Check if this is a TCBInfo reference triple and get the target layer/certificate
                    if let Some((layer_val, cert_index)) =
                        get_tcb_info_layer_and_cert_index(&triple.ref_env, x509_certs.len())?
                    {
                        total_tcb_triples += 1;

                        tracing::debug!("Found TCBInfo reference triple for layer {}", layer_val);

                        // Extract DICE TCBInfo from the corresponding certificate
                        let cert = &x509_certs[cert_index];
                        match extract_dice_tcb_info(cert)? {
                            Some(dice_tcb_info) => {
                                if validate_dice_tcb_against_reference_claims(
                                    &dice_tcb_info,
                                    triple,
                                    Some(layer_val),
                                )? {
                                    validated_layers += 1;
                                    tracing::info!(
                                        "TCBInfo validation passed for layer {}",
                                        layer_val
                                    );
                                } else {
                                    tracing::error!(
                                        "TCBInfo validation failed for layer {}",
                                        layer_val
                                    );
                                    return Ok(false);
                                }
                            }
                            None => {
                                tracing::error!(
                                    "No DICE TCBInfo found in certificate at index {} for layer {}",
                                    cert_index,
                                    layer_val
                                );
                                return Ok(false);
                            }
                        }
                    }
                }
            }
        }
    }

    tracing::debug!(
        "TCBInfo validation summary: {}/{} TCBInfo layers validated",
        validated_layers,
        total_tcb_triples
    );

    if total_tcb_triples == 0 {
        tracing::error!("No TCBInfo reference triples found in Authenticity CORIM");
        return Ok(false);
    }

    // All TCBInfo reference triples must be validated
    if total_tcb_triples > 0 && validated_layers != total_tcb_triples {
        return Ok(false);
    }

    Ok(true)
}

const TCB_INFO_BYTES: [u8; 12] = [86, 69, 78, 67, 83, 87, 53, 109, 98, 119, 61, 61];

/// Helper function to check if an environment is a TCBInfo environment and get the target certificate
///
/// Returns:
/// - Ok(Some((layer, cert_index))) if this is a valid TCBInfo environment with sufficient certificates
/// - Ok(None) if this is not a TCBInfo environment (caller should skip this triple)  
/// - Err(...) if this is a TCBInfo environment but validation failed (attestation should fail)
fn get_tcb_info_layer_and_cert_index(
    env: &corim_rs::EnvironmentMap<'_>,
    x509_certs_len: usize,
) -> Result<Option<(u64, usize)>, anyhow::Error> {
    // Check if environment instance is "TCBInfo"
    let is_tcb_info = if let Some(ref instance) = env.instance {
        match instance {
            corim_rs::InstanceIdTypeChoice::Bytes(tagged_bytes) => {
                // Extract bytes from TaggedBytes and check if it's "TCBInfo"
                let bytes: &[u8] = tagged_bytes.as_ref().as_ref();
                bytes == &TCB_INFO_BYTES
            }
            _ => false,
        }
    } else {
        false
    };

    if !is_tcb_info {
        // Not a TCBInfo environment - caller should skip this triple
        return Ok(None);
    }

    // This IS a TCBInfo environment, so validation failures should fail attestation

    // Check if layer is present and is 0 or 1
    let layer_val = if let Some(ref class) = env.class {
        if let Some(layer) = class.layer {
            let layer_val = layer.0 as u64;
            if layer_val == 0 || layer_val == 1 {
                layer_val
            } else {
                anyhow::bail!(
                    "TCBInfo environment has unsupported layer: {} (only 0 and 1 are supported)",
                    layer_val
                );
            }
        } else {
            anyhow::bail!("TCBInfo environment missing required layer information");
        }
    } else {
        anyhow::bail!("TCBInfo environment missing required class information");
    };

    // Map DICE layer to certificate index
    // cert[0] = root certificate
    // Layer 0 = Second-to-last certificate (intermediate, index n-2)
    // Layer 1 = Last certificate (leaf, index n-1)
    // Expect at least 2 certificates in the chain
    if x509_certs_len < 2 {
        anyhow::bail!(
            "Certificate chain too short: {} certificates (minimum 2 required)",
            x509_certs_len
        );
    }

    let cert_index = match layer_val {
        0 => x509_certs_len - 2, // Layer 0 = Second-to-last certificate (intermediate)
        1 => x509_certs_len - 1, // Layer 1 = Last certificate (leaf)
        _ => unreachable!(),     // Should not happen due to earlier check
    };

    if cert_index >= x509_certs_len {
        anyhow::bail!(
            "TCBInfo layer {} maps to certificate index {}, but only {} certificates available",
            layer_val,
            cert_index,
            x509_certs_len
        );
    }

    Ok(Some((layer_val, cert_index)))
}

/// Check if all criteria in a MeasurementValuesMap are supported by our implementation
///
/// This function implements "fail-closed" security by explicitly checking every possible
/// field in MeasurementValuesMap and failing if any unsupported criteria are present.
///
/// Currently supported fields:
/// - version: Version matching
/// - svn: Security Version Number validation (exact or minimum)
/// - digests: FWID digest validation
/// - integrity_registers: Integrity register validation
///
/// Logs a warning if any unsupported criteria are found, but always returns true (warning-only policy).
fn validate_measurement_values_map_support(
    mval: &corim_rs::MeasurementValuesMap<'_>,
    context: &str,
) {
    let mut unsupported_fields = Vec::new();

    // Unsupported fields - these cause validation failure
    if mval.flags.is_some() {
        unsupported_fields.push("flags");
    }
    if mval.raw.is_some() {
        unsupported_fields.push("raw");
    }
    if mval.mac_addr.is_some() {
        unsupported_fields.push("mac_addr");
    }
    if mval.ip_addr.is_some() {
        unsupported_fields.push("ip_addr");
    }
    if mval.serial_number.is_some() {
        unsupported_fields.push("serial_number");
    }
    if mval.ueid.is_some() {
        unsupported_fields.push("ueid");
    }
    if mval.uuid.is_some() {
        unsupported_fields.push("uuid");
    }
    if mval.name.is_some() {
        unsupported_fields.push("name");
    }
    if mval.cryptokeys.is_some() {
        unsupported_fields.push("cryptokeys");
    }
    if mval.tcb_status.is_some() {
        unsupported_fields.push("tcb_status");
    }
    if mval.tcb_date.is_some() {
        unsupported_fields.push("tcb_date");
    }
    if mval.tcb_status_details.is_some() {
        unsupported_fields.push("tcb_status_details");
    }
    if mval.extensions.is_some() {
        unsupported_fields.push("extensions");
    }

    if !unsupported_fields.is_empty() {
        tracing::warn!(
            "{}: Validation contains unsupported criteria: [{}]. Only 'version', 'svn', 'digests', and 'integrity_registers' fields are evaluated.",
            context,
            unsupported_fields.join(", ")
        );
    }
}

/// Validate a single MeasurementMap against DICE TCB info
///
/// This function performs comprehensive validation of all supported fields in a MeasurementMap
/// against the corresponding values in DICE TCB info. All present fields must match for success.
///
/// Supported fields: version, svn, digests (FWIDs), integrity_registers
///
/// ## Return Values
///
/// - `Ok(true)`: ALL present criteria match successfully
/// - `Ok(false)`: Some criteria failed validation (mismatch - logged as error)
///
/// Note: Unsupported validation criteria are logged as warnings but do not cause failure
/// (warning-only policy, same as SPDM measurements).
fn validate_measurement_map_against_dice_tcb(
    measurement_map: &corim_rs::MeasurementMap<'_>,
    dice_tcb_info: &spdmcertchain::DiceTcbInfo,
    context: &str,
) -> Result<bool, anyhow::Error> {
    let mut checks_performed = 0;

    // Log warnings for any unsupported criteria (warning-only policy)
    validate_measurement_values_map_support(&measurement_map.mval, context);

    // Check version if present
    if let Some(ref version_claim) = measurement_map.mval.version {
        checks_performed += 1;
        if let Some(ref dice_version) = dice_tcb_info.version {
            let version_str = &version_claim.version;
            if dice_version != version_str {
                tracing::error!("{}: version mismatch: DICE='{}' vs reference='{}'", context, dice_version, version_str);
                return Ok(false);
            }
        } else {
            tracing::error!("{}: DICE has no version, but reference expects '{}'", context, version_claim.version);
            return Ok(false);
        }
    }

    // Check SVN if present
    if let Some(ref svn_claim) = measurement_map.mval.svn {
        checks_performed += 1;

        let (_, svn_valid) = validate_svn_claim(svn_claim, dice_tcb_info.svn, context);

        if !svn_valid {
            return Ok(false);
        }
    }

    // Check digests (FWIDs) if present
    if let Some(ref digests) = measurement_map.mval.digests {
        checks_performed += 1;

        let fwid_context = format!("FWID validation for {}", context);
        if !validate_reference_digests_against_fwids(digests, &dice_tcb_info.fwids, &fwid_context)?
        {
            return Ok(false);
        }
    }

    // Check integrity registers if present
    if let Some(ref integrity_registers_claim) = measurement_map.mval.integrity_registers {
        checks_performed += 1;

        let ir_context = format!("Integrity register validation for {}", context);
        if !validate_integrity_registers(
            integrity_registers_claim,
            &dice_tcb_info.integrity_registers,
            &ir_context,
        )? {
            return Ok(false);
        }
    }

    if checks_performed == 0 {
        tracing::warn!("{}: no validation requirements found in measurement map", context);
        return Ok(false);
    }

    tracing::debug!("{}: all {} validation criteria matched", context, checks_performed);
    Ok(true)
}

/// Helper function to validate SVN claims against current SVN value
///
/// The comparison type is inferred from the SvnTypeChoice:
/// - Svn and TaggedSvn: exact comparison (current == reference)
/// - TaggedMinSvn: minimum comparison (current >= reference)
///
/// Returns (extracted_svn_value, validation_result)
fn validate_svn_claim(
    svn_claim: &corim_rs::SvnTypeChoice,
    current_svn: Option<u64>,
    context: &str,
) -> (u64, bool) {
    // Extract SVN value and determine comparison type from the claim variant
    let (reference_svn, is_minimum_check) = match svn_claim {
        corim_rs::SvnTypeChoice::Svn(svn) => (svn.0 as u64, false), // exact comparison
        corim_rs::SvnTypeChoice::TaggedSvn(tagged_svn) => (tagged_svn.as_ref().0 as u64, false), // exact comparison
        corim_rs::SvnTypeChoice::TaggedMinSvn(tagged_min_svn) => {
            (tagged_min_svn.as_ref().0 as u64, true)
        } // minimum comparison
    };

    // Check if current SVN exists
    let Some(current_svn_val) = current_svn else {
        tracing::error!("{}: no current SVN available, but claim requires SVN={}", context, reference_svn);
        return (reference_svn, false);
    };

    // Perform comparison based on the SVN type
    let validation_result = if is_minimum_check {
        if current_svn_val >= reference_svn {
            true
        } else {
            tracing::error!("{}: SVN below minimum: current={} < required={}", context, current_svn_val, reference_svn);
            false
        }
    } else {
        if current_svn_val == reference_svn {
            true
        } else {
            tracing::error!("{}: SVN mismatch: current={} vs required={}", context, current_svn_val, reference_svn);
            false
        }
    };

    (reference_svn, validation_result)
}

/// Helper function to validate reference digests against a collection of FWIDs
///
/// This function checks that ALL reference digests find matching FWIDs in the provided collection.
/// Returns true only if every reference digest has a corresponding FWID match.
fn validate_reference_digests_against_fwids(
    reference_digests: &[corim_rs::Digest],
    fwids: &[spdmcertchain::Fwid],
    context: &str,
) -> Result<bool, anyhow::Error> {
    if fwids.is_empty() {
        tracing::error!("{}: no FWIDs available but {} reference digest(s) provided", context, reference_digests.len());
        return Ok(false);
    }

    // For each reference digest, check if ANY FWID matches - ALL reference digests must be found
    for (digest_idx, reference_digest) in reference_digests.iter().enumerate() {
        let reference_bytes: &[u8] = reference_digest.val.as_ref();

        let mut found_matching_fwid = false;
        for (_fwid_idx, dice_fwid) in fwids.iter().enumerate() {
            if dice_fwid.digest == reference_bytes {
                found_matching_fwid = true;
                break;
            }
        }

        if !found_matching_fwid {
            tracing::error!("{}: reference digest #{} has no matching FWID", context, digest_idx);
            return Ok(false);
        }
    }

    Ok(true)
}

/// Helper function to validate integrity registers using FWID-style verification
///
/// For each reference integrity register:
/// 1. Find corresponding integrity register from DICE TCB info using the label
/// 2. If match found, do FWID-style verification (any digest in register can match any reference digest)
/// 3. All reference integrity registers must find a match
fn validate_integrity_registers(
    reference_registers: &corim_rs::IntegrityRegisters<'_>,
    dice_registers: &[spdmcertchain::IntegrityRegister],
    context: &str,
) -> Result<bool, anyhow::Error> {
    if dice_registers.is_empty() {
        tracing::error!("{}: no integrity registers available but {} reference register(s) provided", context, reference_registers.len());
        return Ok(false);
    }

    // For each reference integrity register, find matching DICE integrity register and validate
    for (ref_reg_idx, (ref_label, ref_digests)) in reference_registers.iter().enumerate() {
        let mut found_matching_register = false;

        for (_dice_reg_idx, dice_integrity_reg) in dice_registers.iter().enumerate() {
            // Match by register label (name or number)
            let label_matches = match ref_label {
                corim_rs::Ulabel::Text(ref_text) => {
                    if let Some(dice_name) = &dice_integrity_reg.register_name {
                        let ref_name_str: &str = ref_text.as_ref();
                        ref_name_str == dice_name
                    } else {
                        false
                    }
                }
                corim_rs::Ulabel::Uint(ref_uint) => {
                    if let Some(dice_num) = dice_integrity_reg.register_num {
                        let ref_num_val = ref_uint.0 as u64;
                        ref_num_val == dice_num
                    } else {
                        false
                    }
                }
            };

            if label_matches {
                // Convert DICE register digests to FWID format for reuse of validation function
                let dice_fwids: Vec<spdmcertchain::Fwid> = dice_integrity_reg
                    .register_digests
                    .iter()
                    .map(|digest| spdmcertchain::Fwid {
                        hash_alg: digest.hash_alg.clone(),
                        digest: digest.digest.clone(),
                    })
                    .collect();

                let register_context = format!(
                    "{}: Register #{} (label={:?})",
                    context, ref_reg_idx, ref_label
                );
                if validate_reference_digests_against_fwids(
                    ref_digests,
                    &dice_fwids,
                    &register_context,
                )? {
                    found_matching_register = true;
                    break;
                }
            }
        }

        if !found_matching_register {
            tracing::error!("{}: no matching DICE integrity register found for reference register #{} (label={:?})", context, ref_reg_idx, ref_label);
            return Ok(false);
        }
    }

    Ok(true)
}

/// Validate a specific DICE TCBInfo against reference claims in a triple
///
/// A reference triple contains a list of claims of type MeasurementMap - only ONE claim needs to match entirely
/// Currently we check for version, svn, digests (FWIDs), and integrity registers
fn validate_dice_tcb_against_reference_claims(
    dice_tcb_info: &spdmcertchain::DiceTcbInfo,
    reference_triple: &corim_rs::ReferenceTripleRecord<'_>,
    layer: Option<u64>,
) -> Result<bool, anyhow::Error> {
    tracing::debug!(
        "Validating {} reference claim(s) for layer {:?}",
        reference_triple.ref_claims.len(),
        layer
    );

    // Try to match each reference claim - only ONE needs to match entirely
    for (claim_idx, claim) in reference_triple.ref_claims.iter().enumerate() {
        let context = format!("Reference claim #{} (layer {:?})", claim_idx, layer);

        // Use the common validation function
        if validate_measurement_map_against_dice_tcb(claim, dice_tcb_info, &context)? {
            tracing::info!(
                "Reference claim {} validated successfully for layer {:?}",
                claim_idx,
                layer
            );
            return Ok(true);
        }
    }

    // No reference claim matched entirely
    tracing::error!("No reference claim matched for layer {:?}", layer);
    Ok(false)
}

/// Validate TCBInfo values against Trust CORIM conditional endorsement series
///
/// Conditional endorsement series handle scenarios where measurements may change over time
/// in a defined sequence. This function:
/// 1. Tracks initial environment state and measurements
/// 2. Evaluates series of allowed measurement changes  
/// 3. Performs required verification at each step
fn validate_tcb_against_trust_corim(
    x509_certs: &[X509],
    trust_corim: &Corim<'_>,
) -> Result<bool, anyhow::Error> {
    use spdmcertchain::extract_dice_tcb_info;

    // Extract CorimMap from the Trust CORIM
    let corim_map: &corim_rs::CorimMap<'_> = match trust_corim {
        corim_rs::ConciseRimTypeChoice::Unsigned(tagged) => tagged,
        corim_rs::ConciseRimTypeChoice::Signed(signed) => &signed.corim_map,
    };

    let mut all_layers_current = true;
    let mut evaluated_layers = 0;

    // Look for conditional endorsement series in CoMID tags (layer-based TCB evolution tracking)
    for tag in &corim_map.tags {
        if let corim_rs::ConciseTagTypeChoice::Mid(comid_tag) = tag {
            let comid = &**comid_tag;

            // Check conditional endorsement series for measurement evolution tracking
            if let Some(ref conditional_series) =
                comid.triples.conditional_endorsement_series_triples
            {
                for (series_idx, series) in conditional_series.iter().enumerate() {
                    // Step 1: Track initial environment state from condition and get target certificate
                    let (layer_num, cert_index) = if let Some((layer_num, cert_index)) =
                        get_tcb_info_layer_and_cert_index(
                            &series.condition.environment,
                            x509_certs.len(),
                        )? {
                        evaluated_layers += 1;
                        (layer_num, cert_index)
                    } else {
                        tracing::warn!(
                            "Series #{} does not have valid TCBInfo environment",
                            series_idx
                        );
                        continue;
                    };

                    // Extract current DICE TCBInfo from the certificate (current state)
                    let cert = &x509_certs[cert_index];
                    match extract_dice_tcb_info(cert)? {
                        Some(dice_tcb_info) => {
                            // Evaluate series of allowed changes and verify at each step
                            let tcb_up_to_date = evaluate_conditional_endorsement_series(
                                &dice_tcb_info,
                                series,
                                layer_num,
                            )?;

                            if !tcb_up_to_date {
                                tracing::warn!(
                                    "Layer {} TCB is out of date according to conditional endorsement series",
                                    layer_num
                                );
                                all_layers_current = false;
                            }
                        }
                        None => {
                            tracing::error!(
                                "No DICE TCBInfo found in cert {} for layer {} Trust evaluation",
                                cert_index, layer_num
                            );
                            all_layers_current = false;
                        }
                    }
                }
            }
        }
    }

    // TODO: Check Trust CORIM validity period for endorsement decisions
    // The Trust CORIM must still be valid for endorsement decisions to be trusted
    // But we also don't have trusted time in Underhill

    tracing::debug!(
        "TCB up-to-date validation result: {} ({} layers evaluated)",
        all_layers_current,
        evaluated_layers
    );

    Ok(all_layers_current)
}

/// Evaluate conditional endorsement series for a specific layer
///
/// This function processes conditional endorsement series to determine TCB status by:
///
/// 1. **Initial condition match**: All initial claims must match against target environment measurements
/// 2. **Series condition match**: Each series has selection criteria and claims that get added when met.
///    The verifier goes through the series until a selection criteria applies, at which point it stops
///    and the corresponding series addition claims are attributed to the target environment
///
/// Returns `true` if TCB is up-to-date, `false` if out-of-date based on the first
/// matching condition in the conditional endorsement series
fn evaluate_conditional_endorsement_series(
    dice_tcb_info: &spdmcertchain::DiceTcbInfo,
    series: &corim_rs::ConditionalEndorsementSeriesTripleRecord<'_>,
    layer: u64,
) -> Result<bool, anyhow::Error> {
    let current_version = dice_tcb_info.version.as_deref().unwrap_or("unknown");
    let current_svn = dice_tcb_info.svn.unwrap_or(0);

    tracing::debug!(
        "Evaluating conditional endorsement series for layer {}: version='{}', SVN={}, {} evolution record(s)",
        layer, current_version, current_svn, series.series.len()
    );

    // Validate against condition environment (initial state check)
    if !series.condition.claims_list.is_empty() {
        for (claim_idx, claim) in series.condition.claims_list.iter().enumerate() {
            let context = format!("Condition #{}", claim_idx);
            if !validate_measurement_map_against_dice_tcb(claim, dice_tcb_info, &context)? {
                return Ok(false);
            }
        }
    }

    // Evaluate series of allowed measurement changes
    // The first series selection criteria that matches terminates series matching
    // and the endorsement values are added to the Attester's actual state
    for (_record_idx, record) in series.series.iter().enumerate() {
        let mut meets_all_selections = true;

        for (sel_idx, selection) in record.selection.iter().enumerate() {
            let context = format!("Selection #{}", sel_idx);
            if !validate_measurement_map_against_dice_tcb(selection, dice_tcb_info, &context)? {
                meets_all_selections = false;
                break;
            }
        }

        // If selection criteria are met, this is our first match - apply endorsements and terminate
        if meets_all_selections {
            // Expect exactly one measurement map in addition with TCB status
            if record.addition.len() != 1 {
                anyhow::bail!(
                    "Expected exactly 1 measurement map in addition, got {}",
                    record.addition.len()
                );
            }

            let addition = &record.addition[0];
            if let Some(ref tcb_status) = addition.mval.tcb_status {
                let status_str = tcb_status.as_ref();

                // Parse the TCB status string and return the appropriate boolean value
                let tcb_up_to_date = match status_str {
                    "UpToDate" => true,
                    "OutOfDate" => {
                        tracing::warn!(
                            "Layer {} TCB is out of date (version='{}', SVN={})",
                            layer, current_version, current_svn
                        );
                        false
                    }
                    other => {
                        anyhow::bail!(
                            "Unknown TCB status '{}' in conditional endorsement series",
                            other
                        );
                    }
                };

                return Ok(tcb_up_to_date);
            } else {
                anyhow::bail!("Addition measurement map missing required tcb_status field");
            }
        }
    }

    // No matching evolution record found
    tracing::error!(
        "No matching evolution record found for layer {} (version='{}', SVN={})",
        layer, current_version, current_svn
    );
    // No matching record means we can't endorse this TCB state as up-to-date
    Ok(false)
}

/// Validate measurements from SPDM measurements report against CORIM reference values and Trust CORIM endorsements
///
/// Apply all measurement reference value triples from the Authenticity CORIM to the measurements
/// Verify measurements against Trust CORIM conditional endorsement series
async fn validate_measurements(
    measurements_data: &[u8],
    corim_pair: &CorimPair<'_>,
) -> Result<(bool, bool), anyhow::Error> {
    // Parse the SPDM measurements response
    let measurements = parse_spdm_measurements_response(measurements_data)?;

    tracing::debug!(
        "Parsed {} measurement entries from SPDM response",
        measurements.len()
    );

    // Step 6a: Apply all measurement reference value triples from the Authenticity CORIM
    let authenticity_valid =
        validate_measurements_against_authenticity_corim(&measurements, &corim_pair.authenticity)?;

    if !authenticity_valid {
        tracing::error!(
            "Measurements validation failed against Authenticity CORIM reference values"
        );
        return Ok((false, false));
    }

    tracing::debug!("Measurements validation passed against Authenticity CORIM");

    // Step 6b: Verify measurements against Trust CORIM conditional endorsement series
    let measurements_up_to_date =
        validate_measurements_against_trust_corim(&measurements, &corim_pair.trust)?;

    if !measurements_up_to_date {
        tracing::warn!("Measurements are not up-to-date according to Trust CORIM endorsements");
        return Ok((true, false)); // Authentic but not up-to-date
    }

    tracing::debug!("Measurements are up-to-date according to Trust CORIM");

    Ok((true, true))
}

/// Parse SPDM measurements response into a structured format
///
/// The TSM returns measurements wrapped in a session capture that includes the complete
/// SPDM protocol exchange (version negotiation, capabilities, algorithms, and measurements).
/// We need to find the actual MEASUREMENTS response (0x12, 0x60) within this data.
///
/// Returns measurement records parsed from the SPDM response
fn parse_spdm_measurements_response(
    measurements_data: &[u8],
) -> Result<Vec<spdmmeasurements::MeasurementRecord>, anyhow::Error> {
    use crate::tdisp::spdmmeasurements::SpdmMeasurementResponseMessage;
    use std::convert::TryFrom;

    tracing::debug!(
        "Parsing SPDM measurements response: {} bytes",
        measurements_data.len()
    );

    // Search for the SPDM MEASUREMENTS response signature (0x12, 0x60)
    // 0x12 = SPDM version 1.2
    // 0x60 = MEASUREMENTS response code
    let mut measurements_offset = None;
    for i in 0..measurements_data.len().saturating_sub(1) {
        if measurements_data[i] == 0x12 && measurements_data[i + 1] == 0x60 {
            tracing::debug!(
                "Found SPDM MEASUREMENTS response signature at offset {}",
                i
            );
            measurements_offset = Some(i);
            break;
        }
    }

    let offset = measurements_offset.context(
        "Failed to find SPDM MEASUREMENTS response signature (0x12, 0x60) in data"
    )?;

    // Parse the SPDM measurement response from the found offset
    let spdm_meas_data = &measurements_data[offset..];
    let spdm_response = SpdmMeasurementResponseMessage::try_from(spdm_meas_data)
        .context("Failed to parse SPDM measurements response")?;

    tracing::debug!(
        "Parsed SPDM measurements response: version=0x{:02x}, response_code=0x{:02x}, {} records (offset: {})",
        spdm_response.spdm_version,
        spdm_response.request_response_code,
        spdm_response.measurement_records.len(),
        offset
    );
    Ok(spdm_response.measurement_records)
}

fn is_spdm_measurements_record(env: &corim_rs::EnvironmentMap<'_>) -> Result<bool, anyhow::Error> {
    if let Some(ref instance) = env.instance {
        // Check if environment instance contains "SPDMMeasurement" in base64
        let is_spdm_measurement = match instance {
            corim_rs::InstanceIdTypeChoice::Bytes(tagged_bytes) => {
                let bytes: &[u8] = tagged_bytes.as_ref().as_ref();

                // Try to decode as base64 and check if it contains "SPDMMeasurement"
                match base64::engine::general_purpose::STANDARD.decode(bytes) {
                    Ok(decoded) => {
                        let decoded_str = String::from_utf8_lossy(&decoded);
                        decoded_str.contains("SPDMMeasurement")
                    }
                    Err(_) => {
                        // If not valid base64, check raw bytes
                        let raw_str = String::from_utf8_lossy(bytes);
                        raw_str.contains("SPDMMeasurement")
                    }
                }
            }
            _ => false,
        };
        Ok(is_spdm_measurement)
    } else {
        Ok(false)
    }
}

/// Validate measurements against Authenticity CORIM reference value triples
///
/// Looks for reference triples with environment instance containing "SPDMMeasurement" in base64.
///
fn validate_measurements_against_authenticity_corim(
    measurements: &[spdmmeasurements::MeasurementRecord],
    authenticity_corim: &Corim<'_>,
) -> Result<bool, anyhow::Error> {
    // Extract CorimMap from the Corim enum
    let corim_map: &corim_rs::CorimMap<'_> = match authenticity_corim {
        corim_rs::ConciseRimTypeChoice::Unsigned(tagged) => tagged,
        corim_rs::ConciseRimTypeChoice::Signed(signed) => &signed.corim_map,
    };

    let mut total_measurement_triples = 0;

    tracing::debug!("Validating measurements against Authenticity CORIM reference triples");

    // Process all reference triples looking for SPDM measurements entries
    for tag in &corim_map.tags {
        if let corim_rs::ConciseTagTypeChoice::Mid(comid_tag) = tag {
            let comid = &**comid_tag;

            if let Some(ref reference_triples) = comid.triples.reference_triples {
                for triple in reference_triples {
                    // Check if this is an SPDM measurements reference triple by examining environment instance
                    let is_spdm_measurement = is_spdm_measurements_record(&triple.ref_env)?;
                    if is_spdm_measurement {
                        total_measurement_triples += 1;
                        tracing::debug!("Validating SPDM measurements against reference claims");
                        if validate_spdm_measurements_against_reference_claims(
                            measurements,
                            triple,
                        )? {
                            tracing::info!("SPDM measurements validation passed - reference triple matched entirely");
                            return Ok(true);
                        } else {
                            tracing::error!("Reference triple did not match SPDM measurements");
                        }
                    }
                }
            }
        }
    }

    tracing::debug!(
        "SPDM measurements validation: 0/{} measurement triples matched",
        total_measurement_triples
    );

    // No matching reference triple found
    // If no measurement triples exist, consider valid (device may not have measurements)
    Ok(total_measurement_triples == 0)
}

/// Validate SPDM measurements against reference claims in a triple
///
/// Each reference triple contains Vec<MeasurementMap> - only ONE claim needs to match entirely
/// Uses mkey of type UInt as specified in the documentation
fn validate_spdm_measurements_against_reference_claims(
    measurements: &[spdmmeasurements::MeasurementRecord],
    reference_triple: &corim_rs::ReferenceTripleRecord<'_>,
) -> Result<bool, anyhow::Error> {
    let mut validated_claims = 0;

    // Try to match each reference claim - all addressable claims must match
    for (claim_idx, claim) in reference_triple.ref_claims.iter().enumerate() {
        // Check if this claim has an mkey (measurement key identifier)
        if let Some(ref mkey) = claim.mkey {
            // Extract UInt value from mkey as per documentation
            if let corim_rs::MeasuredElementTypeChoice::UInt(uint_key) = mkey {
                let key_value = uint_key.0 as u8;

                // Find matching measurement by index
                if let Some(measurement_record) =
                    measurements.iter().find(|record| record.index == key_value)
                {
                    if !validate_single_measurement_against_claim(
                        &measurement_record.measurement,
                        claim,
                    )? {
                        tracing::error!("Measurement claim #{} (key={}) did not match", claim_idx, key_value);
                        return Ok(false);
                    }
                    validated_claims += 1;
                } else {
                    tracing::error!("No measurement found with index {}", key_value);
                    return Ok(false);
                }
            } else {
                tracing::error!(
                    "Measurement claim #{} has non-UInt mkey type — failing attestation (fail-closed)",
                    claim_idx
                );
                return Ok(false);
            }
        } else {
            tracing::error!("Measurement claim #{} has no mkey — failing attestation (fail-closed)", claim_idx);
            return Ok(false);
        }
    }

    // Guard against vacuous success — at least one claim must have been validated
    if validated_claims == 0 {
        tracing::error!("No measurement claims were validated — reference triple has no addressable claims");
        return Ok(false);
    }

    // Warn if the reference triple has fewer claims than the number of SPDM measurement blocks,
    // meaning some device measurements are not covered by reference values.
    if reference_triple.ref_claims.len() < measurements.len() {
        tracing::warn!(
            "Reference triple has {} claim(s) but SPDM response has {} measurement block(s) - {} measurement(s) are not covered by reference values",
            reference_triple.ref_claims.len(),
            measurements.len(),
            measurements.len() - reference_triple.ref_claims.len()
        );
    }

    tracing::debug!("Measurement reference triple matched entirely ({} claims validated)", validated_claims);
    Ok(true)
}

/// Validate a single measurement against a measurement claim
fn validate_single_measurement_against_claim(
    measurement: &spdmmeasurements::DmtfMeasurement,
    claim: &corim_rs::MeasurementMap<'_>,
) -> Result<bool, anyhow::Error> {
    // Warn about unsupported fields in SPDM measurement claims (non-fatal)
    // Unlike DICE TCBInfo which fails closed, SPDM measurements log warnings
    // for unsupported fields and evaluate only the supported ones.
    let mut unsupported_fields = Vec::new();
    if claim.mval.version.is_some() {
        unsupported_fields.push("version");
    }
    if claim.mval.integrity_registers.is_some() {
        unsupported_fields.push("integrity_registers");
    }
    if claim.mval.flags.is_some() {
        unsupported_fields.push("flags");
    }
    if claim.mval.mac_addr.is_some() {
        unsupported_fields.push("mac_addr");
    }
    if claim.mval.ip_addr.is_some() {
        unsupported_fields.push("ip_addr");
    }
    if claim.mval.serial_number.is_some() {
        unsupported_fields.push("serial_number");
    }
    if claim.mval.ueid.is_some() {
        unsupported_fields.push("ueid");
    }
    if claim.mval.uuid.is_some() {
        unsupported_fields.push("uuid");
    }
    if claim.mval.name.is_some() {
        unsupported_fields.push("name");
    }
    if claim.mval.cryptokeys.is_some() {
        unsupported_fields.push("cryptokeys");
    }
    if claim.mval.tcb_status.is_some() {
        unsupported_fields.push("tcb_status");
    }
    if claim.mval.tcb_date.is_some() {
        unsupported_fields.push("tcb_date");
    }
    if claim.mval.tcb_status_details.is_some() {
        unsupported_fields.push("tcb_status_details");
    }
    if claim.mval.extensions.is_some() {
        unsupported_fields.push("extensions");
    }
    if !unsupported_fields.is_empty() {
        tracing::warn!(
            "SPDM measurement claim contains unsupported fields: [{}]. Only 'digests', 'raw', and 'svn' are evaluated.",
            unsupported_fields.join(", ")
        );
    }

    // Each SPDM measurement claim must populate exactly one supported field.
    // Having multiple fields set (e.g., both digests and raw-value) is invalid.
    let supported_field_count = claim.mval.digests.is_some() as u8
        + claim.mval.raw.is_some() as u8
        + claim.mval.svn.is_some() as u8;

    if supported_field_count > 1 {
        tracing::warn!(
            "SPDM measurement claim has {} supported fields set (expected exactly 1). \
             Fields: digests={}, raw={}, svn={}. All set fields will be evaluated.",
            supported_field_count,
            claim.mval.digests.is_some(),
            claim.mval.raw.is_some(),
            claim.mval.svn.is_some(),
        );
    }

    // Evaluate supported mval fields in priority order: digests → raw-value → svn.
    // The first field that is set determines the validation result.
    // CORIM authors should ensure only a single mval field is populated per claim.

    // Check digests if present in reference claim
    if let Some(ref digests) = claim.mval.digests {
        // Check if the measurement value matches any reference digest
        for reference_digest in digests {
            let reference_bytes: &[u8] = reference_digest.val.as_ref();

            if &measurement.value == reference_bytes {
                return Ok(true);
            }
        }

        tracing::error!("Measurement value does not match any reference digests");
        return Ok(false);
    }

    // Check raw value if present in reference claim
    if let Some(ref raw_claim) = claim.mval.raw {
        if let Some(raw_bytes) = raw_claim.raw_value.as_bytes() {
            if measurement.value == raw_bytes {
                return Ok(true);
            } else {
                tracing::error!("Raw value mismatch");
                return Ok(false);
            }
        } else {
            tracing::warn!("Reference raw value is not in bytes format");
            return Ok(false);
        }
    }

    // Check SVN if present in reference claim
    // SPDM measurement blocks with MeasurementType::FirmwareSecurityVersionNumber (0x07)
    // carry the SVN as an 8-byte little-endian unsigned integer in RawBitStream representation.
    if let Some(ref svn_claim) = claim.mval.svn {
        // The device measurement value should be an 8-byte LE unsigned integer
        if measurement.value.len() != 8 {
            tracing::error!(
                "SVN measurement block has unexpected size: {} bytes (expected 8)",
                measurement.value.len()
            );
            return Ok(false);
        }

        let device_svn = u64::from_le_bytes(
            measurement.value[..8]
                .try_into()
                .expect("checked length above"),
        );

        let (_reference_svn, svn_valid) =
            validate_svn_claim(svn_claim, Some(device_svn), "SPDM measurement SVN");

        return Ok(svn_valid);
    }

    // No supported field was set
    tracing::warn!("Reference claim has no supported validation fields (digests, raw, or svn)");
    Ok(false)
}

/// Validate measurements against Trust CORIM conditional endorsement series
///
/// Similar to TCBInfo validation but for measurements evolution tracking
fn validate_measurements_against_trust_corim(
    measurements: &[spdmmeasurements::MeasurementRecord],
    trust_corim: &Corim<'_>,
) -> Result<bool, anyhow::Error> {
    // Extract CorimMap from the Trust CORIM
    let corim_map: &corim_rs::CorimMap<'_> = match trust_corim {
        corim_rs::ConciseRimTypeChoice::Unsigned(tagged) => tagged,
        corim_rs::ConciseRimTypeChoice::Signed(signed) => &signed.corim_map,
    };

    let mut measurement_series_count = 0;

    tracing::debug!(
        "Validating measurements against Trust CORIM conditional endorsement series"
    );

    // Look for conditional endorsement series related to measurements
    // Design intent: there should be exactly one CES triple for the measurement environment.
    // Unlike TCBInfo (one CES per DICE layer), measurements have a single holistic trust posture.
    for tag in &corim_map.tags {
        if let corim_rs::ConciseTagTypeChoice::Mid(comid_tag) = tag {
            let comid = &**comid_tag;

            // Check conditional endorsement series for measurements evolution tracking
            if let Some(ref conditional_series) =
                comid.triples.conditional_endorsement_series_triples
            {
                for (series_idx, series) in conditional_series.iter().enumerate() {
                    // Check if this series is for measurements (not TCBInfo)
                    let is_measurement_series =
                        is_spdm_measurements_record(&series.condition.environment)?;

                    if is_measurement_series {
                        measurement_series_count += 1;

                        if measurement_series_count > 1 {
                            tracing::warn!(
                                "Multiple measurement CES triples found (series #{}).",
                                series_idx
                            );
                        }

                        tracing::debug!(
                            "Processing measurements conditional endorsement series #{}",
                            series_idx
                        );

                        // Evaluate measurements against conditional endorsement series
                        let measurements_up_to_date =
                            evaluate_measurements_conditional_endorsement_series(
                                measurements,
                                series,
                            )?;

                        if measurements_up_to_date {
                            tracing::debug!(
                                "Measurements are up to date according to conditional endorsement series"
                            );
                            return Ok(true);
                        } else {
                            tracing::warn!(
                                "Measurements series #{} did not confirm up-to-date — continuing to check remaining series",
                                series_idx
                            );
                        }
                    }
                }
            }
        }
    }

    tracing::debug!(
        "Measurements up-to-date validation result: no series confirmed up-to-date ({} measurement series evaluated)",
        measurement_series_count
    );

    // If we found measurement series but none returned up-to-date, fail.
    // If no measurement series exist, consider valid (vacuous truth).
    Ok(measurement_series_count == 0)
}

/// Evaluate conditional endorsement series for measurements
///
/// Similar to TCBInfo evaluation but for measurements evolution tracking.
/// This function processes conditional endorsement series to determine measurement status by:
///
/// 1. **Initial condition match**: All initial claims must match against current measurements
/// 2. **Series condition match**: Each series has selection criteria and claims that get added when met.
///    The verifier goes through the series until a selection criteria applies, at which point it stops
///    and the corresponding series addition claims are attributed to the current measurements
///
/// Returns `true` if measurements are up-to-date, `false` if out-of-date based on the first
/// matching condition in the conditional endorsement series
fn evaluate_measurements_conditional_endorsement_series(
    measurements: &[spdmmeasurements::MeasurementRecord],
    series: &corim_rs::ConditionalEndorsementSeriesTripleRecord<'_>,
) -> Result<bool, anyhow::Error> {

    if measurements.is_empty() {
        tracing::error!("No measurements available but Trust CORIM contains measurement evolution series — failing attestation");
        return Ok(false);
    }

    tracing::debug!(
        "Evaluating measurements conditional endorsement series: {} measurement(s), {} evolution record(s)",
        measurements.len(),
        series.series.len()
    );

    // Validate against condition environment (initial state check)
    if !series.condition.claims_list.is_empty() {
        for (claim_idx, claim) in series.condition.claims_list.iter().enumerate() {
            let context = format!("Measurements condition #{}", claim_idx);
            if !validate_measurements_against_single_claim(measurements, claim, &context)? {
                tracing::error!(
                    "Measurements condition #{} not satisfied",
                    claim_idx
                );
                return Ok(false);
            }
        }
    }

    // Evaluate series of allowed measurement changes
    // The first series selection criteria that matches terminates series matching
    for (_record_idx, record) in series.series.iter().enumerate() {
        let mut meets_all_selections = true;

        for (sel_idx, selection) in record.selection.iter().enumerate() {
            let context = format!("Measurements selection #{}", sel_idx);
            if !validate_measurements_against_single_claim(measurements, selection, &context)? {
                meets_all_selections = false;
                break;
            }
        }

        // If selection criteria are met, this is our first match - apply endorsements and terminate
        if meets_all_selections {
            // Expect exactly one measurement map in addition with TCB status
            if record.addition.len() != 1 {
                anyhow::bail!(
                    "Expected exactly 1 measurement map in addition, got {}",
                    record.addition.len()
                );
            }

            let addition = &record.addition[0];
            if let Some(ref tcb_status) = addition.mval.tcb_status {
                let status_str = tcb_status.as_ref();

                // Parse the TCB status string and return the appropriate boolean value
                let tcb_up_to_date = match status_str {
                    "UpToDate" => true,
                    "OutOfDate" => {
                        tracing::warn!(
                            "Measurements are out of date according to conditional endorsement series"
                        );
                        false
                    }
                    other => {
                        anyhow::bail!(
                            "Unknown TCB status '{}' in measurements conditional endorsement series",
                            other
                        );
                    }
                };

                return Ok(tcb_up_to_date);
            } else {
                anyhow::bail!("Addition measurement map missing required tcb_status field");
            }
        }
    }

    // No matching evolution record found for measurements
    tracing::error!("No matching measurements evolution record found");
    Ok(false)
}

/// Helper function to validate measurements against a single measurement claim
///
/// This function reuses the logic from validate_spdm_measurements_against_reference_claims
/// but for a single claim instead of a list of claims
fn validate_measurements_against_single_claim(
    measurements: &[spdmmeasurements::MeasurementRecord],
    claim: &corim_rs::MeasurementMap<'_>,
    context: &str,
) -> Result<bool, anyhow::Error> {
    tracing::debug!(
        "{}: Validating measurements against single claim",
        context
    );

    // Check if this claim has an mkey (measurement key identifier)
    if let Some(ref mkey) = claim.mkey {
        // Extract UInt value from mkey as per documentation
        if let corim_rs::MeasuredElementTypeChoice::UInt(uint_key) = mkey {
            let key_value = uint_key.0 as u8;

            // Find matching measurement by index
            if let Some(measurement_record) =
                measurements.iter().find(|record| record.index == key_value)
            {
                // Validate the specific measurement against the claim
                if validate_single_measurement_against_claim(
                    &measurement_record.measurement,
                    claim,
                )? {
                    return Ok(true);
                } else {
                    tracing::error!("{}: measurement claim did not match for key {}", context, key_value);
                    return Ok(false);
                }
            } else {
                tracing::error!(
                    "{}: no measurement found with index {}",
                    context, key_value
                );
                return Ok(false);
            }
        } else {
            tracing::warn!(
                "{}: measurement claim has non-UInt mkey type",
                context
            );
            return Ok(false);
        }
    } else {
        tracing::warn!("{}: measurement claim has no mkey", context);
        return Ok(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a pair of minimal test CORIMs for testing purposes
    ///
    /// Creates both authenticity and trust CORIMs:
    /// - Authenticity CORIM: Contains identity triple with root certificate thumbprint
    /// - Trust CORIM: Contains only reference triples (no identity)
    /// - ManifestCreator role
    /// - Minimal reference triples for structure compliance
    /// - Unsigned CORIM type
    ///
    /// Returns (authenticity_corim, trust_corim) tuple
    fn create_test_corim_pair<'a>() -> Result<(Corim<'a>, Corim<'a>), anyhow::Error> {
        use corim_rs::{
            CertThumbprintType, ConciseMidTagBuilder, CorimEntityMapBuilder, CorimMapBuilder,
            CorimRoleTypeChoice, CryptoKeyTypeChoice, Digest, EnvironmentMap, HashAlgorithm,
            IdentityTripleRecord, MeasurementMap, ReferenceTripleRecord, TagIdentityMap,
            TriplesMapBuilder,
        };

        // Static string constants to avoid lifetime issues
        #[allow(dead_code)]
        const CORIM_ID_BASE: &str = "test-corim";
        const ENTITY_NAME: &str = "Test Entity";

        // Get the root certificate thumbprint from the mock certificate chain
        let root_thumbprint = [
            0x6c, 0xf4, 0xd3, 0x06, 0xf1, 0x4f, 0x7e, 0xa5, 0xe0, 0x73, 0x10, 0xed, 0x88, 0xdb, 0xb7,
            0x9c, 0xab, 0x9c, 0xe4, 0x2d, 0x7f, 0x4a, 0x4a, 0x19, 0x36, 0xcd, 0x18, 0x41, 0x97, 0x08,
            0xb7, 0x03, 0x96, 0xfd, 0x69, 0xab, 0x41, 0x16, 0xd6, 0x96, 0xdb, 0xa7, 0xd8, 0x4c, 0xfa,
            0x7b, 0xa0, 0x32,
        ];

        // Create identity triple with certificate thumbprint for authenticity CORIM
        let cert_thumbprint = CertThumbprintType(ciborium::tag::Accepted(Digest {
            alg: HashAlgorithm::Sha384,
            val: corim_rs::Bytes::from(root_thumbprint.as_slice()),
        }));

        let identity_triple = IdentityTripleRecord {
            environment: EnvironmentMap {
                class: None,
                instance: Some(corim_rs::InstanceIdTypeChoice::Bytes(
                    corim_rs::TaggedBytes::from(b"SPDM_certificate".as_slice()),
                )),
                group: None,
            },
            key_list: vec![CryptoKeyTypeChoice::CertThumbprint(cert_thumbprint)],
            conditions: None,
        };

        // Create minimal reference triple for both CORIMs
        let reference_triple = ReferenceTripleRecord {
            ref_env: EnvironmentMap {
                class: None,
                instance: None,
                group: None,
            },
            ref_claims: vec![MeasurementMap {
                mkey: None,
                mval: corim_rs::MeasurementValuesMapBuilder::new()
                    .digest(vec![Digest {
                        alg: corim_rs::HashAlgorithm::Sha256,
                        val: corim_rs::Bytes::from([0u8; 32].as_slice()),
                    }])
                    .build()
                    .context("Failed to build minimal measurement values")?,
                authorized_by: None,
            }],
        };

        // Create authenticity CoMID tag with identity triple and reference triple
        let authenticity_comid_tag = ConciseMidTagBuilder::new()
            .tag_identity(TagIdentityMap {
                tag_id: "authenticity-tag".into(),
                tag_version: Some(1.into()),
            })
            .triples(
                TriplesMapBuilder::new()
                    .identity_triples(vec![identity_triple])
                    .reference_triples(vec![reference_triple.clone()])
                    .build()
                    .context("Failed to build authenticity triples map")?,
            )
            .build()
            .context("Failed to build authenticity CoMID tag")?;

        // Create trust CoMID tag with only reference triple (no identity triple)
        let trust_comid_tag = ConciseMidTagBuilder::new()
            .tag_identity(TagIdentityMap {
                tag_id: "trust-tag".into(),
                tag_version: Some(1.into()),
            })
            .triples(
                TriplesMapBuilder::new()
                    .reference_triples(vec![reference_triple])
                    .build()
                    .context("Failed to build trust triples map")?,
            )
            .build()
            .context("Failed to build trust CoMID tag")?;

        // Create authenticity CORIM with identity triple
        let authenticity_corim_map = CorimMapBuilder::new()
            .id("test-corim-authenticity".into())
            .add_entity(
                CorimEntityMapBuilder::new()
                    .entity_name(ENTITY_NAME.into())
                    .add_role(CorimRoleTypeChoice::ManifestCreator)
                    .build()
                    .context("Failed to build authenticity entity")?,
            )
            .add_tag(authenticity_comid_tag.into())
            .build()
            .context("Failed to build authenticity CORIM map")?;

        // Create trust CORIM without identity triple
        let trust_corim_map = CorimMapBuilder::new()
            .id("test-corim-trust".into())
            .add_entity(
                CorimEntityMapBuilder::new()
                    .entity_name(ENTITY_NAME.into())
                    .add_role(CorimRoleTypeChoice::ManifestCreator)
                    .build()
                    .context("Failed to build trust entity")?,
            )
            .add_tag(trust_comid_tag.into())
            .build()
            .context("Failed to build trust CORIM map")?;

        // Create CORIMs (unsigned)
        let authenticity_corim =
            corim_rs::ConciseRimTypeChoice::Unsigned(authenticity_corim_map.into());
        let trust_corim = corim_rs::ConciseRimTypeChoice::Unsigned(trust_corim_map.into());

        Ok((authenticity_corim, trust_corim))
    }
    use futures_executor::block_on;

    /// Helper function to parse CORIM from CBOR data (for testing only)  
    fn parse_corim_from_cbor(cbor_data: &[u8]) -> Result<Corim<'_>, String> {
        use coset::{CoseSign1, TaggedCborSerializable};

        // First try to parse as COSE-wrapped CoRIM (signed)
        match CoseSign1::from_tagged_slice(cbor_data) {
            Ok(cose_sign1) => {
                if let Some(payload) = &cose_sign1.payload {
                    // Parse the inner CorimMap from COSE payload
                    let corim_map: corim_rs::CorimMap<'_> =
                        ciborium::de::from_reader(payload.as_slice()).map_err(|e| {
                            format!("Failed to parse COSE payload as CorimMap: {}", e)
                        })?;
                    // Wrap in the Unsigned variant since it's extracted from COSE
                    Ok(corim_rs::ConciseRimTypeChoice::Unsigned(corim_map.into()))
                } else {
                    Err("COSE structure missing payload".to_string())
                }
            }
            Err(_) => {
                // If COSE parsing fails, try as unsigned CBOR CoRIM
                let corim_map: corim_rs::CorimMap<'_> = ciborium::de::from_reader(cbor_data)
                    .map_err(|e| format!("Failed to parse unsigned CBOR as CorimMap: {}", e))?;
                Ok(corim_rs::ConciseRimTypeChoice::Unsigned(corim_map.into()))
            }
        }
    }

    #[test]
    fn test_tcb_and_cert_chain_validation_with_generated_certs() {
        use crate::tdisp::cert_generator::generate_test_certificate_chain;
        use crate::tdisp::spdmcertchain::extract_dice_tcb_info;
        use spdmcertchain::deserialize_spdm_certificate_response;

        // Generate test certificates using our new generator that matches Microsoft structure
        let test_certificates =
            generate_test_certificate_chain().expect("Failed to generate test certificate chain");

        assert_eq!(
            test_certificates.len(),
            2,
            "Should have Layer 0 and Layer 1 certificates"
        );

        // Get DER-encoded certificates
        // test_certificates[0] = Layer 0, test_certificates[1] = Layer 1
        // SPDM chain is leaf-first, so: cert[0]=Layer1(leaf), cert[1]=Layer0(intermediate)
        let layer0_cert_data = test_certificates[0]
            .to_der()
            .expect("Failed to convert Layer 0 to DER");
        let layer1_cert_data = test_certificates[1]
            .to_der()
            .expect("Failed to convert Layer 1 to DER");
        let leaf_cert_data = &layer1_cert_data;  // Layer 1 is leaf (cert[0] in SPDM)
        let intermediate_cert_data = &layer0_cert_data;  // Layer 0 is intermediate (cert[1] in SPDM)
        use openssl::hash::{MessageDigest, hash};
        let root_thumbprint = hash(MessageDigest::sha384(), &layer0_cert_data)
            .expect("Failed to hash root thumbprint");

        // Create SPDM certificate response message with our test certificates
        let mut spdm_response = Vec::new();

        // SPDM GET_CERTIFICATE response header (8 bytes total)
        spdm_response.push(0x12); // SPDM version 1.2
        spdm_response.push(0x02); // Request/Response code for GET_CERTIFICATE response 
        spdm_response.push(0x00); // Param1: Slot ID 0 (bits 3:0), Reserved (bits 7:4)
        spdm_response.push(0x00); // Param2: Reserved

        // Calculate total certificate chain length including chain header (4 + hash_size + certs)
        let hash_size = 48; // SHA-384 hash size
        let cert_chain_header_size = 4; // CertificateChainHeaderSerialized
        let total_cert_chain_length = cert_chain_header_size
            + hash_size
            + leaf_cert_data.len()
            + intermediate_cert_data.len();

        // Portion length (2 bytes, little endian) - size of certificate chain data in this response
        let portion_length = total_cert_chain_length as u16;
        spdm_response.extend_from_slice(&portion_length.to_le_bytes());

        // Remainder length (2 bytes, little endian) - 0 since complete chain in one response
        spdm_response.extend_from_slice(&0u16.to_le_bytes());

        // Certificate chain header (4 bytes)
        let cert_chain_total_length = total_cert_chain_length as u16;
        spdm_response.extend_from_slice(&cert_chain_total_length.to_le_bytes()); // Total length
        spdm_response.extend_from_slice(&0u16.to_le_bytes()); // Reserved

        // Root certificate hash (SHA-384, 48 bytes) - using zeros for test
        spdm_response.extend_from_slice(&vec![0u8; hash_size]);

        // Add certificates - validation expects: cert[n-2]=Layer0, cert[n-1]=Layer1
        // With 2 certs: cert[0]=Layer0(intermediate), cert[1]=Layer1(leaf)
        spdm_response.extend_from_slice(&intermediate_cert_data);
        spdm_response.extend_from_slice(&leaf_cert_data);

        // Parse the SPDM response
        let parsed_response = deserialize_spdm_certificate_response(&spdm_response)
            .expect("Failed to parse SPDM certificate response");

        // Generate Microsoft-compatible CORIM for both authenticity and trust validation
        let corim_cbor_data = corim_generator::generate_microsoft_corim(Some(&root_thumbprint))
            .expect("Failed to generate Microsoft CORIM");

        let authenticity_corim = parse_corim_from_cbor(&corim_cbor_data)
            .expect("Failed to parse authenticity CORIM from CBOR data");
        let trust_corim = parse_corim_from_cbor(&corim_cbor_data)
            .expect("Failed to parse trust CORIM from CBOR data");

        let cert_chain_validate = block_on(validate_certificate_chain(
            &parsed_response.certificate_chain,
            &authenticity_corim,
        ));

        match cert_chain_validate {
            Ok(true) => {
                println!("valid cert chain");
            }
            Ok(false) => {
                println!("Not a valid cert chain");
            }
            Err(e) => {
                println!("Got an error {}", e);
            }
        };

        // Test Steps 4c and 4d: Validate TCBInfo against CORIMs
        // Parse X.509 certificates from certificate chain
        let x509_certs = parsed_response
            .certificate_chain
            .parse_x509_certificates()
            .expect("Failed to parse X.509 certificates for TCBInfo validation");

        let tcb_validation_result =
            validate_tcb_against_authenticity_corim(&x509_certs, &authenticity_corim);

        match tcb_validation_result {
            Ok(true) => {
                println!("✓ Step 4c: TCBInfo validation against authenticity CORIM PASSED");

                // Test trust CORIM validation (Step 4d)
                let trust_validation_result =
                    validate_tcb_against_trust_corim(&x509_certs, &trust_corim);

                match trust_validation_result {
                    Ok(true) => {
                        println!("✓ Step 4d: TCBInfo validation against trust CORIM PASSED");
                        println!("✓ Complete TDISP Steps 4c-4d validation SUCCESSFUL");
                    }
                    Ok(false) => {
                        panic!("Step 4d: TCBInfo validation against trust CORIM FAILED");
                    }
                    Err(e) => {
                        panic!("Step 4d: Error during trust CORIM validation: {}", e);
                    }
                }
            }
            Ok(false) => {
                println!(
                    "[ERROR] Step 4c: TCBInfo validation against authenticity CORIM returned false"
                );

                // Let's debug what's in our certificates vs what's in the CORIM
                for (i, cert) in x509_certs.iter().enumerate() {
                    if let Ok(Some(dice_info)) = extract_dice_tcb_info(cert) {
                        println!(
                            "[DEBUG] Cert {} DICE info - Vendor: {:?}, Layer: {:?}",
                            i, dice_info.vendor, dice_info.layer
                        );
                        println!("[DEBUG] Cert {} FWID count: {}", i, dice_info.fwids.len());
                        for (j, fwid) in dice_info.fwids.iter().enumerate() {
                            println!(
                                "[DEBUG] Cert {} FWID {}: alg={}, digest={}",
                                i,
                                j,
                                fwid.hash_alg,
                                hex::encode(&fwid.digest)
                            );
                        }
                    }
                }

                panic!("Step 4c: TCBInfo validation against authenticity CORIM FAILED");
            }
            Err(e) => {
                panic!("Step 4c: Error during authenticity CORIM validation: {}", e);
            }
        }
    }

    #[test]
    fn test_spdm_measurements_validation_against_authenticity_corim() {
        use crate::tdisp::corim_generator::{TEST_SPDM_MEASUREMENT_1, TEST_SPDM_MEASUREMENT_2};

        println!(
            "[TEST] Testing Steps 5 & 6: SPDM measurements validation with authenticity CORIM"
        );

        // Generate the test authenticity CORIM that includes SPDM measurements
        let corim_cbor_data = corim_generator::generate_microsoft_corim(None)
            .expect("Failed to generate Microsoft CORIM with SPDM measurements");

        // Parse the authenticity CORIM
        let authenticity_corim = parse_corim_from_cbor(&corim_cbor_data)
            .expect("Failed to parse authenticity CORIM from CBOR data");

        // Create test SPDM measurements that match the CORIM reference values
        let measurements = vec![
            spdmmeasurements::MeasurementRecord {
                index: 1,
                measurement: spdmmeasurements::DmtfMeasurement {
                    value_type: spdmmeasurements::DmtfMeasurementValueType {
                        representation: spdmmeasurements::MeasurementRepresentation::Digest,
                        measurement_type: spdmmeasurements::MeasurementType::MutableFirmware,
                    },
                    value_size: TEST_SPDM_MEASUREMENT_1.len() as u16,
                    value: TEST_SPDM_MEASUREMENT_1.to_vec(),
                },
            },
            spdmmeasurements::MeasurementRecord {
                index: 2,
                measurement: spdmmeasurements::DmtfMeasurement {
                    value_type: spdmmeasurements::DmtfMeasurementValueType {
                        representation: spdmmeasurements::MeasurementRepresentation::Digest,
                        measurement_type: spdmmeasurements::MeasurementType::MutableFirmware,
                    },
                    value_size: TEST_SPDM_MEASUREMENT_2.len() as u16,
                    value: TEST_SPDM_MEASUREMENT_2.to_vec(),
                },
            },
        ];

        // Test measurements validation against authenticity CORIM
        let validation_result =
            validate_measurements_against_authenticity_corim(&measurements, &authenticity_corim);
        assert!(
            validation_result.is_ok(),
            "Measurements validation should succeed"
        );

        let is_authentic = validation_result.unwrap();
        assert!(
            is_authentic,
            "Measurements should be considered authentic against CORIM reference values"
        );

        println!("[SUCCESS] Steps 5 & 6 measurements validation completed successfully");
        println!("[INFO] Test measurements: {} entries", measurements.len());
        println!(
            "[DEBUG] Measurement 1 digest: {}",
            hex::encode(&TEST_SPDM_MEASUREMENT_1)
        );
        println!(
            "[DEBUG] Measurement 2 digest: {}",
            hex::encode(&TEST_SPDM_MEASUREMENT_2)
        );
        println!("[SUCCESS] Authenticity validation: {}", is_authentic);
    }
    /// Test that Manticore negative test cases generate valid CORIMs
    /// and can be loaded by the verifier infrastructure.
    ///
    /// For each negative test case, the generated CORIMs should:
    /// - Be valid CBOR that can be parsed as CorimMap
    /// - Be loadable into TdispVerifier
    /// - Produce the expected attestation result when evaluated
    ///
    /// Auth negative cases (BadSpdmMeasurement, BadTcbInfoLayer0/1, BadRootCertThumbprint)
    ///   -> should cause authentic=false
    /// Trust negative cases (BadTrustTcbInfoLayer0/1)
    ///   -> should cause tcb_up_to_date=false (authentic remains true)
    #[test]
    fn test_manticore_negative_test_cases_load_into_verifier() {
        use crate::tdisp::corim_generator::{
            NegativeTestCase, generate_tdisp_device_rims_json,
            MANTICORE_VENDOR_ID, MANTICORE_DEVICE_ID,
        };
        use base64::Engine;

        for test_case in NegativeTestCase::all() {
            let json_str = generate_tdisp_device_rims_json(*test_case)
                .unwrap_or_else(|e| panic!("Failed to generate JSON for {:?}: {}", test_case, e));

            // Parse JSON to extract base64 CORIMs
            let parsed: serde_json::Value = serde_json::from_str(&json_str)
                .unwrap_or_else(|e| panic!("Invalid JSON for {:?}: {}", test_case, e));
            let auth_b64 = parsed["devices"][0]["auth_rim"].as_str().unwrap();
            let trust_b64 = parsed["devices"][0]["trust_rim"].as_str().unwrap();

            // Decode base64 -> CBOR bytes
            let auth_bytes = base64::engine::general_purpose::STANDARD
                .decode(auth_b64)
                .unwrap_or_else(|e| panic!("Bad auth base64 for {:?}: {}", test_case, e));
            let trust_bytes = base64::engine::general_purpose::STANDARD
                .decode(trust_b64)
                .unwrap_or_else(|e| panic!("Bad trust base64 for {:?}: {}", test_case, e));

            // Parse as CORIMs
            let auth_corim = parse_corim_from_cbor(&auth_bytes)
                .unwrap_or_else(|e| panic!("Failed to parse auth CORIM for {:?}: {}", test_case, e));
            let trust_corim = parse_corim_from_cbor(&trust_bytes)
                .unwrap_or_else(|e| panic!("Failed to parse trust CORIM for {:?}: {}", test_case, e));

            // Load into verifier
            let mut verifier = TdispVerifier::new();
            verifier.add_corim_pair(
                MANTICORE_VENDOR_ID as u16,
                MANTICORE_DEVICE_ID as u16,
                auth_corim,
                trust_corim,
            );

            assert!(
                verifier.has_corims(MANTICORE_VENDOR_ID as u16, MANTICORE_DEVICE_ID as u16),
                "Verifier should have CORIMs for test case {:?}", test_case
            );

            println!("  {:30} loaded into verifier OK ({})",
                test_case.label(), test_case.description());
        }
    }

    /// Test SPDM measurement validation with Manticore negative test cases.
    ///
    /// Uses the real 36 Manticore SPDM measurement digests against positive and
    /// negative auth CORIMs to verify that `validate_measurements_against_authenticity_corim`
    /// correctly accepts matching measurements and rejects corrupted ones.
    #[test]
    fn test_manticore_spdm_measurement_negative_cases() {
        use crate::tdisp::corim_generator::{
            NegativeTestCase, generate_manticore_corim_pair_with_case, MANTICORE_SPDM_MEASUREMENTS,
        };
        use base64::Engine;

        // Build the real Manticore measurement records from the constants
        let measurements: Vec<spdmmeasurements::MeasurementRecord> =
            MANTICORE_SPDM_MEASUREMENTS.iter().map(|(index, digest)| {
                spdmmeasurements::MeasurementRecord {
                    index: *index,
                    measurement: spdmmeasurements::DmtfMeasurement {
                        value_type: spdmmeasurements::DmtfMeasurementValueType {
                            representation: spdmmeasurements::MeasurementRepresentation::Digest,
                            measurement_type: spdmmeasurements::MeasurementType::HardwareConfiguration,
                        },
                        value_size: digest.len() as u16,
                        value: digest.to_vec(),
                    },
                }
            }).collect();

        // Test both positive and negative SPDM measurement cases
        let test_cases = [
            (NegativeTestCase::None, "positive case"),
            (NegativeTestCase::BadSpdmMeasurement, "corrupted measurement #1"),
        ];

        for (test_case, description) in &test_cases {
            let (auth_b64, _trust_b64) = generate_manticore_corim_pair_with_case(*test_case)
                .unwrap_or_else(|e| panic!("Failed to generate {:?}: {}", test_case, e));

            let auth_bytes = base64::engine::general_purpose::STANDARD
                .decode(&auth_b64).unwrap();
            let auth_corim = parse_corim_from_cbor(&auth_bytes)
                .unwrap_or_else(|e| panic!("Failed to parse auth CORIM for {:?}: {}", test_case, e));

            // Use the top-level validation function directly
            let result = validate_measurements_against_authenticity_corim(
                &measurements, &auth_corim,
            ).unwrap_or_else(|e| panic!("Validation error for {:?}: {}", test_case, e));

            let expected = *test_case == NegativeTestCase::None;
            assert_eq!(result, expected,
                "Test case {:?} ({}): got authentic={}, expected={}",
                test_case, description, result, expected);
            println!("  {:30} SPDM measurement validation: {} (expected={}) OK",
                test_case.label(), result, expected);
        }
    }

    #[test]
    fn test_create_test_corim_pair_integration_with_verifier() -> Result<(), anyhow::Error> {
        // Test that CORIMs created by the helper function work with TdispVerifier
        let mut verifier = TdispVerifier::new();
        let vendor_id = 0x1111;
        let device_id = 0x2222;

        // Create CORIMs using the helper
        let (auth, trust) = create_test_corim_pair()?;

        // Add to verifier
        verifier.add_corim_pair(vendor_id, device_id, auth, trust);

        // Verify integration works
        assert!(verifier.has_corims(vendor_id, device_id));
        assert!(verifier.get_corim_pair(vendor_id, device_id).is_some());
        assert!(
            verifier
                .get_authenticity_corim(vendor_id, device_id)
                .is_some()
        );
        assert!(verifier.get_trust_corim(vendor_id, device_id).is_some());

        Ok(())
    }

    /// Build a Trust CORIM with SVN-based CES triples
    ///
    /// - Environment instance: base64("SPDMMeasurement")
    /// - Condition: blocks 15–20, each with min-value SVN >= 0
    /// - CSR[0] (Current): blocks 15–20, each with min-value SVN >= 1 → UpToDate
    /// - CSR[1] (Catch-all): blocks 15–20, each with min-value SVN >= 0 → OutOfDate
    fn build_ovl3_spdm_trust_corim<'a>() -> Corim<'a> {
        use corim_rs::{
            ConditionalEndorsementSeriesTripleRecord, ConditionalSeriesRecord,
            ConciseMidTagBuilder, CorimEntityMapBuilder, CorimMapBuilder,
            CorimRoleTypeChoice, EnvironmentMap, InstanceIdTypeChoice,
            Integer, MeasurementMap, MeasurementValuesMapBuilder,
            MeasuredElementTypeChoice, MinSvnType, StatefulEnvironmentRecord,
            SvnTypeChoice, TagIdentityMap, TaggedBytes, TriplesMapBuilder, Uint,
        };
        use std::borrow::Cow;

        let spdm_instance = base64::engine::general_purpose::STANDARD
            .encode("SPDMMeasurement");

        let block_indices: [u8; 6] = [15, 16, 17, 18, 19, 20];

        // Helper: build a Vec<MeasurementMap> with one entry per block, each carrying min-value SVN >= threshold
        let make_claims = |threshold: i128| -> Vec<MeasurementMap<'a>> {
            block_indices
                .iter()
                .map(|&idx| MeasurementMap {
                    mkey: Some(MeasuredElementTypeChoice::UInt(Uint::from(idx as u64))),
                    mval: MeasurementValuesMapBuilder::new()
                        .svn(SvnTypeChoice::TaggedMinSvn(MinSvnType::from(Integer(
                            threshold,
                        ))))
                        .build()
                        .expect("build mval"),
                    authorized_by: None,
                })
                .collect()
        };

        // Condition environment
        let condition_env = EnvironmentMap {
            class: None,
            instance: Some(InstanceIdTypeChoice::Bytes(TaggedBytes::from(
                spdm_instance.as_bytes(),
            ))),
            group: None,
        };

        // Condition claims: all blocks SVN >= 0 (baseline)
        let condition = StatefulEnvironmentRecord::new(condition_env, make_claims(0));

        // CSR 0: Current — all blocks SVN >= 1 → UpToDate
        let up_to_date = ConditionalSeriesRecord::new(
            make_claims(1),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMapBuilder::new()
                    .tcb_status(Cow::from("UpToDate"))
                    .build()
                    .expect("build addition mval"),
                authorized_by: None,
            }],
        );

        // CSR 1: Catch-all — all blocks SVN >= 0 → OutOfDate
        let out_of_date = ConditionalSeriesRecord::new(
            make_claims(0),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMapBuilder::new()
                    .tcb_status(Cow::from("OutOfDate"))
                    .build()
                    .expect("build addition mval"),
                authorized_by: None,
            }],
        );

        let ces_triple = ConditionalEndorsementSeriesTripleRecord::new(
            condition,
            vec![up_to_date, out_of_date],
        );

        let comid_tag = ConciseMidTagBuilder::new()
            .tag_identity(TagIdentityMap {
                tag_id: "ovl3-spdm-trust-v1".into(),
                tag_version: Some(1.into()),
            })
            .triples(
                TriplesMapBuilder::new()
                    .conditional_endorsement_series_triples(vec![ces_triple])
                    .build()
                    .expect("build triples"),
            )
            .build()
            .expect("build comid");

        let corim_map = CorimMapBuilder::new()
            .id("OVL3_TDISP_Trust_SVN".into())
            .add_entity(
                CorimEntityMapBuilder::new()
                    .entity_name("Test".into())
                    .add_role(CorimRoleTypeChoice::ManifestCreator)
                    .build()
                    .expect("build entity"),
            )
            .add_tag(comid_tag.into())
            .build()
            .expect("build corim");

        corim_rs::ConciseRimTypeChoice::Unsigned(corim_map.into())
    }

    /// Build SVN measurement records for blocks 15–20 with the given SVN value.
    fn make_svn_measurements(svn: u64) -> Vec<spdmmeasurements::MeasurementRecord> {
        (15u8..=20)
            .map(|idx| spdmmeasurements::MeasurementRecord {
                index: idx,
                measurement: spdmmeasurements::DmtfMeasurement {
                    value_type: spdmmeasurements::DmtfMeasurementValueType {
                        representation:
                            spdmmeasurements::MeasurementRepresentation::RawBitStream,
                        measurement_type:
                            spdmmeasurements::MeasurementType::FirmwareSecurityVersionNumber,
                    },
                    value_size: 8,
                    value: svn.to_le_bytes().to_vec(),
                },
            })
            .collect()
    }

    /// Step 6b: Trust CORIM SVN-based measurement evaluation (OVL3 sample).
    ///
    /// Mirrors the structure from `ovl3_trust_corim_sample.json`:
    /// blocks 15–20, min-SVN thresholds, first-match-wins CES semantics.
    #[test]
    fn test_spdm_measurements_trust_corim_svn_based() {
        let trust_corim = build_ovl3_spdm_trust_corim();

        // Case 1: All blocks SVN=1 → matches CSR[0] (>= 1) → UpToDate
        let measurements_current = make_svn_measurements(1);
        let result = validate_measurements_against_trust_corim(
            &measurements_current,
            &trust_corim,
        )
        .expect("validation should not error");
        assert!(result, "SVN=1 across all blocks should be UpToDate");

        // Case 2: All blocks SVN=5 → still matches CSR[0] (5 >= 1) → UpToDate
        let measurements_ahead = make_svn_measurements(5);
        let result = validate_measurements_against_trust_corim(
            &measurements_ahead,
            &trust_corim,
        )
        .expect("validation should not error");
        assert!(result, "SVN=5 across all blocks should still be UpToDate");

        // Case 3: All blocks SVN=0 → fails CSR[0] (0 < 1), matches CSR[1] (>= 0) → OutOfDate
        let measurements_stale = make_svn_measurements(0);
        let result = validate_measurements_against_trust_corim(
            &measurements_stale,
            &trust_corim,
        )
        .expect("validation should not error");
        assert!(!result, "SVN=0 across all blocks should be OutOfDate");
    }

    /// Step 6b: Mixed SVN — one stale block is enough to fall through to catch-all.
    #[test]
    fn test_spdm_measurements_trust_corim_mixed_svn() {
        let trust_corim = build_ovl3_spdm_trust_corim();

        // Start with all blocks at SVN=1 (current), then set block 17 to SVN=0 (stale)
        let mut measurements = make_svn_measurements(1);
        // block 17 is the third entry (indices 15,16,17,18,19,20)
        measurements[2].measurement.value = 0u64.to_le_bytes().to_vec();

        let result = validate_measurements_against_trust_corim(
            &measurements,
            &trust_corim,
        )
        .expect("validation should not error");
        assert!(
            !result,
            "One stale block (17 at SVN=0) should cause OutOfDate"
        );
    }

}
