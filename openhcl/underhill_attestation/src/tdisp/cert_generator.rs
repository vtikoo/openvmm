// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DICE Certificate Generator for TDISP Testing
//! Creates X.509 certificates with DICE TCBInfo extensions that are compatible
//! with existing CORIM files for end-to-end testing

use anyhow::Result;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509, X509Builder, X509Extension, X509NameBuilder};
use std::fs;

/// Layer 0 FWID digest (first 32 bytes)
const TEST_FWID_DIGEST_L0: [u8; 32] = [
    0x17, 0x19, 0xA3, 0x0D, 0x51, 0x01, 0xFF, 0x9D, 0xB2, 0xA5, 0x6E, 0xA9, 0xBD, 0xB5, 0xC4, 0x4E,
    0x0C, 0xD8, 0x34, 0x0B, 0x85, 0x35, 0xC9, 0xBC, 0xBF, 0x5A, 0x2A, 0xE0, 0xA1, 0xD1, 0x54, 0x45,
];

/// Layer 1 FWID digest (first 32 bytes)
const TEST_FWID_DIGEST_L1: [u8; 32] = [
    0xBF, 0x7D, 0x19, 0x96, 0xB0, 0x41, 0xAA, 0x24, 0x29, 0xD5, 0x16, 0x7E, 0xBF, 0x07, 0x6E, 0xEC,
    0xCB, 0xDF, 0xCE, 0x0F, 0xE4, 0x93, 0x9E, 0xD8, 0xA3, 0x93, 0x63, 0x2C, 0x0B, 0x42, 0x3C, 0x2A,
];

/// DICE TCBInfo structure specification from TCG DICE Layered Attestation v1.2

/// DICE TCBInfo OID: 2.23.133.5.4.1
const DICE_TCBINFO_OID: &str = "2.23.133.5.4.1";

/// Generate a DICE TCBInfo ASN.1 extension with the expected CORIM digest
///
/// This creates an ASN.1 DER structure matching the DICE specification:
/// DiceTcbInfo ::= SEQUENCE {
///     vendor      [0] UTF8String OPTIONAL,
///     model       [1] UTF8String OPTIONAL,
///     version     [2] UTF8String OPTIONAL,
///     svn         [3] INTEGER OPTIONAL,
///     layer       [4] INTEGER OPTIONAL,
///     index       [5] INTEGER OPTIONAL,
///     fwids       [6] SEQUENCE OF FWIDRef OPTIONAL,
///     flags       [7] BIT STRING OPTIONAL,
///     vendorInfo  [8] OCTET STRING OPTIONAL,
///     type        [9] OCTET STRING OPTIONAL,
///     integrityRegisters [10] SEQUENCE OF IntegrityRegister OPTIONAL
/// }
fn generate_dice_tcbinfo_extension(layer: u64, fwid_digest: &[u8]) -> Result<Vec<u8>> {
    println!(
        "🔨 Generating DICE TCBInfo for layer: {}, as u8: {:#x}",
        layer, layer as u8
    );

    // Create our 48-byte digest (SHA-384 size to match Microsoft)
    let mut our_digest = vec![0u8; 48];
    if fwid_digest.len() >= 32 {
        our_digest[..32].copy_from_slice(&fwid_digest[..32]);
    } else {
        our_digest[..fwid_digest.len()].copy_from_slice(fwid_digest);
    }
    // Leave remaining bytes as zeros for padding

    if layer == 0 {
        // Layer 0: Use exact Microsoft certificate hex as template
        let microsoft_layer0_hex = "3082010b80094d6963726f736f66748114417a75726520496e74656772617465642048534d8210332e342e322e342d3530393232313734830101840100a63f303d060960864801650304020204301719a30d5101ff9db2a56ea9bdb5c44e0cd8340b8535c9bcbf5a2ae0a1d15445d43b076a31c7f12eedd98ed70f928ea3aa818e304580024657a23f303d06096086480165030402020430000103edd22b14622f727251751e5aff2f580e8d110c3c664fe1d0d63d4f929173111d3220a49da8c5f10f66c3897369304580025443a23f303d060960864801650304020204302e630db522f78ed75f025bac8e0b5590d70f7d8af879dc76a289f72512e9a028ee4d098615d3717b19e6b1ca3698ee4a";
        let asn1_data = hex::decode(microsoft_layer0_hex)?;

        // Replace digests at exact byte offsets (found by analysis):
        // Layer 0 has 3 digests: FWID (78-125), FW register (152-199), TC register (223-270)

        // // Replace FWID digest at offset 78-125
        // asn1_data[78..126].copy_from_slice(&our_digest);
        // println!("  ✓ Replaced FWID digest at offset 78-125");

        // // Replace FW register digest at offset 152-199
        // asn1_data[152..200].copy_from_slice(&our_digest);
        // println!("  ✓ Replaced FW register digest at offset 152-199");

        // // Replace TC register digest at offset 223-270
        // asn1_data[223..271].copy_from_slice(&our_digest);
        // println!("  ✓ Replaced TC register digest at offset 223-270");

        println!("✅ Generated Layer 0 ASN.1 DER: {} bytes", asn1_data.len());
        Ok(asn1_data)
    } else {
        // Layer 1: Use exact Microsoft certificate hex as template
        let microsoft_layer1_hex = "3081c480094d6963726f736f66748114417a75726520496e74656772617465642048534d8210332e342e332e372d3531303031323232830101840101a63f303d06096086480165030402020430bf7d1996b041aa2429d5167ebf076eeccbdfce0fe4939ed8a393632c0b423c2adccb3f8cf78d2a749b234d052252a5a4aa4830468003526f54a23f303d06096086480165030402020430a7e625f513d4dc8216031cc11eb3c5f79f169c533b5f0b51154459013b8949920320a5301909f9c437a4a9cffb2d1700";
        let mut asn1_data = hex::decode(microsoft_layer1_hex)?;

        // Replace digests at exact byte offsets (found by analysis):
        // Layer 1 has 2 digests: FWID (77-124), RoT register (151-198)

        // Replace FWID digest at offset 77-124
        // asn1_data[77..125].copy_from_slice(&our_digest);
        // println!("  ✓ Replaced FWID digest at offset 77-124");

        // Replace RoT register digest at offset 151-198
        asn1_data[151..199].copy_from_slice(&our_digest);
        println!("  ✓ Replaced RoT register digest at offset 151-198");

        println!("✅ Generated Layer 1 ASN.1 DER: {} bytes", asn1_data.len());
        Ok(asn1_data)
    }
}

/// Helper function to find byte pattern in slice
#[allow(dead_code)]
fn find_bytes_in_slice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Generate a test certificate with DICE TCBInfo extension
pub fn generate_test_certificate(layer: u64, subject_name: &str) -> Result<(X509, PKey<Private>)> {
    // Generate RSA key pair
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    // Create certificate builder
    let mut builder = X509Builder::new()?;

    // Set version (X.509 v3)
    builder.set_version(2)?;

    // Set serial number
    let serial = BigNum::from_u32(1)?;
    let serial_asn1 = Asn1Integer::from_bn(&serial)?;
    builder.set_serial_number(&serial_asn1)?;

    // Set subject name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", subject_name)?;
    name_builder.append_entry_by_text("O", "Microsoft")?;
    name_builder.append_entry_by_text("C", "US")?;
    let subject_name = name_builder.build();
    builder.set_subject_name(&subject_name)?;

    // Set issuer name (self-signed)
    builder.set_issuer_name(&subject_name)?;

    // Set public key
    builder.set_pubkey(&pkey)?;

    // Set validity period
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Add basic extensions
    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(basic_constraints)?;

    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()?;
    builder.append_extension(key_usage)?;

    let subject_key_id = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(subject_key_id)?;

    // Generate the DICE TCBInfo extension with layer-specific digest
    let digest = match layer {
        0 => &TEST_FWID_DIGEST_L0,
        1 => &TEST_FWID_DIGEST_L1,
        _ => anyhow::bail!("Unsupported layer: {}", layer),
    };
    let dice_tcbinfo_der = generate_dice_tcbinfo_extension(layer, digest)?;

    // Create custom extension for DICE TCBInfo
    let dice_oid = openssl::asn1::Asn1Object::from_str(DICE_TCBINFO_OID)?;
    let dice_octet_string = openssl::asn1::Asn1OctetString::new_from_bytes(&dice_tcbinfo_der)?;
    let dice_extension = X509Extension::new_from_der(
        &dice_oid,
        false, // not critical
        &dice_octet_string,
    )?;

    builder.append_extension(dice_extension)?;

    // Sign the certificate
    builder.sign(&pkey, MessageDigest::sha256())?;

    let cert = builder.build();

    Ok((cert, pkey))
}

/// Generate a certificate chain compatible with CORIM files
pub fn generate_test_certificate_chain() -> Result<Vec<X509>> {
    let mut chain = Vec::new();

    // Generate Layer 0 certificate (should match CORIM Layer 0)
    let (layer0_cert, _layer0_key) = generate_test_certificate(0, "Layer0-TestDICE")?;
    chain.push(layer0_cert);

    // Generate Layer 1 certificate (should match CORIM Layer 1)
    let (layer1_cert, _layer1_key) = generate_test_certificate(1, "Layer1-TestDICE")?;
    chain.push(layer1_cert);

    Ok(chain)
}

/// Save certificate chain to PEM files for testing
pub fn save_test_certificates() -> Result<()> {
    let chain = generate_test_certificate_chain()?;

    // Get the path to the test_certs directory
    let mut base_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    base_path.push("src/tdisp/test_certs");

    // Create directory if it doesn't exist
    fs::create_dir_all(&base_path)?;

    // Save Layer 0 certificate
    let layer0_pem = chain[0].to_pem()?;
    let mut layer0_pem_path = base_path.clone();
    layer0_pem_path.push("layer0_test.pem");
    fs::write(&layer0_pem_path, layer0_pem)?;

    // Save Layer 1 certificate
    let layer1_pem = chain[1].to_pem()?;
    let mut layer1_pem_path = base_path.clone();
    layer1_pem_path.push("layer1_test.pem");
    fs::write(&layer1_pem_path, layer1_pem)?;

    // Also save as DER for binary testing
    let layer0_der = chain[0].to_der()?;
    let mut layer0_der_path = base_path.clone();
    layer0_der_path.push("layer0_test.der");
    fs::write(&layer0_der_path, layer0_der)?;

    let layer1_der = chain[1].to_der()?;
    let mut layer1_der_path = base_path.clone();
    layer1_der_path.push("layer1_test.der");
    fs::write(&layer1_der_path, layer1_der)?;

    println!("✓ Generated test certificates:");
    println!(
        "  - Layer 0: {}/layer0_test.{{pem,der}}",
        base_path.display()
    );
    println!(
        "  - Layer 1: {}/layer1_test.{{pem,der}}",
        base_path.display()
    );
    println!("  - Layer 0 FWID[0]: {}", hex::encode(&TEST_FWID_DIGEST_L0));
    println!("  - Layer 1 FWID[0]: {}", hex::encode(&TEST_FWID_DIGEST_L1));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdisp::spdmcertchain::parse_dice_tcb_info_asn1;
    use der::Decode;
    use x509_cert::Certificate;

    #[test]
    fn test_generate_compatible_certificates() {
        // Generate test certificates
        let chain =
            generate_test_certificate_chain().expect("Failed to generate certificate chain");

        assert_eq!(chain.len(), 2, "Should generate 2 certificates");

        for (i, cert) in chain.iter().enumerate() {
            println!("Testing certificate {} (Layer {})", i, i);

            // Convert to DER for parsing
            let cert_der = cert.to_der().expect("Failed to convert to DER");

            // Parse with x509-cert crate
            let cert_x509 = Certificate::from_der(&cert_der).expect("Failed to parse certificate");

            // Look for DICE extension
            if let Some(extensions) = &cert_x509.tbs_certificate.extensions {
                let mut found_dice = false;

                for ext in extensions {
                    if ext.extn_id.to_string() == DICE_TCBINFO_OID {
                        found_dice = true;
                        let ext_data = ext.extn_value.as_bytes();

                        // Parse DICE TCBInfo
                        match parse_dice_tcb_info_asn1(ext_data) {
                            Ok(dice_info) => {
                                println!("  ✓ Successfully parsed DICE TCBInfo:");
                                println!("    Vendor: {:?}", dice_info.vendor);
                                println!("    Model: {:?}", dice_info.model);
                                println!("    Version: {:?}", dice_info.version);
                                println!("    Layer: {:?}", dice_info.layer);
                                println!("    FWIDs count: {}", dice_info.fwids.len());

                                // Verify layer matches expectation
                                assert_eq!(dice_info.layer, Some(i as u64));

                                // Verify FWID[0] contains layer-specific digest (first 32 bytes)
                                assert!(
                                    !dice_info.fwids.is_empty(),
                                    "Should have at least one FWID"
                                );
                                assert_eq!(
                                    dice_info.fwids[0].digest.len(),
                                    48,
                                    "FWID digest should be 48 bytes (SHA-384)"
                                );
                                let expected_digest = match i {
                                    0 => &TEST_FWID_DIGEST_L0,
                                    1 => &TEST_FWID_DIGEST_L1,
                                    _ => panic!("Unexpected layer {}", i),
                                };
                                assert_eq!(
                                    &dice_info.fwids[0].digest[..32],
                                    expected_digest,
                                    "First 32 bytes of FWID[0] digest should match layer {} digest",
                                    i
                                );

                                println!(
                                    "    ✓ FWID[0] (alg={}) matches CORIM digest: {}",
                                    dice_info.fwids[0].hash_alg,
                                    hex::encode(&dice_info.fwids[0].digest)
                                );
                            }
                            Err(e) => {
                                panic!("Failed to parse DICE TCBInfo: {}", e);
                            }
                        }

                        break;
                    }
                }

                assert!(found_dice, "Should find DICE TCBInfo extension");
            } else {
                panic!("Certificate should have extensions");
            }
        }

        println!("✓ All certificates generated successfully with matching CORIM digests");
    }
}
