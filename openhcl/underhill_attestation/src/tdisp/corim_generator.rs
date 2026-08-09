// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CORIM Generator for Microsoft Certificate Values
//! Creates CORIM files that match the exact values from Microsoft Azure certificates
//! for TDISP testing compatibility

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor;
use corim::cbor::value::Value;
use corim::profile::intel::MVAL_TEE_TCBSTATUS;
use corim::types::common::{CryptoKey, EntityMap, MeasuredElement, TagIdChoice, VersionMap};
use corim::types::corim::{CorimId, CorimMap};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, IntegrityRegisterId, IntegrityRegisters, MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::tags::{COMID_ROLE_TAG_CREATOR, CORIM_ROLE_MANIFEST_CREATOR, TAG_CORIM, VERSION_SCHEME_MULTIPARTNUMERIC};
use corim::types::triples::{CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord, IdentityTriple, ReferenceTriple};
use openssl::hash::DigestBytes;

/// Specifies which triple should contain wrong data for negative testing.
///
/// For each variant, all triples EXCEPT the specified one remain correct.
/// This validates that the verifier detects each individual type of mismatch.
#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(dead_code)]
pub enum NegativeTestCase {
    /// All triples are correct (positive case)
    None,

    // --- Auth CORIM negative cases (expect authentic=false) ---
    /// One SPDM measurement digest is corrupted (first byte of measurement #1 flipped)
    BadSpdmMeasurement,
    /// DICE TCBInfo layer 0 FWID digest is corrupted
    BadTcbInfoLayer0,
    /// DICE TCBInfo layer 1 FWID digest is corrupted
    BadTcbInfoLayer1,
    /// Root certificate thumbprint is wrong
    BadRootCertThumbprint,

    // --- Trust CORIM negative cases (expect tcb_up_to_date=false) ---
    /// UpToDate SVN threshold for layer 0 set unreachably high (999)
    BadTrustTcbInfoLayer0,
    /// UpToDate SVN threshold for layer 1 set unreachably high (999)
    BadTrustTcbInfoLayer1,
}

impl NegativeTestCase {
    /// Human-readable label for this test case
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "positive",
            Self::BadSpdmMeasurement => "bad_spdm_measurement",
            Self::BadTcbInfoLayer0 => "bad_tcbinfo_layer0",
            Self::BadTcbInfoLayer1 => "bad_tcbinfo_layer1",
            Self::BadRootCertThumbprint => "bad_root_cert_thumbprint",
            Self::BadTrustTcbInfoLayer0 => "bad_trust_tcbinfo_layer0",
            Self::BadTrustTcbInfoLayer1 => "bad_trust_tcbinfo_layer1",
        }
    }

    /// Description of what this test case validates
    #[allow(dead_code)]
    pub fn description(&self) -> &'static str {
        match self {
            Self::None => "All triples correct — expect authentic=true, tcb_up_to_date=true",
            Self::BadSpdmMeasurement => "SPDM measurement #1 corrupted — expect authentic=false",
            Self::BadTcbInfoLayer0 => "DICE TCBInfo layer 0 FWID corrupted — expect authentic=false",
            Self::BadTcbInfoLayer1 => "DICE TCBInfo layer 1 FWID corrupted — expect authentic=false",
            Self::BadRootCertThumbprint => "Root cert thumbprint wrong — expect authentic=false",
            Self::BadTrustTcbInfoLayer0 => "Trust layer 0 SVN threshold unreachable — expect tcb_up_to_date=false",
            Self::BadTrustTcbInfoLayer1 => "Trust layer 1 SVN threshold unreachable — expect tcb_up_to_date=false",
        }
    }

    /// Whether this case affects the Auth CORIM (vs Trust CORIM)
    #[allow(dead_code)]
    pub fn affects_auth(&self) -> bool {
        matches!(self, Self::BadSpdmMeasurement | Self::BadTcbInfoLayer0 | Self::BadTcbInfoLayer1 | Self::BadRootCertThumbprint)
    }

    /// All test cases including the positive one
    #[allow(dead_code)]
    pub fn all() -> &'static [NegativeTestCase] {
        &[
            Self::None,
            Self::BadSpdmMeasurement,
            Self::BadTcbInfoLayer0,
            Self::BadTcbInfoLayer1,
            Self::BadRootCertThumbprint,
            Self::BadTrustTcbInfoLayer0,
            Self::BadTrustTcbInfoLayer1,
        ]
    }
}

/// Expected digest from our test certificates (first 32 bytes of FWID)
const TEST_FWID_DIGEST: [u8; 48] = [
    0x17, 0x19, 0xA3, 0x0D, 0x51, 0x01, 0xFF, 0x9D, 0xB2, 0xA5, 0x6E, 0xA9, 0xBD, 0xB5, 0xC4, 0x4E,
    0x0C, 0xD8, 0x34, 0x0B, 0x85, 0x35, 0xC9, 0xBC, 0xBF, 0x5A, 0x2A, 0xE0, 0xA1, 0xD1, 0x54, 0x45,
    0xD4, 0x3B, 0x07, 0x6A, 0x31, 0xC7, 0xF1, 0x2E, 0xED, 0xD9, 0x8E, 0xD7, 0x0F, 0x92, 0x8E, 0xA3,
];

const TEST_FWID_DIGEST_LAYER1: [u8; 48] = [
    0xBF, 0x7D, 0x19, 0x96, 0xB0, 0x41, 0xAA, 0x24, 0x29, 0xD5, 0x16, 0x7E, 0xBF, 0x07, 0x6E, 0xEC,
    0xCB, 0xDF, 0xCE, 0x0F, 0xE4, 0x93, 0x9E, 0xD8, 0xA3, 0x93, 0x63, 0x2C, 0x0B, 0x42, 0x3C, 0x2A,
    0xDC, 0xCB, 0x3F, 0x8C, 0xF7, 0x8D, 0x2A, 0x74, 0x9B, 0x23, 0x4D, 0x05, 0x22, 0x52, 0xA5, 0xA4,
];

const TEST_L0_INTREG_FW: [u8; 48] = [
    0x00, 0x01, 0x03, 0xED, 0xD2, 0x2B, 0x14, 0x62, 0x2F, 0x72, 0x72, 0x51, 0x75, 0x1E, 0x5A, 0xFF,
    0x2F, 0x58, 0x0E, 0x8D, 0x11, 0x0C, 0x3C, 0x66, 0x4F, 0xE1, 0xD0, 0xD6, 0x3D, 0x4F, 0x92, 0x91,
    0x73, 0x11, 0x1D, 0x32, 0x20, 0xA4, 0x9D, 0xA8, 0xC5, 0xF1, 0x0F, 0x66, 0xC3, 0x89, 0x73, 0x69,
];

const TEST_L0_INTREG_TC: [u8; 48] = [
    0x2E, 0x63, 0x0D, 0xB5, 0x22, 0xF7, 0x8E, 0xD7, 0x5F, 0x02, 0x5B, 0xAC, 0x8E, 0x0B, 0x55, 0x90,
    0xD7, 0x0F, 0x7D, 0x8A, 0xF8, 0x79, 0xDC, 0x76, 0xA2, 0x89, 0xF7, 0x25, 0x12, 0xE9, 0xA0, 0x28,
    0xEE, 0x4D, 0x09, 0x86, 0x15, 0xD3, 0x71, 0x7B, 0x19, 0xE6, 0xB1, 0xCA, 0x36, 0x98, 0xEE, 0x4A,
];

/// Test SPDM measurement digests for validation testing
pub const TEST_SPDM_MEASUREMENT_1: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

/// Test SPDM measurement value #2 for testing
pub const TEST_SPDM_MEASUREMENT_2: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
];

/// Microsoft Layer 0 certificate values (from template analysis)
struct MicrosoftLayer0 {
    vendor: &'static str,
    model: &'static str,
    version: &'static str,
    svn: u64,
    layer: u64,
}

/// Microsoft Layer 1 certificate values (from template analysis)
struct MicrosoftLayer1 {
    vendor: &'static str,
    model: &'static str,
    version: &'static str,
    svn: u64,
    layer: u64,
}

const MSFT_LAYER0: MicrosoftLayer0 = MicrosoftLayer0 {
    vendor: "Microsoft",
    model: "Azure Integrated HSM",
    version: "3.4.2.4-50922174",
    svn: 1,
    layer: 0,
};

const MSFT_LAYER1: MicrosoftLayer1 = MicrosoftLayer1 {
    vendor: "Microsoft",
    model: "Azure Integrated HSM",
    version: "3.4.3.7-51001222",
    svn: 1,
    layer: 1,
};

const SHA256_ALG_ID: i64 = 1;
const SHA384_ALG_ID: i64 = 7;

fn digest(alg: i64, bytes: &[u8]) -> Digest {
    Digest::new(alg, bytes.to_vec())
}

fn multipart_version(version: &str) -> VersionMap {
    VersionMap {
        version: version.into(),
        version_scheme: Some(VERSION_SCHEME_MULTIPARTNUMERIC),
    }
}

fn bytes_instance(bytes: &[u8]) -> corim::types::common::InstanceIdChoice {
    corim::types::common::InstanceIdChoice::Bytes(bytes.to_vec())
}

fn tcb_status_measurement(status: &str) -> MeasurementMap {
    let mut mval = MeasurementValuesMap::default();
    mval.extra_entries
        .insert(MVAL_TEE_TCBSTATUS, Value::Text(status.into()));

    MeasurementMap {
        mkey: None,
        mval,
        authorized_by: None,
    }
}

fn encode_corim(corim_map: CorimMap) -> Result<Vec<u8>> {
    Ok(cbor::encode(&cbor::value::Tagged::new(TAG_CORIM, corim_map))?)
}

/// Generate a CORIM file with Microsoft certificate values
pub fn generate_microsoft_corim(_root_thumbprint: Option<&DigestBytes>) -> Result<Vec<u8>> {
    generate_microsoft_corim_impl()
}

/// Generate a Manticore CORIM pair (Authenticity and Trust) ready for VTL2 settings
///
/// This generates base64-encoded CBOR CORIMs that can be directly used in Set-VTL2Settings.
/// The authenticity CORIM contains the root certificate thumbprint from real Manticore device.
#[allow(dead_code)]
pub fn generate_manticore_corim_pair() -> Result<(String, String)> {
    generate_manticore_corim_pair_with_case(NegativeTestCase::None)
}

/// Generate a Manticore CORIM pair with a specific test case (positive or negative).
///
/// For negative cases, only the targeted triple is corrupted; all others remain correct.
/// This allows testing that the verifier catches each individual type of mismatch.
#[allow(dead_code)]
pub fn generate_manticore_corim_pair_with_case(test_case: NegativeTestCase) -> Result<(String, String)> {
    // This is the actual root certificate thumbprint from Manticore device
    // Extracted from working logs: root_hash in SPDM certificate chain response
    let mut root_thumbprint: [u8; 48] = [
        0x6c, 0xf4, 0xd3, 0x06, 0xf1, 0x4f, 0x7e, 0xa5, 0xe0, 0x73, 0x10, 0xed, 0x88, 0xdb, 0xb7,
        0x9c, 0xab, 0x9c, 0xe4, 0x2d, 0x7f, 0x4a, 0x4a, 0x19, 0x36, 0xcd, 0x18, 0x41, 0x97, 0x08,
        0xb7, 0x03, 0x96, 0xfd, 0x69, 0xab, 0x41, 0x16, 0xd6, 0x96, 0xdb, 0xa7, 0xd8, 0x4c, 0xfa,
        0x7b, 0xa0, 0x32,
    ];

    // Corrupt root thumbprint for negative test case
    if test_case == NegativeTestCase::BadRootCertThumbprint {
        root_thumbprint[0] ^= 0xFF; // Flip first byte
    }

    println!("[MANTICORE] Generating CORIMs (test_case={:?}) with root thumbprint: {}", test_case, hex::encode(root_thumbprint));

    // Create Authenticity CORIM with identity triple containing root cert thumbprint
    let auth_corim = create_manticore_auth_corim(&root_thumbprint, test_case)?;
    
    // Create Trust CORIM with endorsement information
    let trust_corim = create_manticore_trust_corim(test_case)?;

    // Serialize to tagged CoRIM CBOR that matches the Azure decoder.
    let auth_cbor = encode_corim(auth_corim)?;
    let trust_cbor = encode_corim(trust_corim)?;

    // Encode as base64
    let auth_b64 = base64_engine.encode(&auth_cbor);
    let trust_b64 = base64_engine.encode(&trust_cbor);

    println!("[MANTICORE] Generated Authenticity CORIM: {} bytes (base64: {} chars)", 
             auth_cbor.len(), auth_b64.len());
    println!("[MANTICORE] Generated Trust CORIM: {} bytes (base64: {} chars)",
             trust_cbor.len(), trust_b64.len());

    Ok((auth_b64, trust_b64))
}

/// Manticore vendor ID (Microsoft: 0x1414)
pub const MANTICORE_VENDOR_ID: u32 = 0x1414;
/// Manticore device ID (0xC003)
pub const MANTICORE_DEVICE_ID: u32 = 0xC003;

/// Generate the TdispDeviceRims JSON string for a given test case.
///
/// The JSON has the structure expected by Set-Vtl2Settings -Namespace "TdispDeviceRims":
/// ```json
/// {
///   "devices": [{
///     "vendor_id": 5140,
///     "device_id": 49155,
///     "device_name": "Manticore Device",
///     "auth_rim": "<base64>",
///     "trust_rim": "<base64>"
///   }]
/// }
/// ```
#[allow(dead_code)]
pub fn generate_tdisp_device_rims_json(test_case: NegativeTestCase) -> Result<String> {
    let (auth_b64, trust_b64) = generate_manticore_corim_pair_with_case(test_case)?;

    let json = serde_json::json!({
        "devices": [{
            "vendor_id": MANTICORE_VENDOR_ID,
            "device_id": MANTICORE_DEVICE_ID,
            "device_name": format!("Manticore Device ({})", test_case.label()),
            "auth_rim": auth_b64,
            "trust_rim": trust_b64
        }]
    });

    Ok(serde_json::to_string_pretty(&json)?)
}

/// Generate JSON files for all test cases (positive + negative) into the given directory.
///
/// Creates files named `manticore_<label>.json` for each test case.
/// Returns the list of generated file paths.
#[allow(dead_code)]
pub fn generate_all_test_case_json_files(output_dir: &Path) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(output_dir)?;

    let mut paths = Vec::new();
    for test_case in NegativeTestCase::all() {
        let json = generate_tdisp_device_rims_json(*test_case)?;
        let filename = format!("manticore_{}.json", test_case.label());
        let path = output_dir.join(&filename);
        fs::write(&path, &json)?;
        println!("[JSON] Written {} ({} bytes)", path.display(), json.len());
        paths.push(path);
    }

    Ok(paths)
}

// Manticore device DICE TCBInfo FWID digests (SHA-384) from real SPDM certificate chain
// Certificate #0 (root/DeviceID): version "3.3.5.0-50701001", SVN 0
const MANTICORE_FWID_LAYER0: [u8; 48] = [
    0x99, 0x1b, 0x10, 0x46, 0x1b, 0x45, 0x82, 0x61, 0xa7, 0x95, 0x86, 0x24, 0xd5, 0xf9, 0x80, 0x0c,
    0x2e, 0xda, 0xad, 0x4e, 0x3c, 0xb8, 0x98, 0xba, 0xa1, 0x2d, 0x38, 0xaf, 0xe2, 0x2b, 0x26, 0x5c,
    0x9e, 0xd7, 0xcf, 0x1f, 0x32, 0x7d, 0x71, 0xa7, 0xf6, 0x60, 0x42, 0xc2, 0xf3, 0x84, 0x65, 0x12,
];

// Certificate #1 (alias/leaf): version "0.0.0.0-50725215beta(X)", SVN 0
const MANTICORE_FWID_LAYER1: [u8; 48] = [
    0x8c, 0xd9, 0x25, 0x0a, 0xba, 0x28, 0x28, 0xe1, 0x0b, 0x51, 0x65, 0xeb, 0xdd, 0xac, 0x47, 0xf0,
    0x29, 0x9a, 0xa4, 0x56, 0x34, 0x53, 0xa5, 0xb8, 0x83, 0x2f, 0x7c, 0x2a, 0x50, 0x32, 0x3b, 0x6e,
    0x0d, 0xa5, 0xc0, 0xb1, 0xfc, 0x44, 0x6c, 0xb1, 0x72, 0xfe, 0x9a, 0x99, 0x72, 0x9e, 0x9c, 0x58,
];

/// Real Manticore SPDM measurement digests (SHA-384, 48 bytes each)
/// Extracted from actual device SPDM GET_MEASUREMENTS response (36 records)
/// via MOCK_TSM_GET_MEAS_RSP in spdmmeasurements.rs tests
///
/// Format: (index, measurement_type, digest)
/// Types: 0x01=MutableFirmware, 0x02=HardwareConfiguration, 0x03=FirmwareConfiguration
pub const MANTICORE_SPDM_MEASUREMENTS: [(u8, &[u8; 48]); 36] = [
    // record[0]:  index=1,  HardwareConfiguration
    (1,  &[0xe6, 0xd1, 0x4d, 0x4f, 0x19, 0x80, 0x34, 0x74, 0x48, 0x3f, 0x51, 0x62, 0x01, 0xd8, 0xb8, 0x22, 0xf1, 0x0f, 0xf1, 0xd0, 0xcf, 0x0f, 0x99, 0x5c, 0x94, 0x6b, 0xc7, 0x9a, 0xc2, 0x64, 0x3b, 0xad, 0xb3, 0xf0, 0x99, 0xc7, 0x2a, 0xd8, 0x51, 0x3f, 0xa3, 0xf8, 0x1e, 0x84, 0x0e, 0xf5, 0xcf, 0x5a]),
    // record[1]:  index=2,  HardwareConfiguration
    (2,  &[0xbf, 0x2f, 0xdd, 0x64, 0x20, 0xe9, 0x63, 0x4d, 0xc4, 0xae, 0x12, 0xd0, 0xb8, 0x00, 0x09, 0x7c, 0xab, 0x05, 0x46, 0x68, 0xb6, 0x88, 0x0f, 0x03, 0x13, 0x9b, 0xae, 0x48, 0x45, 0xab, 0x0d, 0x49, 0x64, 0x82, 0xc3, 0xde, 0x81, 0x96, 0xb0, 0x8f, 0x62, 0x95, 0x7f, 0xab, 0xad, 0x3f, 0x4a, 0x1f]),
    // record[2]:  index=3,  HardwareConfiguration
    (3,  &[0xd8, 0x5c, 0x05, 0xfe, 0x32, 0x88, 0xf4, 0xca, 0xde, 0x6f, 0xbc, 0xec, 0x82, 0x89, 0xea, 0x00, 0x6a, 0x8b, 0x81, 0x09, 0x82, 0x93, 0xed, 0x92, 0x99, 0xb0, 0x22, 0xc4, 0xe4, 0xbf, 0x2a, 0x81, 0x35, 0x69, 0x06, 0x29, 0xd7, 0x05, 0x23, 0x87, 0x9a, 0xc8, 0x98, 0x3a, 0xe6, 0x4d, 0x83, 0xae]),
    // record[3]:  index=4,  HardwareConfiguration
    (4,  &[0x2e, 0x63, 0x0d, 0xb5, 0x22, 0xf7, 0x8e, 0xd7, 0x5f, 0x02, 0x5b, 0xac, 0x8e, 0x0b, 0x55, 0x90, 0xd7, 0x0f, 0x7d, 0x8a, 0xf8, 0x79, 0xdc, 0x76, 0xa2, 0x89, 0xf7, 0x25, 0x12, 0xe9, 0xa0, 0x28, 0xee, 0x4d, 0x09, 0x86, 0x15, 0xd3, 0x71, 0x7b, 0x19, 0xe6, 0xb1, 0xca, 0x36, 0x98, 0xee, 0x4a]),
    // record[4]:  index=5,  FirmwareConfiguration
    (5,  &[0x6d, 0xc9, 0x9e, 0xd5, 0x28, 0xc5, 0x82, 0x04, 0x62, 0x93, 0xe5, 0xe6, 0xd2, 0xa6, 0xc7, 0x44, 0x9f, 0x3d, 0x93, 0x90, 0x47, 0x69, 0x5e, 0xb3, 0x59, 0xa8, 0x7b, 0x1b, 0x08, 0x03, 0xb5, 0x09, 0x26, 0xe9, 0xa3, 0xed, 0xe2, 0x08, 0x5e, 0x36, 0x03, 0xd7, 0x83, 0x5f, 0x7a, 0xbf, 0xf0, 0x31]),
    // record[5]:  index=6,  FirmwareConfiguration
    (6,  &[0x35, 0xf0, 0x08, 0x73, 0x55, 0xb7, 0x7c, 0xc8, 0x27, 0xc9, 0x2c, 0x63, 0x33, 0x11, 0x1f, 0x5e, 0xa7, 0x26, 0x66, 0x69, 0x67, 0x74, 0x4b, 0x2d, 0xd1, 0x65, 0x35, 0x4f, 0x20, 0x97, 0x3f, 0x84, 0x9b, 0xf2, 0x66, 0x8f, 0x8f, 0x17, 0x91, 0xa6, 0x96, 0x1a, 0x7a, 0xcb, 0x9d, 0xc2, 0x2f, 0x6f]),
    // record[6]:  index=7,  MutableFirmware
    (7,  &[0x88, 0x94, 0x92, 0xe2, 0xce, 0x51, 0xdb, 0x4c, 0xd0, 0x40, 0xfe, 0xe0, 0x86, 0xe4, 0xe9, 0x73, 0x42, 0xd1, 0xe3, 0xbe, 0xa5, 0x96, 0xa3, 0xa6, 0x24, 0xcc, 0x91, 0x65, 0x66, 0x17, 0x42, 0x24, 0xfd, 0xe6, 0x3c, 0xc0, 0x45, 0xa2, 0xd6, 0x4c, 0x46, 0xda, 0x34, 0x1e, 0xc7, 0xa7, 0xf2, 0xe8]),
    // record[7]:  index=8,  MutableFirmware
    (8,  &[0xf2, 0xfd, 0xbf, 0x68, 0x2b, 0x84, 0x45, 0x67, 0x9c, 0xa1, 0xfb, 0x3e, 0xbf, 0xed, 0x3c, 0x78, 0x16, 0x3c, 0x42, 0xb7, 0x16, 0x26, 0xd6, 0xd7, 0xc0, 0x7f, 0xc6, 0xb6, 0x2f, 0xcf, 0xe0, 0x36, 0x13, 0x4d, 0xc5, 0x46, 0x5a, 0xd8, 0xe1, 0xe1, 0xd4, 0xf2, 0xf1, 0x02, 0x5e, 0x9f, 0xf5, 0x29]),
    // record[8]:  index=9,  MutableFirmware
    (9,  &[0x88, 0x3c, 0xd3, 0x00, 0x82, 0xc3, 0x55, 0x6b, 0x7f, 0x80, 0x14, 0xe7, 0x66, 0x35, 0xe3, 0x7c, 0x31, 0x63, 0xdd, 0xbb, 0x2b, 0x44, 0x0d, 0x1f, 0x0c, 0x06, 0x20, 0x85, 0x2f, 0x37, 0x3a, 0xe4, 0xe1, 0x58, 0x44, 0x95, 0x1f, 0xf8, 0x66, 0xa0, 0x7f, 0xb1, 0xb7, 0x2b, 0x30, 0x3d, 0xc6, 0x9c]),
    // record[9]:  index=10, FirmwareConfiguration
    (10, &[0x98, 0x2a, 0xf3, 0x8c, 0xee, 0x85, 0xd4, 0xa2, 0x31, 0x69, 0x7d, 0x43, 0x52, 0x7d, 0x77, 0x5f, 0x68, 0x0c, 0x45, 0x00, 0x95, 0x73, 0x58, 0x0b, 0xf0, 0xa1, 0xf4, 0x5b, 0x00, 0x02, 0x3c, 0x6c, 0x49, 0xc3, 0xf9, 0x0c, 0x53, 0xe6, 0xf2, 0x72, 0x86, 0x82, 0x55, 0xe0, 0x47, 0x34, 0x2d, 0x93]),
    // record[10]: index=11, FirmwareConfiguration
    (11, &[0x9b, 0x23, 0xf7, 0x75, 0xa2, 0x59, 0x6f, 0xb3, 0x63, 0x23, 0xb5, 0xd5, 0x5b, 0xca, 0xa3, 0x2c, 0xbb, 0x8d, 0x03, 0xb6, 0xab, 0xe0, 0xb5, 0xa9, 0x79, 0x45, 0x13, 0xdf, 0xc7, 0x29, 0x61, 0x01, 0x46, 0xab, 0xe8, 0xf9, 0x51, 0x20, 0xa2, 0x21, 0xf6, 0xf0, 0x24, 0x23, 0x44, 0xfb, 0xfe, 0xa5]),
    // record[11]: index=12, FirmwareConfiguration
    (12, &[0x91, 0xe8, 0x06, 0x9e, 0x7e, 0xeb, 0x67, 0x55, 0xdb, 0xcb, 0x37, 0x07, 0x00, 0x68, 0x0b, 0x0a, 0x20, 0x0c, 0x28, 0x2e, 0x8b, 0xb0, 0x2f, 0x69, 0xa8, 0x78, 0xbe, 0xc4, 0x17, 0x78, 0x1e, 0x4f, 0x45, 0x71, 0xed, 0x3c, 0x4c, 0x1d, 0x1a, 0xde, 0x9c, 0xff, 0xc3, 0xc5, 0x4d, 0xdd, 0xf3, 0xa2]),
    // record[12]: index=13, FirmwareConfiguration
    (13, &[0x32, 0x77, 0x15, 0x4c, 0x69, 0xf1, 0x69, 0xd0, 0x1c, 0x5d, 0x0a, 0x86, 0x4a, 0x7e, 0x60, 0x0f, 0x6a, 0xef, 0xf6, 0xa4, 0x8b, 0xad, 0xd2, 0x31, 0x9b, 0x06, 0x30, 0x07, 0xcb, 0x4f, 0x2a, 0x6b, 0xa4, 0x36, 0xa2, 0x4e, 0x7e, 0xfa, 0x22, 0x78, 0x26, 0x1b, 0x72, 0x68, 0xea, 0x02, 0x5b, 0xbe]),
    // record[13]: index=14, MutableFirmware
    (14, &[0xb1, 0x91, 0xe6, 0x3e, 0x8e, 0x9a, 0x01, 0x72, 0x43, 0x9c, 0x44, 0xd2, 0x88, 0x00, 0x9e, 0x1a, 0x71, 0xb6, 0x75, 0xa3, 0xc8, 0x3a, 0x56, 0xc5, 0xff, 0xea, 0x5e, 0x8a, 0xe0, 0x42, 0x56, 0x2e, 0x17, 0x9d, 0xd5, 0xe4, 0xbe, 0x98, 0x6a, 0x1e, 0x58, 0x4f, 0x6a, 0xba, 0x36, 0xb9, 0x0d, 0xac]),
    // record[14]: index=15, MutableFirmware
    (15, &[0xa4, 0x7b, 0x92, 0xbe, 0x15, 0x02, 0x55, 0xa6, 0xd5, 0xe4, 0x58, 0x2b, 0x32, 0x84, 0x77, 0x46, 0x2b, 0x16, 0x4d, 0xc3, 0x0a, 0x6b, 0xc0, 0x82, 0x24, 0x3c, 0x15, 0x2e, 0x53, 0xdf, 0x1b, 0x53, 0x45, 0x3d, 0x31, 0x44, 0x4c, 0x84, 0x82, 0x39, 0xdb, 0x08, 0x84, 0xca, 0x39, 0x74, 0xed, 0x7d]),
    // record[15]: index=16, MutableFirmware
    (16, &[0x4e, 0x7c, 0xe7, 0xae, 0xc8, 0xcc, 0x43, 0x1e, 0x0e, 0x81, 0xbf, 0x8a, 0x25, 0xc8, 0x8d, 0xae, 0x5d, 0xff, 0xd9, 0xb7, 0x07, 0xd9, 0x43, 0xb9, 0x97, 0xbe, 0x18, 0x25, 0x58, 0x25, 0x59, 0x18, 0xd2, 0xe1, 0xe1, 0x18, 0x8e, 0xab, 0xd7, 0x7e, 0x45, 0x89, 0xc7, 0x53, 0xa0, 0xb6, 0x9b, 0x20]),
    // record[16]: index=17, HardwareConfiguration
    (17, &[0xb4, 0x82, 0x5f, 0x49, 0x3f, 0xb1, 0xf8, 0xad, 0xf6, 0xd7, 0xd2, 0xd5, 0xe6, 0xe3, 0x35, 0x98, 0x1a, 0xc3, 0x3b, 0x3b, 0x92, 0xdb, 0x5c, 0x48, 0xb0, 0x3b, 0x5b, 0xd3, 0xa6, 0xda, 0xf1, 0x41, 0x3b, 0x98, 0xb6, 0x9f, 0x02, 0xc5, 0x6b, 0x42, 0x95, 0x71, 0x20, 0x12, 0x12, 0xe5, 0x35, 0x23]),
    // record[17]: index=18, HardwareConfiguration
    (18, &[0xca, 0x44, 0x79, 0x75, 0x01, 0xa9, 0xdd, 0x9e, 0xcb, 0x9c, 0xcc, 0xfd, 0x59, 0x30, 0xc3, 0xe9, 0x36, 0xee, 0x2c, 0x62, 0xc5, 0x06, 0xcb, 0x96, 0x83, 0x39, 0xfc, 0xd6, 0x22, 0x3c, 0x5a, 0x5f, 0xba, 0x21, 0xd4, 0xfc, 0xf3, 0x7a, 0x37, 0x10, 0x36, 0x53, 0x9d, 0xcb, 0xaf, 0xe6, 0xcb, 0xef]),
    // record[18]: index=19, FirmwareConfiguration
    (19, &[0x25, 0x0d, 0xe4, 0xbf, 0xec, 0xa8, 0xed, 0xd0, 0xa0, 0x4a, 0x0c, 0x4e, 0xf2, 0x4b, 0xb8, 0x76, 0x36, 0x94, 0x97, 0x9f, 0x76, 0x91, 0xef, 0xf2, 0xd5, 0x61, 0x60, 0xa6, 0x5a, 0x4c, 0x52, 0xa7, 0x94, 0xd8, 0xa4, 0x0c, 0xfe, 0x47, 0x16, 0xc4, 0xc5, 0x6c, 0xf8, 0xef, 0xa5, 0x6a, 0xd8, 0xf6]),
    // record[19]: index=20, FirmwareConfiguration
    (20, &[0x1e, 0xae, 0xa8, 0xdc, 0x93, 0x48, 0x35, 0xb6, 0x33, 0x3e, 0x86, 0xd7, 0xfe, 0x97, 0x0b, 0xb9, 0x14, 0x2c, 0xa9, 0x95, 0x10, 0x61, 0xb2, 0x39, 0xc9, 0xcf, 0xa1, 0x05, 0xa1, 0xae, 0x73, 0x61, 0xea, 0xd6, 0x31, 0xec, 0x05, 0x97, 0x81, 0xd4, 0x2d, 0xcc, 0xa6, 0x40, 0x8e, 0x77, 0x86, 0x9c]),
    // record[20]: index=21, FirmwareConfiguration
    (21, &[0xc6, 0x8e, 0x10, 0xee, 0x06, 0xe8, 0x2e, 0xdd, 0x26, 0xec, 0xee, 0xad, 0x04, 0x9d, 0x01, 0xbe, 0x4f, 0x5c, 0x46, 0x36, 0x1a, 0x4b, 0x5b, 0x7c, 0x18, 0x31, 0x16, 0x99, 0xd2, 0x81, 0xec, 0x63, 0x1f, 0xbc, 0x28, 0x2d, 0x6a, 0xbc, 0x5c, 0x20, 0x45, 0x8c, 0x14, 0xd1, 0x56, 0x46, 0x05, 0x5d]),
    // record[21]: index=22, MutableFirmware
    (22, &[0xc0, 0xdc, 0xab, 0xd6, 0x11, 0xa0, 0xf5, 0xde, 0x2a, 0x7c, 0x6a, 0x6a, 0x68, 0xf2, 0xe7, 0x2e, 0x7f, 0x19, 0x33, 0x7b, 0x1a, 0x76, 0xa1, 0x20, 0xa6, 0xf1, 0xc9, 0x90, 0xbc, 0xa9, 0xd9, 0xc7, 0x6b, 0xed, 0x44, 0x5b, 0xf2, 0xce, 0x99, 0x8c, 0x04, 0xe4, 0x97, 0x16, 0xf4, 0x45, 0xc7, 0x47]),
    // record[22]: index=23, MutableFirmware
    (23, &[0x48, 0x95, 0x9f, 0xfc, 0x36, 0xf2, 0x3c, 0x0c, 0xb5, 0x46, 0x60, 0xe4, 0x70, 0xf1, 0x67, 0x79, 0x65, 0xce, 0x55, 0x20, 0x51, 0x8f, 0x62, 0x28, 0xfc, 0x53, 0x12, 0xeb, 0xb4, 0xfb, 0x80, 0x96, 0xd4, 0x66, 0x01, 0x5d, 0x22, 0x95, 0xbe, 0x74, 0xa2, 0xf7, 0x64, 0x7c, 0xc9, 0x3b, 0xc6, 0x2c]),
    // record[23]: index=24, MutableFirmware
    (24, &[0x55, 0xe9, 0xc6, 0x0a, 0xa0, 0x9e, 0x7d, 0xd2, 0xae, 0x25, 0x3f, 0x4a, 0xc1, 0xab, 0xc5, 0x41, 0xf6, 0xe6, 0x6a, 0x4f, 0xc7, 0x19, 0x17, 0x35, 0x95, 0x6c, 0xb5, 0x13, 0xa9, 0xee, 0x34, 0x06, 0x8a, 0xb4, 0x15, 0x4f, 0x00, 0x3f, 0x5c, 0xe3, 0xd2, 0x64, 0x97, 0x4d, 0xe4, 0xf9, 0xb9, 0xdc]),
    // record[24]: index=25, MutableFirmware
    (25, &[0x67, 0x4e, 0xff, 0x49, 0x02, 0x75, 0x5a, 0xf8, 0xe6, 0x6c, 0xd5, 0x33, 0x7e, 0x19, 0x66, 0x3a, 0x3d, 0xa2, 0xcd, 0x1f, 0xc6, 0x82, 0x2d, 0xd5, 0x0a, 0xdf, 0xae, 0xe9, 0xb4, 0x33, 0x7b, 0x39, 0xba, 0xaa, 0xd2, 0xdd, 0x4e, 0xcb, 0x04, 0x19, 0x6b, 0x81, 0x4e, 0x7b, 0xb4, 0xf5, 0xd3, 0xe2]),
    // record[25]: index=26, MutableFirmware
    (26, &[0xe3, 0xe7, 0xf3, 0x7a, 0xea, 0xa3, 0x98, 0x77, 0xf8, 0xc2, 0x49, 0x77, 0xa7, 0x02, 0x2c, 0x72, 0x64, 0x18, 0x52, 0x3e, 0xed, 0x34, 0x80, 0x9d, 0x60, 0x98, 0xdf, 0xe2, 0xdc, 0x77, 0x4a, 0x1f, 0xa4, 0xcb, 0xd9, 0x21, 0x01, 0x0e, 0x0b, 0xb6, 0x2b, 0x0b, 0xc5, 0x88, 0x46, 0x4d, 0xa4, 0xed]),
    // record[26]: index=27, MutableFirmware
    (27, &[0x38, 0x8a, 0x2e, 0x14, 0x55, 0xa4, 0xc7, 0x82, 0x8f, 0xf0, 0x5b, 0xf7, 0x45, 0x94, 0x47, 0x5d, 0xf7, 0xc8, 0x11, 0xe4, 0x8b, 0xfc, 0xa2, 0xaa, 0x9d, 0xed, 0xca, 0x21, 0x14, 0x79, 0xf8, 0x26, 0xc3, 0x4a, 0xda, 0x26, 0xba, 0xc7, 0xa3, 0x53, 0xad, 0x11, 0xbe, 0xdb, 0x29, 0x6e, 0x69, 0x1f]),
    // record[27]: index=28, MutableFirmware
    (28, &[0xa0, 0x5e, 0x1b, 0xd1, 0x0c, 0x70, 0x6d, 0x41, 0x60, 0x60, 0x4e, 0x29, 0x9e, 0xe1, 0x91, 0x93, 0xab, 0xa2, 0xdd, 0xdd, 0x47, 0xa4, 0xc2, 0xf4, 0xa0, 0xf9, 0x89, 0xc8, 0x79, 0x06, 0x88, 0xef, 0x7b, 0x0f, 0x7e, 0x38, 0x5c, 0xef, 0xdf, 0x59, 0x12, 0x57, 0x5d, 0x4e, 0xb4, 0x27, 0x8c, 0x29]),
    // record[28]: index=29, FirmwareConfiguration
    (29, &[0xe7, 0xc0, 0x33, 0x9c, 0x04, 0xde, 0x17, 0x0d, 0xec, 0xca, 0x85, 0x52, 0x62, 0x05, 0xfc, 0xbd, 0xee, 0x0c, 0xb9, 0x86, 0x7f, 0x01, 0x70, 0xdb, 0x9e, 0x91, 0xb1, 0x79, 0xc1, 0xb6, 0xb8, 0xa8, 0x41, 0x69, 0x42, 0xb7, 0xbc, 0xb9, 0x01, 0xd1, 0x54, 0x94, 0xcb, 0x38, 0x47, 0x39, 0x4e, 0x31]),
    // record[29]: index=30, FirmwareConfiguration
    (30, &[0x12, 0x7a, 0x72, 0x47, 0xca, 0x71, 0xdc, 0x5c, 0xd1, 0xf6, 0x27, 0xee, 0x10, 0x63, 0x98, 0xef, 0x59, 0x3c, 0x9b, 0x75, 0x59, 0x0e, 0xba, 0x55, 0x79, 0x74, 0x87, 0x80, 0x44, 0xa9, 0xbe, 0xe0, 0xb7, 0xb8, 0x11, 0xc4, 0x25, 0xf4, 0x4d, 0xee, 0xf1, 0x7e, 0x08, 0x38, 0x7d, 0x3e, 0x31, 0x8c]),
    // record[30]: index=31, FirmwareConfiguration
    (31, &[0x09, 0x11, 0x98, 0x34, 0x9a, 0x7e, 0x50, 0x68, 0x35, 0x1a, 0x85, 0x32, 0xec, 0x45, 0xb2, 0x84, 0xa6, 0x0d, 0xe1, 0x22, 0xde, 0xe6, 0xe2, 0x6c, 0xd7, 0x60, 0xe1, 0xbd, 0x45, 0x08, 0x4e, 0x56, 0x2d, 0x4f, 0xbb, 0x91, 0xff, 0xa8, 0xda, 0xe5, 0x56, 0x6b, 0xaa, 0xab, 0x28, 0x7d, 0x67, 0xd4]),
    // record[31]: index=32, FirmwareConfiguration
    (32, &[0x6b, 0x58, 0x8c, 0x0f, 0xa2, 0xf9, 0xe1, 0x1b, 0x9f, 0x72, 0xd2, 0x6a, 0x73, 0xd2, 0x0c, 0x66, 0xd4, 0x24, 0x3f, 0x0b, 0x28, 0xea, 0xc2, 0xa6, 0x0d, 0xd6, 0x78, 0xa6, 0xd5, 0x26, 0xd5, 0x33, 0x58, 0xd6, 0x83, 0xf3, 0x5f, 0x67, 0x05, 0xeb, 0x93, 0xc1, 0x6f, 0xb7, 0x03, 0xfe, 0xd2, 0x77]),
    // record[32]: index=33, FirmwareConfiguration
    (33, &[0x59, 0xb1, 0x68, 0x61, 0xe0, 0xbb, 0x35, 0x91, 0x83, 0x77, 0x52, 0xac, 0x7b, 0x13, 0x79, 0xeb, 0xf5, 0x29, 0x27, 0x84, 0xe1, 0xe1, 0xa9, 0x8a, 0x3c, 0x80, 0xd6, 0xba, 0xa0, 0xf5, 0xe1, 0x9f, 0xb1, 0x07, 0xd0, 0x43, 0x67, 0xd2, 0xbb, 0xba, 0x4c, 0x87, 0x09, 0x71, 0x3d, 0x0f, 0x17, 0x55]),
    // record[33]: index=34, FirmwareConfiguration
    (34, &[0xe0, 0x1f, 0xbc, 0xd6, 0xe3, 0x0d, 0x03, 0xbd, 0x36, 0x35, 0x9c, 0xcd, 0xa4, 0x31, 0xa1, 0xb8, 0x54, 0xaa, 0xd3, 0x8f, 0x11, 0x79, 0xe9, 0xda, 0xef, 0x3f, 0xf5, 0x08, 0xd7, 0x89, 0xe1, 0x05, 0x94, 0x1e, 0x31, 0xb3, 0xd0, 0x62, 0xc2, 0x95, 0xb0, 0x16, 0x1a, 0x4f, 0xf4, 0xb9, 0x9f, 0x62]),
    // record[34]: index=35, FirmwareConfiguration
    (35, &[0xc9, 0x21, 0x56, 0xc3, 0xdf, 0x70, 0xf5, 0xb4, 0x49, 0xbe, 0x8c, 0xbb, 0x2a, 0xa3, 0x8b, 0xc1, 0x7e, 0x71, 0xa4, 0xbb, 0x21, 0x91, 0xf0, 0x65, 0x0c, 0xeb, 0xf8, 0x04, 0xe6, 0x10, 0xc1, 0x6c, 0x84, 0xd7, 0x89, 0x96, 0xe1, 0x58, 0xb8, 0x02, 0xfb, 0xe6, 0xa8, 0xf0, 0xa4, 0xda, 0x1d, 0x6a]),
    // record[35]: index=36, HardwareConfiguration
    (36, &[0x78, 0x95, 0x57, 0xbc, 0x15, 0xd9, 0x9a, 0x66, 0xd2, 0x49, 0xa7, 0x87, 0xbb, 0x51, 0xbf, 0x16, 0xb0, 0x6f, 0xfd, 0x6f, 0x41, 0xc9, 0x69, 0x55, 0xb1, 0x5f, 0x2c, 0x84, 0x22, 0xc2, 0x0c, 0x22, 0x56, 0xe4, 0xa8, 0xc7, 0x99, 0xbc, 0xa6, 0x26, 0x7a, 0x77, 0x76, 0x27, 0x07, 0xd2, 0x85, 0x5b]),
];

/// Create Manticore Authenticity CORIM with device identity and TCBInfo reference triples
#[allow(dead_code)]
fn create_manticore_auth_corim(root_thumbprint: &[u8; 48], test_case: NegativeTestCase) -> Result<CorimMap> {
    // Create identity triple with the actual root certificate thumbprint
    let identity_triple = IdentityTriple::new(
        EnvironmentMap {
            class: None,
            instance: Some(bytes_instance(b"SPDM_certificate")),
            group: None,
        },
        vec![CryptoKey::CertThumbprint(digest(
            SHA384_ALG_ID,
            root_thumbprint.as_slice(),
        ))],
        None,
    );

    // TCBInfo instance identifier: base64("TCBInfo") = "VENCSW5mbw=="
    let tcbinfo_instance = base64_engine.encode("TCBInfo");

    // Prepare FWID digests, corrupting if needed for negative test cases
    let mut layer0_fwid = MANTICORE_FWID_LAYER0;
    let mut layer1_fwid = MANTICORE_FWID_LAYER1;
    if test_case == NegativeTestCase::BadTcbInfoLayer0 {
        layer0_fwid[0] ^= 0xFF; // Flip first byte
    }
    if test_case == NegativeTestCase::BadTcbInfoLayer1 {
        layer1_fwid[0] ^= 0xFF; // Flip first byte
    }

    // Layer 0 TCBInfo reference triple (maps to cert #0 / root cert)
    let layer0_ref_triple = ReferenceTriple::new(
        EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: None,
                model: None,
                layer: Some(0),
                index: None,
            }),
            instance: Some(bytes_instance(tcbinfo_instance.as_bytes())),
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                version: Some(multipart_version("3.3.5.0-50701001")),
                svn: Some(SvnChoice::ExactValue(0)),
                digests: Some(vec![digest(SHA384_ALG_ID, layer0_fwid.as_slice())]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    );

    // Layer 1 TCBInfo reference triple (maps to cert #1 / alias cert)
    let layer1_ref_triple = ReferenceTriple::new(
        EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: None,
                model: None,
                layer: Some(1),
                index: None,
            }),
            instance: Some(bytes_instance(tcbinfo_instance.as_bytes())),
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                version: Some(multipart_version("0.0.0.0-50725215beta(X)")),
                svn: Some(SvnChoice::ExactValue(0)),
                digests: Some(vec![digest(SHA384_ALG_ID, layer1_fwid.as_slice())]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    );

    // SPDM Measurement reference triple with all 36 measurement records from the real device
    // The instance identifier must contain "SPDMMeasurement" (base64-encoded) to be
    // recognized by is_spdm_measurements_record() during validation.
    let spdm_measurement_instance = base64_engine.encode("SPDMMeasurement");

    let spdm_measurement_claims: Vec<MeasurementMap> = MANTICORE_SPDM_MEASUREMENTS
        .iter()
        .map(|(index, measurement_digest)| {
            // For BadSpdmMeasurement, corrupt measurement #1 (first byte flipped)
            let mut digest_bytes = (*measurement_digest).clone();
            if test_case == NegativeTestCase::BadSpdmMeasurement && *index == 1 {
                digest_bytes[0] ^= 0xFF;
            }
            MeasurementMap {
                mkey: Some(MeasuredElement::Uint(*index as u64)),
                mval: MeasurementValuesMap {
                    digests: Some(vec![digest(SHA384_ALG_ID, digest_bytes.as_slice())]),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }
        })
        .collect();

    let spdm_measurement_triple = ReferenceTriple::new(
        EnvironmentMap {
            class: None,
            instance: Some(bytes_instance(spdm_measurement_instance.as_bytes())),
            group: None,
        },
        spdm_measurement_claims,
    );

    // Create CoMID tag with identity triple, TCBInfo reference triples, AND SPDM measurement triple
    let comid_tag = ComidBuilder::new(TagIdChoice::Text("manticore-auth-v1".into()))
        .set_tag_version(1)
        .add_entity(EntityMap {
            entity_name: "Microsoft Corporation".into(),
            reg_id: None,
            role: vec![COMID_ROLE_TAG_CREATOR],
        })
        .add_identity_triple(identity_triple)
        .add_reference_triple(layer0_ref_triple)
        .add_reference_triple(layer1_ref_triple)
        .add_reference_triple(spdm_measurement_triple)
        .build()?;

    // Create CORIM map
    let corim_map = CorimBuilder::new(CorimId::Text("manticore-auth-corim-v1".into()))
        .add_entity(EntityMap {
            entity_name: "Microsoft Corporation".into(),
            reg_id: None,
            role: vec![CORIM_ROLE_MANIFEST_CREATOR],
        })
        .add_comid_tag(comid_tag)?
        .build()?;

    Ok(corim_map)
}

/// Create Manticore Trust CORIM with conditional endorsement series for TCBInfo layers.
///
/// For each TCBInfo layer (0 and 1), creates a conditional endorsement series triple:
///   - Condition: environment with layer + TCBInfo instance, claims with min_svn >= 0 (baseline)
///   - Series[0]: selection min_svn >= current_svn → addition tcb-status = "UpToDate"
///   - Series[1]: selection min_svn >= 0 (catch-all) → addition tcb-status = "OutOfDate"
///
/// First-match-wins semantics: if the device SVN meets the current threshold, it's UpToDate;
/// otherwise the catch-all marks it OutOfDate.
#[allow(dead_code)]
fn create_manticore_trust_corim(test_case: NegativeTestCase) -> Result<CorimMap> {
    // TCBInfo instance identifier: base64("TCBInfo") = "VENCSW5mbw=="
    let tcbinfo_instance = base64_engine.encode("TCBInfo");

    // Current SVN values from the device certs (both layers report SVN=0)
    // For negative test cases, set the UpToDate threshold unreachably high (999)
    // so the device's actual SVN=0 won't match, falling through to OutOfDate.
    let layer0_svn = if test_case == NegativeTestCase::BadTrustTcbInfoLayer0 {
        999u64
    } else {
        MSFT_LAYER0.svn
    };
    let layer1_svn = if test_case == NegativeTestCase::BadTrustTcbInfoLayer1 {
        999u64
    } else {
        MSFT_LAYER1.svn
    };
    let layer_configs: [(u64, u64); 2] = [
        (0, layer0_svn), // (layer_index, current_svn)
        (1, layer1_svn),
    ];

    let mut cond_endorsement_series = Vec::new();

    for (layer_index, current_svn) in &layer_configs {
        // Build the condition environment: class with layer, instance with TCBInfo
        let condition_env = EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: None,
                model: None,
                layer: Some(*layer_index),
                index: None,
            }),
            instance: Some(bytes_instance(tcbinfo_instance.as_bytes())),
            group: None,
        };

        // Condition claims: min_svn >= 0 (baseline - matches everything)
        let condition_claims = vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::MinValue(0)),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }];

        let condition = CesCondition {
            environment: condition_env,
            claims_list: condition_claims,
            authorized_by: None,
        };

        // Series entry 1: selection min_svn >= current_svn → UpToDate
        let up_to_date_series = ConditionalSeriesRecord::new(
            // selection: min_svn >= current_svn (e.g., >= 1)
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::MinValue(*current_svn)),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
            // addition: tcb-status = "UpToDate"
            vec![tcb_status_measurement("UpToDate")],
        );

        // Series entry 2: selection min_svn >= 0 (catch-all) → OutOfDate
        let out_of_date_series = ConditionalSeriesRecord::new(
            // selection: min_svn >= 0 (catches anything not caught above)
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::MinValue(0)),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
            // addition: tcb-status = "OutOfDate"
            vec![tcb_status_measurement("OutOfDate")],
        );

        let triple = ConditionalEndorsementSeriesTriple::new(
            condition,
            vec![up_to_date_series, out_of_date_series],
        );

        cond_endorsement_series.push(triple);
    }

    // Create CoMID tag with conditional endorsement series triples
    let mut comid_builder = ComidBuilder::new(TagIdChoice::Text("manticore-trust-v1".into()))
        .set_tag_version(1)
        .add_entity(EntityMap {
            entity_name: "Microsoft Corporation".into(),
            reg_id: None,
            role: vec![COMID_ROLE_TAG_CREATOR],
        });
    for triple in cond_endorsement_series {
        comid_builder = comid_builder.add_conditional_endorsement_series(triple);
    }
    let comid_tag = comid_builder
        .build()?;

    // Create CORIM map
    let corim_map = CorimBuilder::new(CorimId::Text("manticore-trust-corim-v1".into()))
        .add_entity(EntityMap {
            entity_name: "Microsoft Corporation".into(),
            reg_id: None,
            role: vec![CORIM_ROLE_MANIFEST_CREATOR],
        })
        .add_comid_tag(comid_tag)?
        .build()?;

    Ok(corim_map)
}

fn generate_microsoft_corim_impl() -> Result<Vec<u8>> {
    println!("[BUILD] Generating CORIM with Microsoft certificate values...");

    // Create the base64 encoded instance identifier for TCBInfo
    // "TCBInfo" -> base64 = "VENCSW5mbw=="
    let tcbinfo_instance = base64_engine.encode("TCBInfo");
    println!("  [NOTE] TCBInfo instance (base64): {}", tcbinfo_instance);

    // Create the base64 encoded instance identifier for SPDM Measurements
    // "SPDMMeasurement" -> base64
    let spdm_measurement_instance = base64_engine.encode("SPDMMeasurement");
    println!(
        "  [NOTE] SPDMMeasurement instance (base64): {}",
        spdm_measurement_instance
    );

    // Create the base64 encoded instance identifier for SPDM Certificate
    // "SPDMCertificate" -> base64
    let spdm_certificate_instance = base64_engine.encode("SPDMCertificate");
    println!(
        "  [NOTE] SPDMCertificate instance (base64): {}",
        spdm_measurement_instance
    );

    // Create the digest for FWID (use raw bytes, not base64)
    let test_l0_fwid_digest = digest(SHA384_ALG_ID, TEST_FWID_DIGEST.as_slice());
    println!(
        "  [NOTE] Test FWID digest: {}",
        hex::encode(&TEST_FWID_DIGEST)
    );

    // Integrity registers for layer 0
    let mut l0_map = BTreeMap::new();
    l0_map
        .entry(IntegrityRegisterId::Text("FW".into()))
        .or_insert(vec![digest(SHA384_ALG_ID, TEST_L0_INTREG_FW.as_slice())]);
    l0_map
        .entry(IntegrityRegisterId::Text("TC".into()))
        .or_insert(vec![digest(SHA384_ALG_ID, TEST_L0_INTREG_TC.as_slice())]);
    let test_l0_intreg = IntegrityRegisters(l0_map);

    // Create the digest for FWID layer 1 (use raw bytes, not base64)
    let test_l1_fwid_digest = digest(SHA384_ALG_ID, TEST_FWID_DIGEST_LAYER1.as_slice());
    println!(
        "  [NOTE] Test FWID Layer 1 digest: {}",
        hex::encode(&TEST_FWID_DIGEST_LAYER1)
    );

    // Create test SPDM measurement digests
    let test_measurement_1_digest = digest(SHA256_ALG_ID, TEST_SPDM_MEASUREMENT_1.as_slice());

    let test_measurement_2_digest = digest(SHA256_ALG_ID, TEST_SPDM_MEASUREMENT_2.as_slice());
    println!(
        "  [NOTE] Test SPDM measurement 1: {}",
        hex::encode(&TEST_SPDM_MEASUREMENT_1)
    );
    println!(
        "  [NOTE] Test SPDM measurement 2: {}",
        hex::encode(&TEST_SPDM_MEASUREMENT_2)
    );

    // Create version maps for Microsoft versions
    let layer0_version = multipart_version(MSFT_LAYER0.version);
    let layer1_version = multipart_version(MSFT_LAYER1.version);

    let comid = ComidBuilder::new(TagIdChoice::Text("microsoft-tdisp-layer0".into()))
        .set_tag_version(1)
        .add_entity(EntityMap {
            entity_name: "Microsoft Test Generator".into(),
            reg_id: None,
            role: vec![COMID_ROLE_TAG_CREATOR],
        })
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap {
                class: Some(ClassMap {
                    class_id: None,
                    vendor: Some(MSFT_LAYER0.vendor.into()),
                    model: Some(MSFT_LAYER0.model.into()),
                    layer: Some(MSFT_LAYER0.layer),
                    index: None,
                }),
                instance: Some(bytes_instance(tcbinfo_instance.as_bytes())),
                group: None,
            },
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    version: Some(layer0_version.clone()),
                    svn: Some(SvnChoice::ExactValue(MSFT_LAYER0.svn)),
                    digests: Some(vec![test_l0_fwid_digest]),
                    integrity_registers: Some(test_l0_intreg),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
        ))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap {
                class: Some(ClassMap {
                    class_id: None,
                    vendor: Some(MSFT_LAYER1.vendor.into()),
                    model: Some(MSFT_LAYER1.model.into()),
                    layer: Some(MSFT_LAYER1.layer),
                    index: None,
                }),
                instance: Some(bytes_instance(tcbinfo_instance.as_bytes())),
                group: None,
            },
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    version: Some(layer1_version),
                    svn: Some(SvnChoice::ExactValue(MSFT_LAYER1.svn)),
                    digests: Some(vec![test_l1_fwid_digest]),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
        ))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap {
                class: None,
                instance: Some(bytes_instance(spdm_measurement_instance.as_bytes())),
                group: None,
            },
            vec![
                MeasurementMap {
                    mkey: Some(MeasuredElement::Uint(1)),
                    mval: MeasurementValuesMap {
                        digests: Some(vec![test_measurement_1_digest]),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                },
                MeasurementMap {
                    mkey: Some(MeasuredElement::Uint(2)),
                    mval: MeasurementValuesMap {
                        digests: Some(vec![test_measurement_2_digest]),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                },
            ],
        ))
        .add_identity_triple(IdentityTriple::new(
            EnvironmentMap {
                class: None,
                instance: Some(bytes_instance(spdm_certificate_instance.as_bytes())),
                group: None,
            },
            vec![CryptoKey::CertThumbprint(digest(
                SHA384_ALG_ID,
                TEST_FWID_DIGEST_LAYER1.as_slice(),
            ))],
            None,
        ))
        .build()?;

    let corim_map = CorimBuilder::new(CorimId::Text("microsoft-tdisp-test-corim".into()))
        .add_comid_tag(comid)?
        .add_entity(EntityMap {
            entity_name: "Microsoft Test Generator".into(),
            reg_id: None,
            role: vec![CORIM_ROLE_MANIFEST_CREATOR],
        })
        .build()?;

    // Serialize to tagged CoRIM CBOR that matches the Azure decoder.
    let cbor_data = encode_corim(corim_map)?;

    println!("  [SUCCESS] Generated CORIM with {} bytes", cbor_data.len());
    println!("  [INFO] CORIM contains:");
    println!(
        "    - Layer 0: vendor={}, version={}",
        MSFT_LAYER0.vendor, MSFT_LAYER0.version
    );
    println!(
        "    - Layer 1: vendor={}, version={}",
        MSFT_LAYER1.vendor, MSFT_LAYER1.version
    );
    println!("    - Test FWID digest: {}", hex::encode(&TEST_FWID_DIGEST));
    println!(
        "    - SPDM Measurement 1: {}",
        hex::encode(&TEST_SPDM_MEASUREMENT_1)
    );
    println!(
        "    - SPDM Measurement 2: {}",
        hex::encode(&TEST_SPDM_MEASUREMENT_2)
    );

    Ok(cbor_data)
}

/// Save the generated CORIM to a file
pub fn save_microsoft_corim() -> Result<PathBuf> {
    let cbor_data = generate_microsoft_corim(None)?;

    // Get the path to save the CORIM file
    let mut output_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    output_path.push("src/tdisp/auth-corim-microsoft-generated.cbor");

    // Write the CBOR data
    fs::write(&output_path, cbor_data)?;

    println!("[SAVE] Saved Microsoft CORIM to: {}", output_path.display());

    Ok(output_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_manticore_corims_for_vtl2_settings() {
        let json = generate_tdisp_device_rims_json(NegativeTestCase::None)
            .expect("Failed to generate TdispDeviceRims JSON");

        // Validate it's real JSON
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("Output should be valid JSON");
        assert!(parsed["devices"][0]["auth_rim"].is_string());
        assert!(parsed["devices"][0]["trust_rim"].is_string());
        assert_eq!(parsed["devices"][0]["vendor_id"], MANTICORE_VENDOR_ID);
        assert_eq!(parsed["devices"][0]["device_id"], MANTICORE_DEVICE_ID);

        // Validate the base64 CORIMs are valid CBOR
        let auth_b64 = parsed["devices"][0]["auth_rim"].as_str().unwrap();
        let trust_b64 = parsed["devices"][0]["trust_rim"].as_str().unwrap();
        let auth_bytes = base64::engine::general_purpose::STANDARD
            .decode(auth_b64).expect("Failed to decode auth CORIM base64");
        let trust_bytes = base64::engine::general_purpose::STANDARD
            .decode(trust_b64).expect("Failed to decode trust CORIM base64");
        let _: cbor::value::Tagged<CorimMap> = cbor::decode(auth_bytes.as_slice())
            .expect("Auth CORIM should be valid tagged CBOR");
        let _: cbor::value::Tagged<CorimMap> = cbor::decode(trust_bytes.as_slice())
            .expect("Trust CORIM should be valid tagged CBOR");

        println!("\n{}", "=".repeat(80));
        println!("MANTICORE TDISP DEVICE RIMS JSON (positive case)");
        println!("{}\n", "=".repeat(80));
        println!("{}", json);
        println!("{}", "=".repeat(80));
    }

}

#[allow(dead_code)]
fn main() -> Result<()> {
    println!("Microsoft CORIM Generator");
    println!("========================");

    let output_path = save_microsoft_corim()?;

    println!("[COMPLETE] Successfully generated Microsoft CORIM file!");
    println!("[FILE] File: {}", output_path.display());
    println!("[TOOL] Ready for TDISP testing with Microsoft certificate values");

    Ok(())
}
