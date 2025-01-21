// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local verifier implementation for attesting TDISP devices.
//! Host passes Node BOM document to underhill, which uses it
//! as the policy for attesting devices.

mod measurement;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;

use bytes::{Buf, Bytes};
use thiserror::Error;

/*
Node BOM definitions
*/

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementValue {
    pub value_type: u8,
    pub value_size: u16,
    pub big_endian: bool,
    pub check: String,
    pub bitmask: String,
    pub value: String,
}
// Measurement entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measurement {
    //#[serde(validate(range(min = 1, max = 254)))]
    pub index: u8,
    pub name: String,
    //#[serde(validate(range(min = 0, max = 255)))]
    pub meas_blk_type: u8,
    pub size: u16,
    pub measurement_value: MeasurementValue,
}

// Main device manifest struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceManifest {
    pub vendor_id: u16,
    pub device_id: u16,
    pub device_name: String,
    pub intermediate_thumbprint: String,
    pub measurements: Vec<Measurement>,
}

impl DeviceManifest {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeManifest {
    bom_id: String,
    bom_name: String,
    bom_svn: u32,
    // TODO: Consider hash map with vid/did as key
    // device_manifest_map: HashMap<(u16, u16), DeviceManifest>,
    device_manifests: Vec<DeviceManifest>,
}

/*
SPDM definitions
*/

#[derive(Debug)]
pub struct SpdmMeasurementRequestMessage {
    spdm_version: u8,
    request_response_code: u8,
    param1: u8,
    param2: u8,
    nonce: [u8; 32],
    slot_id_param: u8,
}

impl TryFrom<&[u8]> for SpdmMeasurementRequestMessage {
    type Error = String;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut buf = Bytes::copy_from_slice(data);

        // TODO: remove hardcoded value with defined constant
        if buf.remaining() < 37 {
            // Total size: 1 + 1 + 1 + 1 + 32 + 1 = 37
            return Err("Buffer too short".to_string());
        }

        let spdm_version = buf.get_u8();
        let request_response_code = buf.get_u8();
        let param1 = buf.get_u8();
        let param2 = buf.get_u8();

        let mut nonce = [0u8; 32];
        buf.copy_to_slice(&mut nonce);

        let slot_id_param = buf.get_u8();

        if !buf.is_empty() {
            return Err(format!(
                "Something went wrong during parsing the SPDM GET MEASUREMENT request message.\n\
                 Expected length: {}, Actual length: {}",
                37,
                data.len()
            ));
        }

        Ok(SpdmMeasurementRequestMessage {
            spdm_version,
            request_response_code,
            param1,
            param2,
            nonce,
            slot_id_param,
        })
    }
}

#[derive(Debug)]
pub struct DmtfMeasurement {
    dmtf_spec_measurement_value_type: u8,
    dmtf_spec_measurement_value_size: u16,
    dmtf_spec_measurement_value: Vec<u8>,
}

impl TryFrom<&[u8]> for DmtfMeasurement {
    type Error = String;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut buf = Bytes::copy_from_slice(data);

        if buf.remaining() < 3 {
            return Err("Buffer too short".to_string());
        }

        let dmtf_spec_measurement_value_type = buf.get_u8();
        let dmtf_spec_measurement_value_size = buf.get_u16_le();

        if buf.remaining() < dmtf_spec_measurement_value_size as usize {
            return Err("Buffer too short for measurement value".to_string());
        }

        let dmtf_spec_measurement_value = buf
            .split_to(dmtf_spec_measurement_value_size as usize)
            .to_vec();

        if !buf.is_empty() {
            eprintln!("Warning: {} bytes left after parsing", buf.remaining());
        }

        Ok(DmtfMeasurement {
            dmtf_spec_measurement_value_type,
            dmtf_spec_measurement_value_size,
            dmtf_spec_measurement_value,
        })
    }
}

impl fmt::Display for DmtfMeasurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DmtfMeasurement:")?;
        write!(f, "Type: {} ", self.dmtf_spec_measurement_value_type)?;
        writeln!(f, "Size: {}", self.dmtf_spec_measurement_value_size)?;
        writeln!(
            f,
            "Value as hex string: {:?}",
            hex::encode(&self.dmtf_spec_measurement_value)
        )?;
        //writeln!(f, "Value: {:?}", self.dmtf_spec_measurement_value)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct MeasurementRecord {
    measurement_blocks: HashMap<u8, DmtfMeasurement>,
    number_of_blocks: u8,
}

impl MeasurementRecord {
    pub fn get_measurements(&self) -> HashMap<u8, String> {
        self.measurement_blocks
            .iter()
            .map(|(&index, measurement)| {
                (
                    index - 1,
                    hex::encode(&measurement.dmtf_spec_measurement_value),
                )
            })
            .collect()
    }
}

impl TryFrom<(&[u8], u8)> for MeasurementRecord {
    type Error = String;

    fn try_from((data, number_of_blocks): (&[u8], u8)) -> Result<Self, Self::Error> {
        if number_of_blocks == 0 {
            return Err("The number of blocks in the measurement record is zero.".to_string());
        }

        let mut buf = Bytes::copy_from_slice(data);
        let mut measurement_blocks = HashMap::new();

        for _ in 0..number_of_blocks {
            if buf.remaining() < 4 {
                return Err("Buffer too short for measurement block header".to_string());
            }

            let index = buf.get_u8();
            let measurement_specification = buf.get_u8();

            if measurement_specification != 1 {
                return Err("Measurement block not following DMTF specification.".to_string());
            }

            let measurement_size = buf.get_u16_le() as usize;

            if buf.remaining() < measurement_size {
                return Err("Buffer too short for measurement value".to_string());
            }

            let dmtf_measurement =
                DmtfMeasurement::try_from(buf.split_to(measurement_size).to_vec().as_slice())
                    .map_err(|e| format!("Failed to parse DMTF measurement: {}", e))?;

            measurement_blocks.insert(index, dmtf_measurement);
        }

        if !buf.is_empty() {
            return Err("Something went wrong during parsing the measurement record.".to_string());
        }

        Ok(MeasurementRecord {
            measurement_blocks,
            number_of_blocks,
        })
    }
}

impl fmt::Display for MeasurementRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "MeasurementRecord:")?;
        // print measurement_blocks in order of index
        for index in 1..=self.number_of_blocks {
            if let Some(measurement) = self.measurement_blocks.get(&(index)) {
                writeln!(f, "Measurement Index {} {}", index, measurement)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct OpaqueData {
    // TODO
}
#[derive(Debug)]
pub struct SpdmMeasurementResponseMessage {
    spdm_version: u8,
    request_response_code: u8,
    param1: u8,
    param2: u8,
    number_of_blocks: u8,
    measurement_record_length: u32,
    nonce: [u8; 32],
    opaque_length: u16,
    signature: Vec<u8>,
    measurement_record: MeasurementRecord,
    opaque_data: OpaqueData,
}

impl TryFrom<&[u8]> for SpdmMeasurementResponseMessage {
    type Error = String;

    fn try_from(response_data: &[u8]) -> Result<Self, Self::Error> {
        let mut buf = Bytes::copy_from_slice(response_data);

        if buf.remaining() < 41 {
            // Minimum size for fixed fields
            return Err("Buffer too short for fixed fields".to_string());
        }

        let spdm_version = buf.get_u8();
        let request_response_code = buf.get_u8();
        if request_response_code != 0x60 {
            return Err(format!(
                "Invalid request_response_code: 0x{:x}",
                request_response_code
            ));
        }
        let param1 = buf.get_u8();
        let param2 = buf.get_u8();
        let number_of_blocks = buf.get_u8();
        let measurement_record_length = buf.get_uint_le(3) as u32;
        let signature_length = 96; // Hardcoded for now
                                   // print all the fields

        if buf.remaining() < measurement_record_length as usize + 34 + signature_length {
            return Err("Buffer too short for variable length fields".to_string());
        }

        let raw_record = buf.split_to(measurement_record_length as usize).to_vec();
        let measurement_record =
            MeasurementRecord::try_from((raw_record.to_vec().as_slice(), number_of_blocks))
                .map_err(|e| format!("Failed to parse measurement record: {}", e))?;

        let mut nonce = [0u8; 32];
        buf.copy_to_slice(&mut nonce);

        let opaque_length = buf.get_u16_le();
        let opaque_data = OpaqueData {}; // TODO
                                         // let opaque_data = OpaqueData::try_from(buf.split_to(opaque_length as usize).as_ref())
                                         //     .map_err(|e| format!("Failed to parse opaque data: {}", e))?;

        let signature = buf.split_to(signature_length).to_vec();

        // if !buf.is_empty() {
        //     return Err(format!(
        //         "Something went wrong during parsing the SPDM GET MEASUREMENT response message.\n\
        //          Expected length: {}, Actual length: {}",
        //         response_data.len(),
        //         response_data.len() - buf.len()
        //     ));
        // }

        Ok(SpdmMeasurementResponseMessage {
            spdm_version,
            request_response_code,
            param1,
            param2,
            number_of_blocks,
            measurement_record_length,
            nonce,
            opaque_length,
            signature,
            measurement_record,
            opaque_data,
        })
    }
}

impl fmt::Display for SpdmMeasurementResponseMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\nSpdmMeasurementResponseMessage:")?;
        writeln!(f, "==================================")?;
        writeln!(f, "SPDMVersion: 0x{:x}", self.spdm_version)?;
        writeln!(f, "RequestResponseCode: 0x{:x}", self.request_response_code)?;
        // TODO: print set bitfields
        writeln!(f, "Param1: {}", self.param1)?;
        writeln!(f, "Param2: {}", self.param2)?;
        writeln!(f, "NumberOfBlocks: {}", self.number_of_blocks)?;
        writeln!(
            f,
            "MeasurementRecordLength: {}",
            self.measurement_record_length
        )?;
        writeln!(f, "{}", self.measurement_record);

        Ok(())
    }
}

struct SPDMCertificateChain {
    // TODO
}

struct SPDMDeviceInterfaceReport {
    // TODO
}

#[allow(missing_docs)] // self-explanatory fields
#[derive(Debug, Error)]
pub(crate) enum DeviceAttestationError {
    #[error("invalid data format: {0:?}")]
    InvalidFormat(usize),
}

#[allow(missing_docs)] // self-explanatory fields
#[derive(Debug, Error)]
pub(crate) enum DevicePolicyReadError {
    #[error("invalid data format: {0:?}")]
    InvalidFormat(usize),
}

#[allow(missing_docs)] // self-explanatory fields
#[derive(Debug, Error)]
pub(crate) enum NodeSBOMReadError {
    #[error("invalid data format: {0:?}")]
    InvalidFormat(usize),
}

struct DevicePolicy {
    allow_all_devices: bool,
    bom_authority: String,
    bom_name: String,
    bom_id: String,
    bom_min_svn: u32,
}

pub(crate) enum TdispVerifierState {
    Uninitialized,
    DevicePolicyAttested,
    DevicePolicyAttestedAndBOMVerified,
    Error,
}

struct TdispVerifier {
    pub node_bom: Option<NodeManifest>,
    pub device_policy: Option<DevicePolicy>,
    pub state: TdispVerifierState,
}

// make an instance of TdispVerifier

impl TdispVerifier {
    pub fn new() -> Self {
        TdispVerifier {
            node_bom: None,
            device_policy: None,
            state: TdispVerifierState::Uninitialized,
        }
    }

    pub fn get_device_policy() -> Result<DevicePolicy, DevicePolicyReadError> {
        // TODO: Implement policy retrieval logic
        Err(DevicePolicyReadError::InvalidFormat(0))
    }

    pub fn read_and_verify_node_sbom() -> Result<NodeManifest, NodeSBOMReadError> {
        //TODO: Read from host
        // Verify signature and signer
        // Check BOM svn
        Err(NodeSBOMReadError::InvalidFormat(0))
    }

    pub fn get_node_sbom() -> Result<NodeManifest, NodeSBOMReadError> {
        Err(NodeSBOMReadError::InvalidFormat(0))
    }

    pub fn attest_device(vendor_id: u16, device_id: u16) -> Result<bool, DeviceAttestationError> {
        // TODO: Implement attestation logic
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_node_manifest() {
        let node_manifest_str = r#"
        {
            "bom_id": "1234567890",
            "bom_name": "Test BOM",
            "bom_svn": 1,
            "device_manifests": [
                {
                    "vendor_id": 1,
                    "device_id": 1,
                    "device_name": "Test Device",
                    "intermediate_thumbprint": "1234567890",
                    "measurements": [
                        {
                            "index": 1,
                            "name": "Test Measurement",
                            "meas_blk_type": 1,
                            "size": 32,
                            "measurement_value": {
                                "value_type": 1,
                                "value_size": 32,
                                "big_endian": false,
                                "check": "equal",
                                "bitmask": "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                                "value": "0x"
                            }
                         }
                    ]
                }
            ]
        }"#;

        let node_manifest: NodeManifest = serde_json::from_str(node_manifest_str).unwrap();
        println!("{:?}", node_manifest);
    }
}
