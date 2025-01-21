// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt;
//use zerocopy::ByteOrder;
//use zerocopy::LittleEndian;

#[derive(PartialEq, Eq)]
pub struct MEASUREMENTS {
    pub spdmversion: u8,
    pub request_response_code: u8,
    pub param1: u8,
    pub param2: u8,
    pub number_of_blocks: u8,
    pub measurement_record_length: u32, // This field size is 3 bytes
    pub measurement_record_data: Vec<u8>,
    pub nonce: [u8; 32],
    pub opaque_data_length: u16,
    pub opaque_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl MEASUREMENTS {
    // Constructor method to create an empty MEASUREMENTS struct
    pub fn new() -> Self {
        MEASUREMENTS {
            spdmversion: 0,
            request_response_code: 0,
            param1: 0,
            param2: 0,
            number_of_blocks: 0,
            measurement_record_length: 0,
            measurement_record_data: Vec::new(),
            nonce: [0u8; 32],
            opaque_data_length: 0,
            opaque_data: Vec::new(),
            signature: Vec::new(),
        }
    }
}

impl fmt::Debug for MEASUREMENTS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MEASUREMENTS")
            .field("spdmversion", &format_args!("{:02X}", self.spdmversion))
            .field(
                "request_response_code",
                &format_args!("{:02X}", self.request_response_code),
            )
            .field("param1", &format_args!("{:02X}", self.param1))
            .field("param2", &format_args!("{:02X}", self.param2))
            .field(
                "number_of_blocks",
                &format_args!("{:02X}", self.number_of_blocks),
            )
            .field(
                "measurement_record_length",
                &format_args!("{:06X}", self.measurement_record_length),
            )
            .field(
                "measurement_record_data",
                &self
                    .measurement_record_data
                    .iter()
                    .map(|byte| format!("{:02X}", byte))
                    .collect::<Vec<String>>(),
            )
            .field(
                "nonce",
                &self
                    .nonce
                    .iter()
                    .map(|byte| format!("{:02X}", byte))
                    .collect::<Vec<String>>(),
            )
            .field(
                "opaque_data_length",
                &format_args!("{:04X}", self.opaque_data_length),
            )
            .field(
                "opaque_data",
                &self
                    .opaque_data
                    .iter()
                    .map(|byte| format!("{:02X}", byte))
                    .collect::<Vec<String>>(),
            )
            .field(
                "signature",
                &self
                    .signature
                    .iter()
                    .map(|byte| format!("{:02X}", byte))
                    .collect::<Vec<String>>(),
            )
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct MeasurementBlockFormat {
    pub index: u8,
    pub measurement_specification: u8,
    pub measurement_size: u16,
    pub measurement: Vec<u8>,
}

impl MeasurementBlockFormat {
    // Constructor method to create an empty MeasurementBlockFormat struct
    pub fn new() -> Self {
        MeasurementBlockFormat {
            index: 0,
            measurement_specification: 0,
            measurement_size: 0,
            measurement: Vec::new(),
        }
    }
}

impl fmt::Debug for MeasurementBlockFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeasurementBlockFormat")
            .field("index", &format_args!("{:02X}", self.index))
            .field(
                "measurement_specification",
                &format_args!("{:02X}", self.measurement_specification),
            )
            .field(
                "measurement_size",
                &format_args!("{:04X}", self.measurement_size),
            )
            .field(
                "measurement",
                &self
                    .measurement
                    .iter()
                    .map(|byte| format!("{:02X}", byte))
                    .collect::<Vec<String>>(),
            )
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct DmtfMeasrurementSpecFormat {
    pub dmtf_spec_measurement_value_type: u8,
    pub dmtf_spec_measurement_value_size: u16,
    pub dmtf_spec_measurement_value: Vec<u8>,
}

impl DmtfMeasrurementSpecFormat {
    // Constructor method to create an empty DmtfMeasrurementSpecFormat struct
    pub fn new() -> Self {
        DmtfMeasrurementSpecFormat {
            dmtf_spec_measurement_value_type: 0,
            dmtf_spec_measurement_value_size: 0,
            dmtf_spec_measurement_value: Vec::new(),
        }
    }
}

impl fmt::Debug for DmtfMeasrurementSpecFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DmtfMeasrurementSpecFormat")
            .field(
                "dmtf_spec_measurement_value_type",
                &format_args!("{:02X}", self.dmtf_spec_measurement_value_type),
            )
            .field(
                "dmtf_spec_measurement_value_size",
                &format_args!("{:04X}", self.dmtf_spec_measurement_value_size),
            )
            .field(
                "dmtf_spec_measurement_value",
                &self
                    .dmtf_spec_measurement_value
                    .iter()
                    .map(|byte| format!("{:02X}", byte))
                    .collect::<Vec<String>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null;

    #[test]
    fn test_measurement() {
        let (dmtf_measurements, measurement_blocks) = parse_manticore_measurement();

        for dmtf_meas in dmtf_measurements {
            println!(
                "{:?}",
                parse_dmtf_spec_measurement_value_type(dmtf_meas.dmtf_spec_measurement_value_type)
            );
            println!("{:?}", dmtf_meas);
            println!();
        }
    }

    fn parse_manticore_measurement(
    ) -> (Vec<DmtfMeasrurementSpecFormat>, Vec<MeasurementBlockFormat>) {
        let measurement_str = manticore_raw_measurement();

        let hex_values: Vec<u8> = measurement_str
            .lines()
            .filter_map(|line| u32::from_str_radix(line.trim_start_matches("0x"), 16).ok())
            .flat_map(|value| value.to_be_bytes().to_vec())
            .collect();

        let mut measurements_byte_offset = 0;

        let mut measurements = MEASUREMENTS::new();

        measurements.spdmversion = hex_values[idx(measurements_byte_offset)];
        measurements_byte_offset += 1;

        measurements.request_response_code = hex_values[idx(measurements_byte_offset)];
        measurements_byte_offset += 1;

        measurements.param1 = hex_values[idx(measurements_byte_offset)];
        measurements_byte_offset += 1;

        measurements.param2 = hex_values[idx(measurements_byte_offset)];
        measurements_byte_offset += 1;

        measurements.number_of_blocks = hex_values[idx(measurements_byte_offset)];
        measurements_byte_offset += 1;

        measurements.measurement_record_length = (hex_values[idx(measurements_byte_offset)] as u32)
            | ((hex_values[idx(measurements_byte_offset + 1)] as u32) << 8)
            | ((hex_values[idx(measurements_byte_offset + 2)] as u32) << 16);
        measurements_byte_offset += 3;

        measurements.measurement_record_data = hex_values[measurements_byte_offset
            ..measurements_byte_offset + (measurements.measurement_record_length as usize)]
            .to_vec();
        measurements_byte_offset += (measurements.measurement_record_length as usize);

        for i in 0..32 {
            measurements.nonce[i] = hex_values[measurements_byte_offset + i];
        }
        measurements_byte_offset += 32;

        measurements.opaque_data_length = (hex_values[idx(measurements_byte_offset)] as u16)
            | ((hex_values[idx(measurements_byte_offset + 1)] as u16) << 8);
        measurements_byte_offset += 2;

        measurements.opaque_data = hex_values[measurements_byte_offset
            ..measurements_byte_offset + (measurements.opaque_data_length as usize)]
            .to_vec();
        measurements_byte_offset += measurements.opaque_data_length as usize;

        // println!("{:?}", measurements);

        let mut measurement_index = 0;
        let mut dmtf_index = 0;

        let mut measurement_blocks: Vec<MeasurementBlockFormat> = Vec::new();
        let mut dmtf_measurements: Vec<DmtfMeasrurementSpecFormat> = Vec::new();

        for i in 0..measurements.number_of_blocks {
            let mut block = MeasurementBlockFormat::new();

            block.index = measurements.measurement_record_data[idx(measurement_index)];
            measurement_index += 1;

            block.measurement_specification =
                measurements.measurement_record_data[idx(measurement_index)];
            measurement_index += 1;

            block.measurement_size = (measurements.measurement_record_data[idx(measurement_index)]
                as u16)
                | ((measurements.measurement_record_data[idx(measurement_index + 1)] as u16) << 8);
            measurement_index += 2;

            for j in 0..(block.measurement_size as usize) {
                block
                    .measurement
                    .push(measurements.measurement_record_data[idx(measurement_index)]);
                measurement_index += 1;
            }

            let mut dmtf_block = DmtfMeasrurementSpecFormat::new();
            dmtf_index = 0;

            dmtf_block.dmtf_spec_measurement_value_type = block.measurement[dmtf_index];
            dmtf_index += 1;

            dmtf_block.dmtf_spec_measurement_value_size = (block.measurement[dmtf_index] as u16)
                | ((block.measurement[dmtf_index + 1] as u16) << 8);
            dmtf_index += 2;

            dmtf_block.dmtf_spec_measurement_value = block.measurement
                [dmtf_index..(dmtf_index + (dmtf_block.dmtf_spec_measurement_value_size as usize))]
                .to_vec();

            dmtf_measurements.push(dmtf_block);
            measurement_blocks.push(block);
        }

        (dmtf_measurements, measurement_blocks)
    }

    fn idx(byte_idx: usize) -> usize {
        4 * (byte_idx / 4) + 3 - (byte_idx % 4)
    }

    fn parse_dmtf_spec_measurement_value_type(value: u8) -> String {
        let str = match (value >> 1) {
            0x00 => "Immutable ROM",
            0x01 => "Mutable FW",
            0x02 => "HW configuration",
            0x03 => "FW configuration",
            0x04 => "Measurement Manifest",
            0x05 => "Debug & device mode",
            0x06 => "Mutable FW's VN",
            0x07 => "Mutable FW's SVN",
            _ => "Unknown",
        };

        let str_repres = match (value & 0x1) {
            0x00 => "Digest",
            0x01 => "Raw bitstream",
            _ => "Unknown",
        };

        format!("{} ({})", str, str_repres)
    }

    fn manticore_raw_measurement() -> String {
        let measurement_str = r#"
0x00006012
0x0007bc24
0x00330101
0xe6003002
0x194f4dd1
0x48743480
0x0162513f
0xf122b8d8
0xcfd0f10f
0x945c990f
0xc29ac76b
0xb3ad3b64
0x2ac799f0
0xa33f51d8
0x0e841ef8
0x025acff5
0x02003301
0x2fbf0030
0xe92064dd
0xaec44d63
0x00b8d012
0x05ab7c09
0x88b66846
0x9b13030f
0xab4548ae
0x8264490d
0x9681dec3
0x95628fb0
0x3fadab7f
0x01031f4a
0x30020033
0x055cd800
0xf48832fe
0xbc6fdeca
0xea8982ec
0x818b6a00
0xed938209
0x22b09992
0x2abfe4c4
0x06693581
0x2305d729
0x98c89a87
0x834de63a
0x330104ae
0x00300200
0xb50d632e
0xd78ef722
0xac5b025f
0x90550b8e
0x8a7d0fd7
0x76dc79f8
0x25f789a2
0x28a0e912
0x86094dee
0x7b71d315
0xcab1e619
0x4aee9836
0x00330105
0x6d003003
0x28d59ec9
0x620482c5
0xd2e6e593
0x9f44c7a6
0x4790933d
0x59b35e69
0x081b7ba8
0x2609b503
0xe2eda3e9
0x03365e08
0x7a5f83d7
0x0631f0bf
0x03003301
0xf0350030
0xb7557308
0xc927c87c
0x1133632c
0x26a75e1f
0x74676966
0x65d12d4b
0x97204f35
0xf29b843f
0x178f8f66
0x1a96a691
0xc29dcb7a
0x01076f2f
0x30010033
0x92948800
0xdb51cee2
0xfe40d04c
0xe9e486e0
0xe3d14273
0xa396a5be
0x91cc24a6
0x42176665
0x3ce6fd24
0xd6a245c0
0x34da464c
0xf2a7c71e
0x330108e8
0x00300100
0xdcad7341
0xae57382c
0xf4d33b06
0xd8feab08
0xc7edc786
0x7f0a8424
0x8897f91d
0xbe358883
0x5dbf29be
0x8760bbe3
0xb3092b36
0xa955bf4f
0x00330109
0x9d003001
0x9c6b82f0
0xb03a42d0
0x15ee1ab5
0xcc0752b0
0x3827f15f
0xa47d3296
0x9e9a512b
0x64e1f811
0xae4c1c62
0x47f89480
0xd377fd14
0x0a8b3ec2
0x03003301
0x1b480030
0xc1e0b91f
0xb681fe34
0x314611fa
0x85391817
0x943a9c29
0xee38e3c7
0x0e9d91aa
0x6766ce4d
0xc546d82f
0x03818b0f
0x2c662729
0x010b21fb
0x30030033
0xe1de6200
0x67fd715c
0xd90c7034
0x8073d859
0x5afd82dd
0xc0ea9b38
0x726230db
0xd4b347e0
0x9f19c7c6
0x619d0d71
0xd08f8d96
0xc8613fc6
0x33010c3b
0x00300300
0x9e06e891
0x5567eb7e
0x0737cbdb
0x0a0b6800
0x2e280c20
0x692fb08b
0xc4be78a8
0x4f1e7817
0x3ced7145
0xde1a1d4c
0xc5c3ff9c
0xa2f3dd4d
0x0033010d
0x32003003
0x694c1577
0x1cd069f1
0x4a860a5d
0x6a0f607e
0x8ba4f6ef
0x9b31d2ad
0xcb073006
0xa46b2a4f
0x7e4ea236
0x267822fa
0xea68721b
0x0ebe5b02
0x01003301
0x91b10030
0x9a8e3ee6
0x9c437201
0x0088d244
0xb6711a9e
0x3ac8a375
0xeaffc556
0x42e08a5e
0x9d172e56
0x98bee4d5
0x4f581e6a
0xb936ba6a
0x010fac0d
0x30010033
0x22242600
0xb58d3026
0x8d58ce76
0x3ff66875
0x0068e6a0
0x7c455450
0xc2a33760
0x61b45b5e
0x354e0dd6
0x2c4c9ac9
0x60665717
0xa0bd3ae9
0x33011044
0x00300100
0x3fe84084
0x73f42047
0xe9132b6a
0xad46f84c
0xa3bd362c
0x4847a45a
0x1291cca6
0x2ef66f49
0x744611c0
0x3443e707
0x9dc17032
0xae19a0fb
0x00330111
0x27003002
0xcf5b4847
0x7a81ab62
0x640b72a1
0x422e2a01
0xfd5a78af
0x0d3e3cf7
0x2d0a44db
0x3bd1bf57
0x0e92b235
0x8468ea38
0xe730a0f7
0x12c2a549
0x02003301
0x92c00030
0xf3c486e4
0x0270990c
0x4fdd8d91
0x6ba06b6f
0xddd50a55
0x7a961375
0x24f01727
0x7dbd66a4
0xfaad3bd9
0xb1d7e4bf
0xccc260ce
0x01132158
0x30030033
0xa9482500
0x4875f1e3
0x9f8ed40f
0xf8fe08b4
0x15e147d8
0xc9cf09fd
0x7ce4e096
0x51241ceb
0x9d010ab4
0x1caa4d23
0x3abeb7b1
0x185bda67
0x330114dc
0x00300300
0xdca8ae1e
0xb6354893
0xd7863e33
0xb90b97fe
0x95a92c14
0x39b26110
0x05a1cfc9
0x6173aea1
0xec31d6ea
0xd4819705
0x40a6cc2d
0x9c86778e
0x00330115
0xc6003003
0x06ee108e
0x26dd2ee8
0x04adeeec
0x4fbe019d
0x1a36465c
0x187c5b4b
0xd2991631
0x1f63ec81
0x6a2d28bc
0x45205cbc
0x56d1148c
0x165d0546
0x01003301
0xdcc00030
0xa011d6ab
0x7c2adef5
0xf2686a6a
0x197f2ee7
0x761a7b33
0xf1a620a1
0xa9bc90c9
0xed6bc7d9
0xcef25b44
0xe4048c99
0x45f41697
0x011747c7
0x30010033
0xa8ffbe00
0x2d2dacf2
0x0ad1968d
0x06ba7b0a
0x578ce137
0x40c5c113
0x0ea00a4d
0xcd74e596
0x0d47e5b4
0x21911e36
0x4866f0bf
0x6ca64879
0x330118eb
0x00300100
0xb6ce46a8
0x486450d3
0x80bcf52c
0x5c387400
0x92e5c87c
0xd564129f
0x430cf4ff
0xe1b8dc7d
0xe98c0636
0xf7277f08
0xa2c0eb70
0x231a6fd3
0x00330119
0x0e003001
0x1a641f01
0x078f8eef
0xefeb3d22
0xd8cc1ec7
0x1bc91e56
0xe4affb59
0xf762cf43
0x2ad1621d
0x63c7fc88
0x8d33853b
0xace8e1e3
0x1afecf7d
0x01003301
0x58ae0030
0xda1ae606
0x9404263e
0x52209fb7
0x7579ed82
0x3d5ec8c3
0xe7b73cca
0xbcb81d32
0x2fb3afaa
0xba7437e5
0x91052dc2
0x62c45358
0x011bcb31
0x30010033
0x533e0700
0x33102293
0x76ebb30d
0x9881f720
0xa451e707
0xd2d61976
0x13e31eb5
0xa271dc06
0x564616b6
0x5ce3754e
0x9b42f0ae
0xfcb71885
0x33011c09
0x00300100
0xccba5bc2
0x5a064b18
0x633a3357
0x1dc5987c
0x59919eda
0x4abba3f7
0xce079087
0x9a81e8a7
0xee8141a5
0x0d19ba2c
0xe8a7f198
0xe9655c6e
0x0033011d
0xe7003003
0x049c33c0
0xec0d17de
0x625285ca
0xeebdfc05
0x7f86b90c
0x9edb7001
0xc179b191
0x41a8b8b6
0xbcb74269
0x54d101b9
0x4738cb94
0x1e314e39
0x03003301
0x7a120030
0x71ca4772
0xf6d15cdc
0x6310ee27
0x3c59ef98
0x0e59759b
0x747955ba
0xa9448087
0xb8b7e0be
0xf425c411
0x7ef1ee4d
0x3e7d3808
0x011f8c31
0x30030033
0x98110900
0x507e9a34
0x851a3568
0xb245ec32
0xe10da684
0xe2e6de22
0xe160d76c
0x4e0845bd
0xbb4f2d56
0xdaa8ff91
0xaa6b56e5
0x677d28ab
0x330120d4
0x00300300
0x0f8c586b
0x1be1f9a2
0x6ad2729f
0x660cd273
0x0b3f24d4
0xa6c2ea28
0xa678d60d
0x33d526d5
0xf383d658
0xeb05675f
0xb76fc193
0x77d2fe03
0x00330121
0x59003003
0xe06168b1
0x839135bb
0x7bac5277
0xf5eb7913
0xe1842729
0x3c8aa9e1
0xa0bad680
0xb19fe1f5
0x6743d007
0x4cbabbd2
0x3d710987
0x2255170f
0x03003301
0x1fe00030
0x0de3d6bc
0x3536bd03
0x31a4cd9c
0xaa54b8a1
0x79118fd3
0x3fefdae9
0x89d708f5
0x1e9405e1
0x62d0b331
0x16b095c2
0xb9f44f1a
0x0123629f
0x30030033
0x5621c900
0xf570dfc3
0x8cbe49b4
0x8ba32abb
0xa4717ec1
0xf09121bb
0xf8eb0c65
0xc110e604
0x89d7846c
0xb858e196
0xa8e6fb02
0x1ddaa4f0
0x3301246a
0x00300200
0xbc579578
0x669ad915
0x87a749d2
0x16bf51bb
0x6ffd6fb0
0x5569c941
0x842c5fb1
0x220cc222
0xc7a8e456
0x26a6bc99
0x2776777a
0x5b85d207
0xff22dc23
0x7d537c25
0xed7b7602
0x8b913ac9
0x3bd171fe
0x96cdac2d
0x9ab64180
0xbcb5dde7
0x9ffc0000
0xaa384c3b
0x63ae196f
0x216c03ba
0x7015a2ce
0x5006f8f0
0x8c55fde4
0xae6e597e
0xb7d7d736
0xdc13b267
0xd9f250fa
0x1c87d8df
0x4ee96691
0x38146f0d
0x70f4f2f0
0xce6b197e
0xc9a8c838
0xc6ecdc54
0x08d0ae5e
0x201792e2
0x735fc239
0xc53cff03
0x733e0fdc
0x94c73d92
0x000066fd
"#;

        measurement_str.to_string()
    }
}
