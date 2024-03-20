use std::fmt::Display;

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, Result};
use binary_reader::{BinaryReader, Endian};
use chrono::{NaiveDate, NaiveDateTime};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const ICF_KEY: [u8; 16] = hex_literal::decode(&[env!("SAEKAWA_ICF_KEY").as_bytes()]);
const ICF_IV: [u8; 16] = hex_literal::decode(&[env!("SAEKAWA_ICF_IV").as_bytes()]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u16,
    pub minor: u8,
    pub build: u8,
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:0>2}.{:0>2}", self.major, self.minor, self.build)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcfInnerData {
    pub id: String,
    pub version: Version,
    pub required_system_version: Version,
    pub datetime: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcfPatchData {
    pub id: String,
    pub source_version: Version,
    pub target_version: Version,
    pub required_system_version: Version,
    pub datetime: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcfData {
    System(IcfInnerData),
    App(IcfInnerData),
    Patch(IcfPatchData),
    Option(IcfInnerData),
}

fn decrypt_icf(data: &mut [u8], key: impl AsRef<[u8]>, iv: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    let size = data.len();

    let mut decrypted = Vec::with_capacity(size);

    for i in (0..size).step_by(4096) {
        let from_start = i;

        let bufsz = std::cmp::min(4096, size - from_start);
        let buf = &data[i..i + bufsz];
        let mut decbuf = vec![0; bufsz];

        let cipher = Aes128CbcDec::new_from_slices(key.as_ref(), iv.as_ref())?;
        cipher
            .decrypt_padded_b2b_mut::<NoPadding>(buf, &mut decbuf)
            .map_err(|err| anyhow!(err))?;

        let xor1 = u64::from_le_bytes(decbuf[0..8].try_into()?) ^ (from_start as u64);
        let xor2 = u64::from_le_bytes(decbuf[8..16].try_into()?) ^ (from_start as u64);

        decrypted.extend(xor1.to_le_bytes());
        decrypted.extend(xor2.to_le_bytes());
        decrypted.extend(&decbuf[16..]);
    }

    Ok(decrypted)
}

pub fn decode_icf_container_data(
    rd: &mut BinaryReader,
) -> Result<(Version, NaiveDateTime, Version)> {
    let version = Version {
        build: rd.read_u8()?,
        minor: rd.read_u8()?,
        major: rd.read_u16()?,
    };

    let datetime = NaiveDate::from_ymd_opt(
        rd.read_i16()? as i32,
        rd.read_u8()? as u32,
        rd.read_u8()? as u32,
    )
    .ok_or(anyhow!("Invalid date"))?
    .and_hms_milli_opt(
        rd.read_u8()? as u32,
        rd.read_u8()? as u32,
        rd.read_u8()? as u32,
        rd.read_u8()? as u32,
    )
    .ok_or(anyhow!("Invalid time"))?;

    let required_system_version = Version {
        build: rd.read_u8()?,
        minor: rd.read_u8()?,
        major: rd.read_u16()?,
    };

    Ok((version, datetime, required_system_version))
}

pub fn decode_icf(data: &mut [u8]) -> Result<Vec<IcfData>> {
    let decrypted = decrypt_icf(data, ICF_KEY, ICF_IV)?;

    let mut rd = BinaryReader::from_vec(&decrypted);
    rd.endian = Endian::Little;

    let checksum = crc32fast::hash(&decrypted[4..]);
    let reported_crc = rd.read_u32()?;
    if reported_crc != checksum {
        return Err(anyhow!(
            "Reported CRC32 ({reported_crc:02X}) does not match actual checksum ({checksum:02X})"
        ));
    }

    let reported_size = rd.read_u32()? as usize;
    let actual_size = decrypted.len();
    if actual_size != reported_size {
        return Err(anyhow!(
            "Reported size {reported_size} does not match actual size {actual_size}"
        ));
    }

    let padding = rd.read_u64()?;
    if padding != 0 {
        return Err(anyhow!("Padding error. Expected 8 NULL bytes."));
    }

    let entry_count: usize = rd.read_u64()?.try_into()?;
    let expected_size = 0x40 * (entry_count + 1);
    if actual_size != expected_size {
        return Err(anyhow!("Expected size {expected_size} ({entry_count} entries) does not match actual size {actual_size}"));
    }

    let app_id = String::from_utf8(rd.read_bytes(4)?.to_vec())?;
    let platform_id = String::from_utf8(rd.read_bytes(3)?.to_vec())?;
    let _platform_generation = rd.read_u8()?;

    let reported_crc = rd.read_u32()?;
    let mut checksum = 0;
    for i in 1..=entry_count {
        let container = &decrypted[0x40 * i..0x40 * (i + 1)];
        if container[0] == 2 && container[1] == 1 {
            checksum ^= crc32fast::hash(container);
        }
    }

    if reported_crc != checksum {
        return Err(anyhow!("Reported container CRC32 ({reported_crc:02X}) does not match actual checksum ({checksum:02X})"));
    }

    for _ in 0..7 {
        if rd.read_u32()? != 0 {
            return Err(anyhow!("Padding error. Expected 28 NULL bytes."));
        }
    }

    let mut entries: Vec<IcfData> = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let sig = rd.read_u32()?;

        if sig != 0x0102 && sig != 0x0201 {
            return Err(anyhow!("Container does not start with signature (0x0102)"));
        }

        let container_type = rd.read_u32()?;
        for _ in 0..3 {
            if rd.read_u64()? != 0 {
                return Err(anyhow!("Padding error. Expected 24 NULL bytes."));
            }
        }

        let data: IcfData = match container_type {
            0x0000 | 0x0001 | 0x0002 => {
                for _ in 0..2 {
                    if rd.read_u64()? != 0 {
                        return Err(anyhow!("Padding error. Expected 16 NULL bytes."));
                    }
                }

                let (version, datetime, required_system_version) = decode_icf_container_data(&mut rd)?;

                match container_type {
                    0x0000 => IcfData::System(IcfInnerData {
                        id: platform_id.clone(),
                        version,
                        datetime,
                        required_system_version,
                    }),
                    0x0001 => IcfData::App(IcfInnerData {
                        id: app_id.clone(),
                        version,
                        datetime,
                        required_system_version,
                    }),
                    0x0002 => IcfData::Option(IcfInnerData {
                        id: app_id.clone(),
                        version,
                        datetime,
                        required_system_version,
                    }),
                    _ => unreachable!(),
                }
            }
            _ => {
                // PATCH container type also encode the patch's sequence number
                // in the higher 16 bits.
                // The lower 16 bits will always be 1.
                let sequence_number = (container_type >> 8) as u8;

                if (container_type & 1) == 0 || sequence_number == 0 {
                    println!("Unknown ICF container type {container_type:#06x} at byte {:#06x}, skipping", rd.pos);
                    rd.read_bytes(32)?;
                    continue;
                }

                let (target_version, target_datetime, _) = decode_icf_container_data(&mut rd)?;
                let (source_version, _, source_required_system_version) = decode_icf_container_data(&mut rd)?;

                IcfData::Patch(IcfPatchData {
                    id: app_id.clone(),
                    source_version,
                    target_version,
                    required_system_version: source_required_system_version,          
                    datetime: target_datetime,          
                })
            }
        };

        entries.push(data);
    }

    Ok(entries)
}
