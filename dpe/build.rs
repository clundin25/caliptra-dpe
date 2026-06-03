// Licensed under the Apache-2.0 license

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

// Mock types and modules expected by x509_generator.rs

pub use caliptra_dpe_types::DpeProfile;
pub mod tci {
    pub use caliptra_dpe_types::{TciMeasurement, TciNodeData};
    pub const TCI_SIZE: usize = caliptra_dpe_types::TCI_SIZE;
}
pub mod response {
    pub use caliptra_dpe_types::DpeErrorCode;
}

#[inline(always)]
pub(crate) fn okref<T, E: Copy>(r: &Result<T, E>) -> Result<&T, E> {
    match r {
        Ok(r) => Ok(r),
        Err(e) => Err(*e),
    }
}

// Include the generator code
#[allow(dead_code)]
mod x509_gen {
    include!("x509_generator.rs");
}

use arrayvec::ArrayVec;
#[cfg(feature = "ml-dsa")]
use caliptra_dpe_crypto::ml_dsa::MldsaPublicKey;
use caliptra_dpe_crypto::{ecdsa::EcdsaPubKey, PubKey};
use caliptra_dpe_platform::CertValidity;
use x509_gen::{CertWriter, DirectoryString, MeasurementData, Name};

struct Offsets {
    pubkey: usize,
    serial: usize,
    not_before: usize,
    not_after: usize,
    skid: Option<usize>,
    akid: usize,
    subject_sn: usize,
    explicit_tag: usize,
    sequence_tag: usize,
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn generate_template(profile: DpeProfile, is_ca: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>, Offsets) {
    let mut buf = vec![0u8; 16384]; // Large enough for ML-DSA
    let mut writer = CertWriter::new(&mut buf, profile, false);

    let serial_number = [0x11u8; 20];

    #[allow(unreachable_patterns)]
    let issuer_cn: &[u8] = match profile {
        DpeProfile::P256Sha256 => b"Caliptra 2.1 Ecc256 Rt Alias",
        DpeProfile::P384Sha384 => b"Caliptra 2.1 Ecc384 Rt Alias",
        #[cfg(feature = "ml-dsa")]
        DpeProfile::Mldsa87 => b"Caliptra 2.1 MlDsa87 Rt Alias",
        _ => panic!("Unsupported profile"),
    };
    let dummy_issuer_sn = [0x44u8; 64]; // '4' repeated 64 times
    let issuer_rdn_name = Name {
        cn: DirectoryString::Utf8String(issuer_cn),
        serial: DirectoryString::PrintableString(&dummy_issuer_sn),
    };
    let mut issuer_buf = [0u8; 256];
    let mut issuer_writer = CertWriter::new(&mut issuer_buf, profile, false);
    let issuer_len = issuer_writer.encode_rdn(&issuer_rdn_name).unwrap();
    let issuer_name = &issuer_buf[..issuer_len];

    let dummy_subject_sn = [0x35u8; 64]; // '5' repeated 64 times
    let subject_cn: &[u8] = if is_ca {
        b"DPE Exported CDI"
    } else {
        b"DPE Leaf"
    };
    let subject_name = Name {
        cn: DirectoryString::PrintableString(subject_cn),
        serial: DirectoryString::PrintableString(&dummy_subject_sn),
    };

    #[allow(unreachable_patterns)]
    let pubkey = match profile {
        DpeProfile::P256Sha256 => {
            let x = [0x22u8; 32];
            let y = [0x33u8; 32];
            PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(
                caliptra_dpe_crypto::ecdsa::curve_256::EcdsaPub256::from_slice(&x, &y),
            ))
        }
        DpeProfile::P384Sha384 => {
            let x = [0x22u8; 48];
            let y = [0x33u8; 48];
            PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(
                caliptra_dpe_crypto::ecdsa::EcdsaPub::from_slice(&x, &y),
            ))
        }
        DpeProfile::Mldsa87 => {
            #[cfg(feature = "ml-dsa")]
            {
                let bytes = [0x22u8; 2592];
                PubKey::Mldsa(MldsaPublicKey::from_slice(&bytes))
            }
            #[cfg(not(feature = "ml-dsa"))]
            panic!("ML-DSA not enabled in build script but requested")
        }
        _ => panic!("Unsupported profile"),
    };

    let tci_node = tci::TciNodeData {
        tci_type: 0,
        tci_cumulative: tci::TciMeasurement([0xaa; tci::TCI_SIZE]),
        tci_current: tci::TciMeasurement([0xbb; tci::TCI_SIZE]),
        locality: 0,
        svn: 1,
    };
    let tci_nodes = [tci_node, tci_node, tci_node];

    let mut validity_not_before = ArrayVec::new();
    validity_not_before
        .try_extend_from_slice(b"20260101000000Z")
        .unwrap();
    let mut validity_not_after = ArrayVec::new();
    validity_not_after
        .try_extend_from_slice(b"20261231235959Z")
        .unwrap();

    let validity = CertValidity {
        not_before: validity_not_before,
        not_after: validity_not_after,
    };

    let measurements = MeasurementData {
        label: &[0xcc; 17],
        tci_nodes: &tci_nodes,
        is_ca,
        supports_recursive: false,
        subject_key_identifier: [0xdd; 20],
        authority_key_identifier: [0xee; 20],
        subject_alt_name: None,
    };

    writer
        .encode_tbs(
            &serial_number,
            issuer_name,
            &subject_name,
            &pubkey,
            &measurements,
            &validity,
        )
        .unwrap();

    let part1_start = writer.tbs_part1_start.unwrap();
    let part1_end = writer.tbs_part1_end.unwrap();
    let part2_start = writer.tbs_part2_start.unwrap();
    let part2_end = writer.tbs_part2_end.unwrap();
    let explicit_tag = writer.extensions_explicit_tag_offset.unwrap();
    let sequence_tag = writer.extensions_sequence_tag_offset.unwrap();
    drop(writer);

    let part1_template = buf[part1_start..part1_end].to_vec();
    let part2_template = buf[part2_start..part2_end].to_vec();

    let serial_offset = find_subslice(&part1_template, &serial_number).unwrap();

    #[allow(unreachable_patterns)]
    let (pubkey_offset, pubkey_len) = match profile {
        DpeProfile::P256Sha256 => {
            let mut needle = vec![0x04];
            needle.extend_from_slice(&[0x22; 32]);
            needle.extend_from_slice(&[0x33; 32]);
            (find_subslice(&part2_template, &needle).unwrap(), 65)
        }
        DpeProfile::P384Sha384 => {
            let mut needle = vec![0x04];
            needle.extend_from_slice(&[0x22; 48]);
            needle.extend_from_slice(&[0x33; 48]);
            (find_subslice(&part2_template, &needle).unwrap(), 97)
        }
        DpeProfile::Mldsa87 => {
            let needle = [0x22u8; 32];
            (find_subslice(&part2_template, &needle).unwrap(), 2592)
        }
        _ => panic!("Unsupported profile"),
    };

    let not_before_offset = find_subslice(&part2_template, b"20260101000000Z").unwrap();
    let not_after_offset = find_subslice(&part2_template, b"20261231235959Z").unwrap();
    let skid_offset = if is_ca {
        Some(find_subslice(&part2_template, &[0xdd; 20]).unwrap())
    } else {
        None
    };
    let akid_offset = find_subslice(&part2_template, &[0xee; 20]).unwrap();
    let subject_sn_offset = find_subslice(&part2_template, &dummy_subject_sn).unwrap();

    let explicit_tag_offset = explicit_tag - part2_start;
    let sequence_tag_offset = sequence_tag - part2_start;

    let part2_pre = part2_template[..pubkey_offset].to_vec();
    let part2_post = part2_template[pubkey_offset + pubkey_len..].to_vec();

    (
        part1_template,
        part2_pre,
        part2_post,
        Offsets {
            pubkey: pubkey_offset,
            serial: serial_offset,
            not_before: not_before_offset,
            not_after: not_after_offset,
            skid: skid_offset,
            akid: akid_offset,
            subject_sn: subject_sn_offset,
            explicit_tag: explicit_tag_offset,
            sequence_tag: sequence_tag_offset,
        },
    )
}

#[cfg(not(feature = "disable_csr"))]
struct CriOffsets {
    pubkey: usize,
    subject_sn: usize,
    explicit_tag: usize,
    sequence_tag: usize,
    set_of_tag: usize,
    extensions_sequence_tag: usize,
}

#[cfg(not(feature = "disable_csr"))]
fn generate_cri_template(profile: DpeProfile, is_ca: bool) -> (Vec<u8>, Vec<u8>, CriOffsets) {
    let mut buf = vec![0u8; 16384]; // Large enough for ML-DSA
    let mut writer = CertWriter::new(&mut buf, profile, false);

    let dummy_subject_sn = [0x35u8; 64]; // '5' repeated 64 times
    let subject_cn: &[u8] = if is_ca {
        b"DPE Exported CDI"
    } else {
        b"DPE Leaf"
    };
    let subject_name = Name {
        cn: DirectoryString::PrintableString(subject_cn),
        serial: DirectoryString::PrintableString(&dummy_subject_sn),
    };

    #[allow(unreachable_patterns)]
    let pubkey = match profile {
        DpeProfile::P256Sha256 => {
            let x = [0x22u8; 32];
            let y = [0x33u8; 32];
            PubKey::Ecdsa(EcdsaPubKey::Ecdsa256(
                caliptra_dpe_crypto::ecdsa::curve_256::EcdsaPub256::from_slice(&x, &y),
            ))
        }
        DpeProfile::P384Sha384 => {
            let x = [0x22u8; 48];
            let y = [0x33u8; 48];
            PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(
                caliptra_dpe_crypto::ecdsa::EcdsaPub::from_slice(&x, &y),
            ))
        }
        DpeProfile::Mldsa87 => {
            #[cfg(feature = "ml-dsa")]
            {
                let bytes = [0x22u8; 2592];
                PubKey::Mldsa(MldsaPublicKey::from_slice(&bytes))
            }
            #[cfg(not(feature = "ml-dsa"))]
            panic!("ML-DSA not enabled in build script but requested")
        }
        _ => panic!("Unsupported profile"),
    };

    let tci_node = tci::TciNodeData {
        tci_type: 0,
        tci_cumulative: tci::TciMeasurement([0xaa; tci::TCI_SIZE]),
        tci_current: tci::TciMeasurement([0xbb; tci::TCI_SIZE]),
        locality: 0,
        svn: 1,
    };
    let tci_nodes = [tci_node, tci_node, tci_node];

    let measurements = MeasurementData {
        label: &[0xcc; 17],
        tci_nodes: &tci_nodes,
        is_ca,
        supports_recursive: false,
        subject_key_identifier: [0xdd; 20],
        authority_key_identifier: [0xee; 20],
        subject_alt_name: None,
    };

    writer
        .encode_certification_request_info(&pubkey, &subject_name, &measurements)
        .unwrap();

    let start = writer.cri_template_start.unwrap();
    let end = writer.cri_template_end.unwrap();
    let explicit_tag = writer.cri_attributes_explicit_tag_offset.unwrap();
    let sequence_tag = writer.cri_attribute_sequence_tag_offset.unwrap();
    let set_of_tag = writer.cri_set_of_tag_offset.unwrap();
    let ext_sequence_tag = writer.extensions_sequence_tag_offset.unwrap();
    drop(writer);

    let template = buf[start..end].to_vec();

    #[allow(unreachable_patterns)]
    let (pubkey_offset, pubkey_len) = match profile {
        DpeProfile::P256Sha256 => {
            let mut needle = vec![0x04];
            needle.extend_from_slice(&[0x22; 32]);
            needle.extend_from_slice(&[0x33; 32]);
            (find_subslice(&template, &needle).unwrap(), 65)
        }
        DpeProfile::P384Sha384 => {
            let mut needle = vec![0x04];
            needle.extend_from_slice(&[0x22; 48]);
            needle.extend_from_slice(&[0x33; 48]);
            (find_subslice(&template, &needle).unwrap(), 97)
        }
        DpeProfile::Mldsa87 => {
            let needle = [0x22u8; 32];
            (find_subslice(&template, &needle).unwrap(), 2592)
        }
        _ => panic!("Unsupported profile"),
    };

    let subject_sn_offset = find_subslice(&template, &dummy_subject_sn).unwrap();

    let template_pre = template[..pubkey_offset].to_vec();
    let template_post = template[pubkey_offset + pubkey_len..].to_vec();

    (
        template_pre,
        template_post,
        CriOffsets {
            pubkey: pubkey_offset,
            subject_sn: subject_sn_offset,
            explicit_tag: explicit_tag - start,
            sequence_tag: sequence_tag - start,
            set_of_tag: set_of_tag - start,
            extensions_sequence_tag: ext_sequence_tag - start,
        },
    )
}

#[cfg(not(feature = "disable_csr"))]
fn write_cri_template_vars(
    output: &mut String,
    prefix: &str,
    template_pre: &[u8],
    template_post: &[u8],
    offsets: &CriOffsets,
) {
    output.push_str(&format!(
        "pub const {}_CRI_PRE_PUBKEY: &[u8] = &{:?};\n",
        prefix, template_pre
    ));
    output.push_str(&format!(
        "pub const {}_CRI_POST_PUBKEY: &[u8] = &{:?};\n",
        prefix, template_post
    ));
    output.push_str(&format!(
        "pub const {}_CRI_PUBLIC_KEY_OFFSET: usize = {};\n",
        prefix, offsets.pubkey
    ));
    output.push_str(&format!(
        "pub const {}_CRI_SUBJECT_SN_OFFSET: usize = {};\n",
        prefix, offsets.subject_sn
    ));
    output.push_str(&format!(
        "pub const {}_CRI_EXPLICIT_TAG_OFFSET: usize = {};\n",
        prefix, offsets.explicit_tag
    ));
    output.push_str(&format!(
        "pub const {}_CRI_SEQUENCE_TAG_OFFSET: usize = {};\n",
        prefix, offsets.sequence_tag
    ));
    output.push_str(&format!(
        "pub const {}_CRI_SET_OF_TAG_OFFSET: usize = {};\n",
        prefix, offsets.set_of_tag
    ));
    output.push_str(&format!(
        "pub const {}_CRI_EXTENSIONS_SEQUENCE_TAG_OFFSET: usize = {};\n",
        prefix, offsets.extensions_sequence_tag
    ));
}

fn write_template_vars(
    output: &mut String,
    prefix: &str,
    part1: &[u8],
    part2_pre: &[u8],
    part2_post: &[u8],
    offsets: &Offsets,
) {
    output.push_str(&format!(
        "pub const {}_TBS_PART1_TEMPLATE: &[u8] = &{:?};\n",
        prefix, part1
    ));
    output.push_str(&format!(
        "pub const {}_TBS_PART2_PRE_PUBKEY: &[u8] = &{:?};\n",
        prefix, part2_pre
    ));
    output.push_str(&format!(
        "pub const {}_TBS_PART2_POST_PUBKEY: &[u8] = &{:?};\n",
        prefix, part2_post
    ));
    output.push_str(&format!(
        "pub const {}_PUBLIC_KEY_OFFSET: usize = {};\n",
        prefix, offsets.pubkey
    ));
    output.push_str(&format!(
        "pub const {}_SERIAL_NUMBER_OFFSET: usize = {};\n",
        prefix, offsets.serial
    ));
    output.push_str(&format!(
        "pub const {}_NOT_BEFORE_OFFSET: usize = {};\n",
        prefix, offsets.not_before
    ));
    output.push_str(&format!(
        "pub const {}_NOT_AFTER_OFFSET: usize = {};\n",
        prefix, offsets.not_after
    ));
    if let Some(skid) = offsets.skid {
        output.push_str(&format!(
            "pub const {}_SKID_OFFSET: usize = {};\n",
            prefix, skid
        ));
    }
    output.push_str(&format!(
        "pub const {}_AKID_OFFSET: usize = {};\n",
        prefix, offsets.akid
    ));
    output.push_str(&format!(
        "pub const {}_SUBJECT_SN_OFFSET: usize = {};\n",
        prefix, offsets.subject_sn
    ));
    output.push_str(&format!(
        "pub const {}_EXPLICIT_TAG_OFFSET: usize = {};\n",
        prefix, offsets.explicit_tag
    ));
    output.push_str(&format!(
        "pub const {}_SEQUENCE_TAG_OFFSET: usize = {};\n",
        prefix, offsets.sequence_tag
    ));
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("dpe_page_templates.rs");
    let mut f = File::create(&dest_path).unwrap();

    let mut output = String::new();

    // Generate ECC256 CA template if feature enabled
    if env::var("CARGO_FEATURE_P256").is_ok() {
        let (p256_ca_p1, p256_ca_p2_pre, p256_ca_p2_post, p256_ca_offsets) =
            generate_template(DpeProfile::P256Sha256, /*is_ca=*/ true);
        write_template_vars(
            &mut output,
            "ECC256_CA",
            &p256_ca_p1,
            &p256_ca_p2_pre,
            &p256_ca_p2_post,
            &p256_ca_offsets,
        );

        let (p256_leaf_p1, p256_leaf_p2_pre, p256_leaf_p2_post, p256_leaf_offsets) =
            generate_template(DpeProfile::P256Sha256, /*is_ca=*/ false);
        write_template_vars(
            &mut output,
            "ECC256_LEAF",
            &p256_leaf_p1,
            &p256_leaf_p2_pre,
            &p256_leaf_p2_post,
            &p256_leaf_offsets,
        );
    }

    // Generate ECC384 CA template
    let (ecc384_ca_p1, ecc384_ca_p2_pre, ecc384_ca_p2_post, ecc384_ca_offsets) =
        generate_template(DpeProfile::P384Sha384, /*is_ca=*/ true);
    write_template_vars(
        &mut output,
        "ECC384_CA",
        &ecc384_ca_p1,
        &ecc384_ca_p2_pre,
        &ecc384_ca_p2_post,
        &ecc384_ca_offsets,
    );

    // Generate ECC384 Leaf template
    let (ecc384_leaf_p1, ecc384_leaf_p2_pre, ecc384_leaf_p2_post, ecc384_leaf_offsets) =
        generate_template(DpeProfile::P384Sha384, /*is_ca=*/ false);
    write_template_vars(
        &mut output,
        "ECC384_LEAF",
        &ecc384_leaf_p1,
        &ecc384_leaf_p2_pre,
        &ecc384_leaf_p2_post,
        &ecc384_leaf_offsets,
    );

    // Generate ML-DSA87 templates if feature enabled
    if env::var("CARGO_FEATURE_ML_DSA").is_ok() {
        let (mldsa_ca_p1, mldsa_ca_p2_pre, mldsa_ca_p2_post, mldsa_ca_offsets) =
            generate_template(DpeProfile::Mldsa87, /*is_ca=*/ true);
        write_template_vars(
            &mut output,
            "MLDSA87_CA",
            &mldsa_ca_p1,
            &mldsa_ca_p2_pre,
            &mldsa_ca_p2_post,
            &mldsa_ca_offsets,
        );

        let (mldsa_leaf_p1, mldsa_leaf_p2_pre, mldsa_leaf_p2_post, mldsa_leaf_offsets) =
            generate_template(DpeProfile::Mldsa87, /*is_ca=*/ false);
        write_template_vars(
            &mut output,
            "MLDSA87_LEAF",
            &mldsa_leaf_p1,
            &mldsa_leaf_p2_pre,
            &mldsa_leaf_p2_post,
            &mldsa_leaf_offsets,
        );
    }

    #[cfg(not(feature = "disable_csr"))]
    {
        // Generate ECC256 CA CSR template if feature enabled
        if env::var("CARGO_FEATURE_P256").is_ok() {
            let (p256_ca_cri_pre, p256_ca_cri_post, p256_ca_cri_offsets) =
                generate_cri_template(DpeProfile::P256Sha256, /*is_ca=*/ true);
            write_cri_template_vars(
                &mut output,
                "ECC256_CA",
                &p256_ca_cri_pre,
                &p256_ca_cri_post,
                &p256_ca_cri_offsets,
            );

            let (p256_leaf_cri_pre, p256_leaf_cri_post, p256_leaf_cri_offsets) =
                generate_cri_template(DpeProfile::P256Sha256, /*is_ca=*/ false);
            write_cri_template_vars(
                &mut output,
                "ECC256_LEAF",
                &p256_leaf_cri_pre,
                &p256_leaf_cri_post,
                &p256_leaf_cri_offsets,
            );
        }

        // Generate ECC384 CA CSR template
        let (ecc384_ca_cri_pre, ecc384_ca_cri_post, ecc384_ca_cri_offsets) =
            generate_cri_template(DpeProfile::P384Sha384, /*is_ca=*/ true);
        write_cri_template_vars(
            &mut output,
            "ECC384_CA",
            &ecc384_ca_cri_pre,
            &ecc384_ca_cri_post,
            &ecc384_ca_cri_offsets,
        );

        // Generate ECC384 Leaf CSR template
        let (ecc384_leaf_cri_pre, ecc384_leaf_cri_post, ecc384_leaf_cri_offsets) =
            generate_cri_template(DpeProfile::P384Sha384, /*is_ca=*/ false);
        write_cri_template_vars(
            &mut output,
            "ECC384_LEAF",
            &ecc384_leaf_cri_pre,
            &ecc384_leaf_cri_post,
            &ecc384_leaf_cri_offsets,
        );

        // Generate ML-DSA87 CSR templates if feature enabled
        if env::var("CARGO_FEATURE_ML_DSA").is_ok() {
            let (mldsa_ca_cri_pre, mldsa_ca_cri_post, mldsa_ca_cri_offsets) =
                generate_cri_template(DpeProfile::Mldsa87, /*is_ca=*/ true);
            write_cri_template_vars(
                &mut output,
                "MLDSA87_CA",
                &mldsa_ca_cri_pre,
                &mldsa_ca_cri_post,
                &mldsa_ca_cri_offsets,
            );

            let (mldsa_leaf_cri_pre, mldsa_leaf_cri_post, mldsa_leaf_cri_offsets) =
                generate_cri_template(DpeProfile::Mldsa87, /*is_ca=*/ false);
            write_cri_template_vars(
                &mut output,
                "MLDSA87_LEAF",
                &mldsa_leaf_cri_pre,
                &mldsa_leaf_cri_post,
                &mldsa_leaf_cri_offsets,
            );
        }
    }

    f.write_all(output.as_bytes()).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=x509_generator.rs");
}
