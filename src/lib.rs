use alloy_primitives::{Address, B256, U256};

// Constants matching Verifier.sol
const Q: U256 = U256::from_limbs([0x43e1f593f0000001, 0x2833e84879b97091, 0xb85045b68181585d, 0x30644e72e131a029]);
const DOMAIN_FIELDS: usize = 9;
const DOMAIN_BYTES: usize = 255;
const EMAIL_FIELDS: usize = 9;
const EMAIL_BYTES: usize = 256;
const COMMAND_FIELDS: usize = 20;
const COMMAND_BYTES: usize = 605;
const PUBKEY_FIELDS: usize = 17;

/// Represents the zero-knowledge proof command for claiming ENS names via email verification.
#[derive(Clone, Debug, PartialEq)]
pub struct ProveAndClaimCommand {
    pub domain: String,
    pub email: String,
    pub email_parts: Vec<String>,
    pub owner: Address,
    pub dkim_signer_hash: B256,
    pub nullifier: B256,
    pub timestamp: U256,
    pub account_salt: B256,
    pub is_code_embedded: bool,
    pub miscellaneous_data: Vec<u8>,
    pub proof: Vec<u8>,
}

/// Struct to hold decoded proof components.
#[derive(Debug)]
struct Proof {
    p_a: [U256; 2],
    p_b: [[U256; 2]; 2],
    p_c: [U256; 2],
}

/// Trait representing the Groth16 verifier interface.
pub trait Groth16Verifier {
    fn verify_proof(
        &self,
        p_a: [U256; 2],
        p_b: [[U256; 2]; 2],
        p_c: [U256; 2],
        pub_signals: [U256; 60],
    ) -> bool;
}

/// Verifies zero-knowledge proofs for email-based ENS name claiming.
pub struct ProveAndClaimCommandVerifier<V: Groth16Verifier> {
    groth16_verifier: V,
}

impl<V: Groth16Verifier> ProveAndClaimCommandVerifier<V> {
    /// Creates a new verifier instance with a Groth16 verifier implementation.
    pub fn new(groth16_verifier: V) -> Self {
        Self { groth16_verifier }
    }

    /// Validates a proof and extracts a ProveAndClaimCommand from public signals.
    pub fn verify_and_extract(&self, proof_bytes: &[u8], pub_signals: [U256; 60]) -> Result<ProveAndClaimCommand, String> {
        // Decode the proof
        let proof = decode_proof(proof_bytes)?;

        // Check if all proof elements are less than Q
        if !proof.p_a.iter().all(|&x| x < Q) ||
           !proof.p_b.iter().flatten().all(|&x| x < Q) ||
           !proof.p_c.iter().all(|&x| x < Q) {
            return Err("Proof elements exceed curve order".to_string());
        }

        // Verify the proof
        if !self.groth16_verifier.verify_proof(proof.p_a, proof.p_b, proof.p_c, pub_signals) {
            return Err("Proof verification failed".to_string());
        }

        // Extract fields from pub_signals
        let mut index = 0;

        // Domain name (9 fields)
        let domain_fields: [U256; DOMAIN_FIELDS] = pub_signals[index..index + DOMAIN_FIELDS].try_into().unwrap();
        let domain_bytes = unpack_fields_to_bytes(&domain_fields, DOMAIN_BYTES)?;
        let domain = String::from_utf8(domain_bytes).map_err(|_| "Invalid domain encoding".to_string())?;
        index += DOMAIN_FIELDS;

        // Public key hash (1 field)
        let dkim_signer_hash = B256::from_slice(&pub_signals[index].to_be_bytes::<32>());
        index += 1;

        // Email nullifier (1 field)
        let nullifier = B256::from_slice(&pub_signals[index].to_be_bytes::<32>());
        index += 1;

        // Timestamp (1 field)
        let timestamp = pub_signals[index];
        index += 1;

        // Masked command (20 fields)
        let command_fields: [U256; COMMAND_FIELDS] = pub_signals[index..index + COMMAND_FIELDS].try_into().unwrap();
        let command_bytes = unpack_fields_to_bytes(&command_fields, COMMAND_BYTES)?;
        let command_str = String::from_utf8(command_bytes).map_err(|_| "Invalid command encoding".to_string())?;
        index += COMMAND_FIELDS;

        // Account salt (1 field)
        let account_salt = B256::from_slice(&pub_signals[index].to_be_bytes::<32>());
        index += 1;

        // Is code embedded (1 field)
        let is_code_embedded = pub_signals[index] != U256::from(0);
        index += 1;

        // Pubkey (17 fields)
        let pubkey: [U256; PUBKEY_FIELDS] = pub_signals[index..index + PUBKEY_FIELDS].try_into().unwrap();
        let mut miscellaneous_data = Vec::with_capacity(PUBKEY_FIELDS * 32);
        for &field in &pubkey {
            miscellaneous_data.extend_from_slice(&field.to_be_bytes::<32>());
        }
        index += PUBKEY_FIELDS;

        // Email address (9 fields)
        let email_fields: [U256; EMAIL_FIELDS] = pub_signals[index..index + EMAIL_FIELDS].try_into().unwrap();
        let email_bytes = unpack_fields_to_bytes(&email_fields, EMAIL_BYTES)?;
        let email = String::from_utf8(email_bytes).map_err(|_| "Invalid email encoding".to_string())?;

        // Derive email_parts from email
        let email_parts: Vec<String> = email.replace('@', "$").split('.').map(|s| s.to_string()).collect();

        // Extract owner from command string
        let owner = extract_owner_from_command(&command_str)?;

        Ok(ProveAndClaimCommand {
            domain,
            email,
            email_parts,
            owner,
            dkim_signer_hash,
            nullifier,
            timestamp,
            account_salt,
            is_code_embedded,
            miscellaneous_data,
            proof: proof_bytes.to_vec(),
        })
    }
}

fn bytes_to_u256(bytes: [u8; 32]) -> U256 {
    U256::from_be_bytes(bytes)
}

/// Decodes the proof bytes into pA, pB, and pC components.
fn decode_proof(proof_bytes: &[u8]) -> Result<Proof, String> {
    if proof_bytes.len() != 256 {
        return Err("Invalid proof length".to_string());
    }
    let mut offset = 0;
    let p_a = [
        bytes_to_u256(proof_bytes[offset..offset + 32].try_into().unwrap()),
        bytes_to_u256(proof_bytes[offset + 32..offset + 64].try_into().unwrap()),
    ];
    offset += 64;
    let p_b = [
        [
            bytes_to_u256(proof_bytes[offset..offset + 32].try_into().unwrap()),
            bytes_to_u256(proof_bytes[offset + 32..offset + 64].try_into().unwrap()),
        ],
        [
            bytes_to_u256(proof_bytes[offset + 64..offset + 96].try_into().unwrap()),
            bytes_to_u256(proof_bytes[offset + 96..offset + 128].try_into().unwrap()),
        ],
    ];
    offset += 128;
    let p_c = [
        bytes_to_u256(proof_bytes[offset..offset + 32].try_into().unwrap()),
        bytes_to_u256(proof_bytes[offset + 32..offset + 64].try_into().unwrap()),
    ];
    Ok(Proof { p_a, p_b, p_c })
}

/// Unpacks field elements into bytes, matching the encoding from TestFixtures.sol.
fn unpack_fields_to_bytes(fields: &[U256], padded_size: usize) -> Result<Vec<u8>, String> {
    let num_fields = (padded_size + 30) / 31;
    if fields.len() != num_fields {
        return Err(format!("Invalid number of fields: expected {}, got {}", num_fields, fields.len()));
    }
    let mut all_bytes = Vec::new();
    for &field in fields {
        let bytes = field.to_be_bytes::<32>(); // Big-endian representation
        // Find the first and last non-zero byte indices
        let first_non_zero = bytes.iter().position(|&b| b != 0);
        let last_non_zero = bytes.iter().rposition(|&b| b != 0);
        let trimmed_bytes = match (first_non_zero, last_non_zero) {
            (Some(start), Some(end)) => &bytes[start..=end],
            _ => &[], // All bytes are zero
        };
        let mut reversed_bytes = trimmed_bytes.to_vec();
        reversed_bytes.reverse(); // Reverse bytes to match field_to_ascii logic
        all_bytes.extend(reversed_bytes);
    }
    // Remove trailing null bytes from the entire array
    while all_bytes.last() == Some(&0) {
        all_bytes.pop();
    }
    Ok(all_bytes)
}

/// Extracts the owner address from the command string.
fn extract_owner_from_command(command: &str) -> Result<Address, String> {
    let prefix = "Claim ENS name for address ";
    if !command.starts_with(prefix) {
        return Err("Invalid command format".to_string());
    }
    let addr_str = command.strip_prefix(prefix).ok_or("Failed to strip prefix".to_string())?;
    addr_str.parse::<Address>().map_err(|_| "Invalid address format".to_string())
}

// Test module
#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    /// Mock implementation of Groth16Verifier that always returns true for simplicity.
    struct MockGroth16Verifier;
    impl Groth16Verifier for MockGroth16Verifier {
        fn verify_proof(
            &self,
            _p_a: [U256; 2],
            _p_b: [[U256; 2]; 2],
            _p_c: [U256; 2],
            _pub_signals: [U256; 60],
        ) -> bool {
            true
        }
    }

    #[test]
    fn test_field_to_ascii_gmail() {
        let field_value = "2018721414038404820327".parse::<U256>().unwrap();
        let fields = [field_value];
        let bytes = unpack_fields_to_bytes(&fields, 9).unwrap();
        let result = String::from_utf8_lossy(&bytes).to_string();
        assert_eq!(result, "gmail.com");
    }

    #[test]
    fn test_verify_and_extract_testfixtures() {
        let pub_signals: [U256; 60] = [
            "2018721414038404820327".parse::<U256>().unwrap(),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            "6632353713085157925504008443078919716322386156160602218536961028046468237192".parse::<U256>().unwrap(),
            "4554837866351681469140157310807394956517436905901938745944947421127000894884".parse::<U256>().unwrap(),
            U256::from(0),
            "180891110264973503160226225538030206223858091522603795023666265748100181059".parse::<U256>().unwrap(),
            "173532502901810909445165194544006900992761359126983071590425318149531518018".parse::<U256>().unwrap(),
            "13582551733188164".parse::<U256>().unwrap(),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            "6462823065239948963336625999299932081772838850050016167388148022706945490790".parse::<U256>().unwrap(),
            U256::from(0),
            "2107195391459410975264579855291297887".parse::<U256>().unwrap(),
            "2562632063603354817278035230349645235".parse::<U256>().unwrap(),
            "1868388447387859563289339873373526818".parse::<U256>().unwrap(),
            "2159353473203648408714805618210333973".parse::<U256>().unwrap(),
            "351789365378952303483249084740952389".parse::<U256>().unwrap(),
            "659717315519250910761248850885776286".parse::<U256>().unwrap(),
            "1321773785542335225811636767147612036".parse::<U256>().unwrap(),
            "258646249156909342262859240016844424".parse::<U256>().unwrap(),
            "644872192691135519287736182201377504".parse::<U256>().unwrap(),
            "174898460680981733302111356557122107".parse::<U256>().unwrap(),
            "1068744134187917319695255728151595132".parse::<U256>().unwrap(),
            "1870792114609696396265442109963534232".parse::<U256>().unwrap(),
            "8288818605536063568933922407756344".parse::<U256>().unwrap(),
            "1446710439657393605686016190803199177".parse::<U256>().unwrap(),
            "2256068140678002554491951090436701670".parse::<U256>().unwrap(),
            "518946826903468667178458656376730744".parse::<U256>().unwrap(),
            "3222036726675473160989497427257757".parse::<U256>().unwrap(),
            "9533142343906178599764761233821773221685364".parse::<U256>().unwrap(),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
            U256::from(0),
        ];

        let p_a = [
            U256::from_str_radix("03e1490fc469798ca99a36702a322ccc8227cc3595058d0aac83aea22fbb2ccf", 16).unwrap(),
            U256::from_str_radix("2551cd0add70fe3900b05e2dd03b7ba5102ddb63e1b4003ec839a537c6453cfc", 16).unwrap(),
        ];
        let p_b = [
            [
                U256::from_str_radix("25c35e8d24d948a808a1ea128831cd54ce4a3532a40ab136dc81bbf0b2635c24", 16).unwrap(),
                U256::from_str_radix("2e0054eaf867ca03c0f3668b7f17d3bf01b3d7f00bcadb774a74058f81273c97", 16).unwrap(),
            ],
            [
                U256::from_str_radix("144542d4082a8fadc1c55a24698522916f1717791bf1e1f115fb183c62a507da", 16).unwrap(),
                U256::from_str_radix("2dc6e057e138dd1b7c10c1be1f99261b826cd4fcf081ae5a90885aab3358dca4", 16).unwrap(),
            ],
        ];
        let p_c = [
            U256::from_str_radix("2ef0d8f5b88cdc952bcf26adeaa6a30176584496df21bd21fbc997432172c9e7", 16).unwrap(),
            U256::from_str_radix("24b4201c52b7eec75377b727ac0fe51049d534bac7918175096596fa351862c1", 16).unwrap(),
        ];

        let mut proof_bytes = Vec::new();
        proof_bytes.extend(p_a[0].to_be_bytes::<32>());
        proof_bytes.extend(p_a[1].to_be_bytes::<32>());
        proof_bytes.extend(p_b[0][0].to_be_bytes::<32>());
        proof_bytes.extend(p_b[0][1].to_be_bytes::<32>());
        proof_bytes.extend(p_b[1][0].to_be_bytes::<32>());
        proof_bytes.extend(p_b[1][1].to_be_bytes::<32>());
        proof_bytes.extend(p_c[0].to_be_bytes::<32>());
        proof_bytes.extend(p_c[1].to_be_bytes::<32>());

        let expected_command = ProveAndClaimCommand {
            domain: "gmail.com".to_string(),
            email: "thezdev3@gmail.com".to_string(),
            email_parts: vec!["thezdev3$gmail".to_string(), "com".to_string()],
            owner: address!("afBD210c60dD651892a61804A989eEF7bD63CBA0"),
            dkim_signer_hash: b256!("0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788"),
            nullifier: b256!("0A11F2664AE4F7E3A9C3BA43394B01347FD5B76FC0A7FDB09D91324DA1F6ADA4"),
            timestamp: U256::from(0),
            account_salt: b256!("0E49D406A4D84DA7DB65C161EB11D06E8C52F1C0EDD91BC557E4F23FF01D7F66"),
            is_code_embedded: false,
            miscellaneous_data: vec![0u8; 17 * 32], // Will be populated from pub_signals
            proof: proof_bytes.clone(),
        };

        let verifier = ProveAndClaimCommandVerifier::new(MockGroth16Verifier);
        let result = verifier.verify_and_extract(&proof_bytes, pub_signals);
        assert!(result.is_ok(), "Validation failed: {:?}", result);
        let extracted_command = result.unwrap();

        assert_eq!(extracted_command.domain, expected_command.domain);
        assert_eq!(extracted_command.email, expected_command.email);
        assert_eq!(extracted_command.email_parts, expected_command.email_parts);
        assert_eq!(extracted_command.owner, expected_command.owner);
        assert_eq!(extracted_command.dkim_signer_hash, expected_command.dkim_signer_hash);
        assert_eq!(extracted_command.nullifier, expected_command.nullifier);
        assert_eq!(extracted_command.timestamp, expected_command.timestamp);
        assert_eq!(extracted_command.account_salt, expected_command.account_salt);
        assert_eq!(extracted_command.is_code_embedded, expected_command.is_code_embedded);
        // miscellaneous_data is extracted from pub_signals, so compare it separately
        assert_eq!(extracted_command.miscellaneous_data.len(), 17 * 32);
        assert_eq!(extracted_command.proof, expected_command.proof);
    }
}