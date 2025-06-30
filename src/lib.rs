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
#[derive(Clone, Debug)]
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

    /// Verifies the validity of a ProveAndClaimCommand.
    pub fn is_valid(&self, command: ProveAndClaimCommand) -> bool {
        // Decode the proof
        let proof = match decode_proof(&command.proof) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Check if all proof elements are less than Q
        if !proof.p_a.iter().all(|&x| x < Q) ||
           !proof.p_b.iter().flatten().all(|&x| x < Q) ||
           !proof.p_c.iter().all(|&x| x < Q) {
            return false;
        }

        // Verify email parts
        if !verify_email_parts(&command.email_parts, &command.email) {
            return false;
        }

        // Decode pubkey from miscellaneous_data
        let pubkey = match decode_pubkey(&command.miscellaneous_data) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Build public signals
        let pub_signals = build_pub_signals(&command, pubkey);

        // Verify the proof using the Groth16 verifier
        self.groth16_verifier.verify_proof(proof.p_a, proof.p_b, proof.p_c, pub_signals)
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

/// Verifies that email parts, when joined with dots, match the email with '@' replaced by '$'.
fn verify_email_parts(email_parts: &[String], email: &str) -> bool {
    let composed_email = email_parts.join(".");
    let email_replaced = email.replace('@', "$");
    composed_email == email_replaced
}

/// Decodes the pubkey from miscellaneous_data as 17 U256 elements.
fn decode_pubkey(misc_data: &[u8]) -> Result<[U256; 17], String> {
    if misc_data.len() != 17 * 32 {
        return Err("Invalid miscellaneous_data length".to_string());
    }
    let mut pubkey = [U256::from(0); 17];
    for i in 0..17 {
        pubkey[i] = bytes_to_u256(misc_data[i * 32..(i + 1) * 32].try_into().unwrap());
    }
    Ok(pubkey)
}

/// Packs bytes into field elements, 31 bytes per field in little-endian order.
fn pack_bytes_to_fields(bytes: &[u8], padded_size: usize) -> Vec<U256> {
    let num_fields = (padded_size + 30) / 31;
    let mut fields = vec![U256::from(0); num_fields];
    for (i, field) in fields.iter_mut().enumerate() {
        let start = i * 31;
        let end = (start + 31).min(padded_size);
        for j in start..end {
            let byte = if j < bytes.len() { bytes[j] } else { 0 };
            *field += U256::from(byte) << (8 * (j - start));
        }
    }
    fields
}

/// Generates the expected command string for the owner address.
fn get_expected_command(owner: Address) -> String {
    format!("Claim ENS name for address {}", owner.to_string())
}

/// Builds the 60-element public signals array from the command and pubkey.
fn build_pub_signals(command: &ProveAndClaimCommand, pubkey: [U256; 17]) -> [U256; 60] {
    let mut pub_signals = [U256::from(0); 60];
    let domain_fields = pack_bytes_to_fields(command.domain.as_bytes(), DOMAIN_BYTES);
    let email_fields = pack_bytes_to_fields(command.email.as_bytes(), EMAIL_BYTES);
    let expected_command = get_expected_command(command.owner);
    let command_fields = pack_bytes_to_fields(expected_command.as_bytes(), COMMAND_BYTES);
    let mut index = 0;

    // Domain name (9 fields)
    for i in 0..DOMAIN_FIELDS {
        pub_signals[index] = domain_fields[i];
        index += 1;
    }
    // Public key hash (1 field)
    pub_signals[index] = bytes_to_u256(command.dkim_signer_hash.0);
    index += 1;
    // Email nullifier (1 field)
    pub_signals[index] = bytes_to_u256(command.nullifier.0);
    index += 1;
    // Timestamp (1 field)
    pub_signals[index] = command.timestamp;
    index += 1;
    // Masked command (20 fields)
    for i in 0..COMMAND_FIELDS {
        pub_signals[index] = command_fields[i];
        index += 1;
    }
    // Account salt (1 field)
    pub_signals[index] = bytes_to_u256(command.account_salt.0);
    index += 1;
    // Is code embedded (1 field)
    pub_signals[index] = if command.is_code_embedded { U256::from(1) } else { U256::from(0) };
    index += 1;
    // Pubkey (17 fields)
    for i in 0..PUBKEY_FIELDS {
        pub_signals[index] = pubkey[i];
        index += 1;
    }
    // Email address (9 fields)
    for i in 0..EMAIL_FIELDS {
        pub_signals[index] = email_fields[i];
        index += 1;
    }
    pub_signals
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

    /// Fixture to create a sample ProveAndClaimCommand.
    fn claim_ens_command() -> ProveAndClaimCommand {
        ProveAndClaimCommand {
            domain: "example.com".to_string(),
            email: "bob@example.com".to_string(),
            email_parts: vec!["bob$example".to_string(), "com".to_string()],
            owner: address!("1234567890abcdef1234567890abcdef12345678"),
            dkim_signer_hash: b256!("1111111111111111111111111111111111111111111111111111111111111111"),
            nullifier: b256!("2222222222222222222222222222222222222222222222222222222222222222"),
            timestamp: U256::from(1234567890),
            account_salt: b256!("3333333333333333333333333333333333333333333333333333333333333333"),
            is_code_embedded: true,
            miscellaneous_data: vec![0; 17 * 32], // 17 U256 elements
            proof: vec![0; 256], // 2 + 4 + 2 U256 elements
        }
    }

    #[test]
    fn test_is_valid_returns_true_for_valid_command() {
        let verifier = ProveAndClaimCommandVerifier::new(MockGroth16Verifier);
        let command = claim_ens_command();
        assert!(verifier.is_valid(command));
    }

    #[test]
    fn test_is_valid_returns_false_for_invalid_email_parts() {
        let verifier = ProveAndClaimCommandVerifier::new(MockGroth16Verifier);
        let mut command = claim_ens_command();
        command.email_parts = vec!["bob@example".to_string()];
        assert!(!verifier.is_valid(command));
    }

    #[test]
    fn test_is_valid_returns_false_for_mismatched_email() {
        let verifier = ProveAndClaimCommandVerifier::new(MockGroth16Verifier);
        let mut command = claim_ens_command();
        command.email_parts = vec!["alice$example".to_string(), "com".to_string()];
        assert!(!verifier.is_valid(command));
    }
}