use std::fs::File;
use std::io::{Read, Write};
use std::path;
use std::process::exit;

use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use project_root::get_project_root;

///
/// Reads a file from a std::path::PathBuf reference
/// and returns a vector of unsigned characters.
///
fn read_file(file_path: &path::PathBuf) -> Vec<u8> {
    if file_path.display().to_string().is_empty() {
        return [].to_vec();
    }

    if !file_path.exists() {
        return String::from("Not Found!").into();
    }
    let mut file_content = Vec::new();
    let mut file = File::open(&file_path).expect("Unable to open file");
    file.read_to_end(&mut file_content).expect("Unable to read");
    file_content
}

///
/// Generates a signature for the given file using
/// the private key provided to it.
///
/// returns Ok() on success with a signature data
/// as well as dumps the signature to a given path.
///
pub fn generate_signature_for_file(
    private_key_path: &std::path::PathBuf,
    file_to_sign: &std::path::PathBuf,
    signature_path: &std::path::PathBuf,
) -> Result<Vec<u8>, ErrorStack> {
    // Load a private key
    let private_key_contents = match std::fs::read(private_key_path) {
        Ok(private_key_data) => private_key_data,
        Err(err) => {
            println!("Bad Key File: {:?}", err);
            exit(2);
        }
    };
    let keypair = match Rsa::private_key_from_pem(&private_key_contents) {
        Ok(keypair_private_data) => keypair_private_data,
        Err(error) => {
            println!("Bad private key: {:?}", error);
            exit(2)
        }
    };
    let keypair = match PKey::from_rsa(keypair) {
        Ok(keypair_private_data) => keypair_private_data,
        Err(error) => {
            println!("Bad private key: {:?}", error);
            exit(2)
        }
    };
    let content_vector = read_file(&file_to_sign);
    if content_vector.len() == 0 {
        println!("Cannot read file: {}", file_to_sign.display().to_string());
        exit(1)
    }
    let contents_bytes = content_vector.as_slice();

    // Sign the data
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.update(contents_bytes).unwrap();
    let signature_result = signer.sign_to_vec();
    match signature_result.clone() {
        Ok(signature) => {
            let mut file = File::create(signature_path).unwrap();
            file.write_all(signature.as_slice()).unwrap();
            return signature_result;
        }
        Err(_) => return signature_result,
    };
}

///
/// Uses a signature for the given file
/// and the file to check agains the public cert
/// and verify the file was signed correctly.
///
/// returns Ok() on success with and result with
/// verification status.
///
pub fn verify_file_signature(
    public_key_path: &path::PathBuf,
    signature: &[u8],
    file_to_verify: &path::PathBuf,
) -> Result<bool, ErrorStack> {
    // Load a keypair from file
    let public_key_contents = match std::fs::read(public_key_path) {
        Ok(public_key_data) => public_key_data,
        Err(err) => {
            println!("Bad Key File: {:?}", err);
            exit(2);
        }
    };
    let keypair_pub = match Rsa::public_key_from_pem(&public_key_contents) {
        Ok(keypair_pub_data) => keypair_pub_data,
        Err(error) => {
            println!("Bad public key: {:?}", error);
            exit(2)
        }
    };

    let keypair_pub = match PKey::from_rsa(keypair_pub) {
        Ok(keypair_pub_data) => keypair_pub_data,
        Err(error) => {
            println!("Bad public key: {:?}", error);
            exit(2)
        }
    };
    // Read the contents to verify.
    let content_vector = read_file(&file_to_verify);
    if content_vector.len() == 0 {
        println!("Cannot read file: {}", file_to_verify.display().to_string());
        exit(1)
    }
    let contents_bytes = content_vector.as_slice();

    // set up verifier instances.
    let mut verifier = match Verifier::new(MessageDigest::sha256(), &keypair_pub) {
        Ok(verifier_data) => verifier_data,
        Err(err) => {
            println!("Cannot setup sha digest verifier, error: {:?}", err);
            exit(2);
        }
    };
    verifier.update(contents_bytes).unwrap();
    // verify signature.
    verifier.verify(&signature)
}

///
/// Uses a signature path for the given file
/// and the file to check agains the public cert
/// and verify the file was signed correctly.
///
/// returns Ok() on success with and result with
/// verification status.
///
pub fn verify_file_from_signature_file(
    public_key_path: &path::PathBuf,
    signature_path: &path::PathBuf,
    file_to_verify: &path::PathBuf,
) -> Result<bool, ErrorStack>
{
    let signature_data = match std::fs::read(&signature_path) {
        Ok(signature_data) => signature_data,
        Err(err) => {
            println!("Cannot read signature information, error: {:?}", err);
            exit(2)
        },
    };

    verify_file_signature(&public_key_path, &signature_data, &file_to_verify)
}

fn main() {
    // get project root directory.
    let project_root = match get_project_root() {
        Ok(project_root) => project_root,
        Err(_) => {
            println!("Error cannot get project root path.");
            exit(1);
        }
    };

    // setup test cert path.
    let test_cert_dir = project_root.join(path::PathBuf::from("test_cert"));
    let private_key_path = test_cert_dir.join(path::PathBuf::from("keypair.pem"));
    let public_key_path = test_cert_dir.join(path::PathBuf::from("publickey.crt"));

    // Setup test data path.
    let test_directory_path = project_root.join(path::PathBuf::from("test_data"));
    let test_data_file_path = test_directory_path.join(path::PathBuf::from("random.img"));
    let signature_path = test_directory_path.join(path::PathBuf::from("random.sig"));

    // Perform signature generation.
    let signature_result =
        generate_signature_for_file(&private_key_path, &test_data_file_path, &signature_path);
    // Extract signature from result.
    let signature_data = match signature_result {
        Ok(signature_data) => signature_data,

        Err(error) => {
            let _ = std::fs::remove_file(&signature_path);
            println!("Failed to verify signature: {:?}", error);
            exit(3);
        }
    };
    // Verify signature.
    match verify_file_signature(
        &public_key_path,
        &signature_data.as_slice(),
        &test_data_file_path,
    ) {
        Ok(is_verified) => {
            // signture file is no longer needed. we can remove it.
            let _ = std::fs::remove_file(&signature_path);
            if is_verified {
                println!("Data was signed and verified.");
            } else {
                println!("Data was not verified from signature.");
            }
        }
        Err(error) => {
            let _ = std::fs::remove_file(&signature_path);
            println!("Failed to verify signature: {:?}", error);
            exit(2);
        }
    };
}
