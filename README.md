# Rust OpenSSL KeyPair Verification Example

This repository includes a simple example of generating a signature for a file as well as verifying the signature for the file.

- [generate_signature_for_file()](README.md#generate_signature_for_file)
- [verify_file_signature()](README.md#verify_file_signature)
- [verify_file_from_signature_file()](README.md#verify_file_from_signature_file)

## API Explanation

### generate_signature_for_file()

The API to generate a signature takes the private key path, the file to sign and the path to which signature is to be dumped as an argument.

On successully creating a signature, it gets dumped to file path as well as a version is retuned as part of Result return type of the function.

```rust
fn generate_signature_for_file(
    private_key_path: &std::path::PathBuf,
    file_to_sign: &std::path::PathBuf,
    signature_path: &std::path::PathBuf,
)
```

### verify_file_signature()

The API to verify a file uses the file and its signature as signature raw data. On successful operation, the API returns reult containing the verification data and error.

```rust
pub fn verify_file_signature(
    public_key_path: &path::PathBuf,
    signature: &[u8],
    file_to_verify: &path::PathBuf,
)
```

### verify_file_from_signature_file()

The API to verify a file uses the file and its signature as path. On successful operation, the API returns reult containing the verification data and error.

```rust
pub fn verify_file_from_signature_file(
    public_key_path: &path::PathBuf,
    signature_path: &path::PathBuf,
    file_to_verify: &path::PathBuf,
)
```
