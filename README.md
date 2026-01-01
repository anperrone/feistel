# Feistel Cipher

A didactic implementation of a [Feistel cipher](https://en.wikipedia.org/wiki/Feistel_cipher) in Rust.

## ⚠️ Disclaimer

**This is an educational implementation and should NOT be used for real cryptographic purposes.** For production use, please use well-audited cryptographic libraries like [RustCrypto](https://github.com/RustCrypto).

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
feistel = "0.1.0"
```

### Example

```rust
use feistel::FeistelCipher;

fn main() {
    // Create a cipher with a 64-bit key
    let cipher = FeistelCipher::new(0xDEADBEEF_CAFEBABE);

    let plaintext: u64 = 0x0123456789ABCDEF;

    // Encrypt
    let ciphertext = cipher.encrypt(plaintext);

    // Decrypt
    let decrypted = cipher.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted);
}
```

### Custom Number of Rounds

```rust
use feistel::FeistelCipher;

// Create a cipher with 32 rounds (default is 16)
let cipher = FeistelCipher::with_rounds(0xDEADBEEF_CAFEBABE, 32);
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
Contributions are welcome! Please feel free to submit a Pull Request.
