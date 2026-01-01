//! # Feistel Cipher
//!
//! A didactic implementation of a [Feistel cipher](https://en.wikipedia.org/wiki/Feistel_cipher) in Rust.
//!
//! ## ⚠️ Security Warning
//!
//! **This is an educational implementation and should NOT be used for real cryptographic purposes.**
//! For production use, please use well-audited cryptographic libraries.
//!
//! ## Overview
//!
//! A Feistel cipher is a symmetric structure used in the construction of block ciphers.
//! The key advantage is that encryption and decryption operations are very similar,
//! requiring only a reversal of the key schedule.
//!
//! ## Example
//!
//! ```rust
//! use feistel::FeistelCipher;
//!
//! let cipher = FeistelCipher::new(0xDEADBEEF_CAFEBABE);
//!
//! let plaintext: u64 = 0x0123456789ABCDEF;
//! let ciphertext = cipher.encrypt(plaintext);
//! let decrypted = cipher.decrypt(ciphertext);
//!
//! assert_eq!(plaintext, decrypted);
//! ```

/// Default number of rounds for the Feistel cipher.
pub const DEFAULT_ROUNDS: usize = 16;

/// A Feistel cipher implementation.
///
/// This struct holds the round keys derived from the master key and provides
/// methods for encryption and decryption.
#[derive(Debug, Clone)]
pub struct FeistelCipher {
    /// Round keys derived from the master key
    round_keys: Vec<u32>,
}

impl FeistelCipher {
    /// Creates a new Feistel cipher with the given key and default number of rounds (16).
    ///
    /// # Arguments
    ///
    /// * `key` - A 64-bit key used to derive round keys
    ///
    /// # Example
    ///
    /// ```rust
    /// use feistel::FeistelCipher;
    ///
    /// let cipher = FeistelCipher::new(0x0123456789ABCDEF);
    /// ```
    pub fn new(key: u64) -> Self {
        Self::with_rounds(key, DEFAULT_ROUNDS)
    }

    /// Creates a new Feistel cipher with a custom number of rounds.
    ///
    /// # Arguments
    ///
    /// * `key` - A 64-bit key used to derive round keys
    /// * `rounds` - The number of rounds to use (more rounds = more security, but slower)
    ///
    /// # Example
    ///
    /// ```rust
    /// use feistel::FeistelCipher;
    ///
    /// let cipher = FeistelCipher::with_rounds(0x0123456789ABCDEF, 32);
    /// ```
    pub fn with_rounds(key: u64, rounds: usize) -> Self {
        let round_keys = Self::derive_round_keys(key, rounds);
        Self { round_keys }
    }

    /// Derives round keys from the master key using a simple key schedule.
    ///
    /// Note: This is a simplified key schedule for educational purposes.
    fn derive_round_keys(key: u64, rounds: usize) -> Vec<u32> {
        let mut keys = Vec::with_capacity(rounds);
        let mut current = key;

        for i in 0..rounds {
            // Simple key schedule: rotate and mix
            current = current.rotate_left(5) ^ (current.wrapping_mul(0x9E3779B97F4A7C15));
            keys.push((current >> 32) as u32 ^ (i as u32));
        }

        keys
    }

    /// Encrypts a 64-bit block of data.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The 64-bit block to encrypt
    ///
    /// # Returns
    ///
    /// The encrypted 64-bit ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use feistel::FeistelCipher;
    ///
    /// let cipher = FeistelCipher::new(0xDEADBEEF);
    /// let ciphertext = cipher.encrypt(0x12345678);
    /// ```
    pub fn encrypt(&self, plaintext: u64) -> u64 {
        let mut left = (plaintext >> 32) as u32;
        let mut right = plaintext as u32;

        for round_key in &self.round_keys {
            let new_right = left ^ Self::round_function(right, *round_key);
            left = right;
            right = new_right;
        }

        // Final swap
        ((right as u64) << 32) | (left as u64)
    }

    /// Decrypts a 64-bit block of data.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The 64-bit block to decrypt
    ///
    /// # Returns
    ///
    /// The decrypted 64-bit plaintext
    ///
    /// # Example
    ///
    /// ```rust
    /// use feistel::FeistelCipher;
    ///
    /// let cipher = FeistelCipher::new(0xDEADBEEF);
    /// let plaintext: u64 = 0x12345678;
    /// let ciphertext = cipher.encrypt(plaintext);
    /// let decrypted = cipher.decrypt(ciphertext);
    /// assert_eq!(plaintext, decrypted);
    /// ```
    pub fn decrypt(&self, ciphertext: u64) -> u64 {
        let mut left = (ciphertext >> 32) as u32;
        let mut right = ciphertext as u32;

        // Apply rounds in reverse order
        for round_key in self.round_keys.iter().rev() {
            let new_right = left ^ Self::round_function(right, *round_key);
            left = right;
            right = new_right;
        }

        // Final swap
        ((right as u64) << 32) | (left as u64)
    }

    /// The round function F(R, K).
    ///
    /// This function takes the right half and the round key, and produces
    /// a 32-bit output that will be XORed with the left half.
    ///
    /// Note: This is a simplified round function for educational purposes.
    /// Real ciphers use more complex functions with S-boxes and permutations.
    #[inline]
    fn round_function(data: u32, key: u32) -> u32 {
        let mixed = data.wrapping_add(key);
        let rotated = mixed.rotate_left(7);
        rotated ^ mixed.rotate_right(3) ^ key
    }

    /// Returns the number of rounds configured for this cipher.
    pub fn rounds(&self) -> usize {
        self.round_keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let cipher = FeistelCipher::new(0xDEADBEEF_CAFEBABE);
        let plaintext: u64 = 0x0123456789ABCDEF;

        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_various_values() {
        let cipher = FeistelCipher::new(0x1234567890ABCDEF);
        let test_values: [u64; 6] = [0, 1, u64::MAX, 0xDEADBEEF, 0xCAFEBABE, 0x123456789ABCDEF0];

        for plaintext in test_values {
            let ciphertext = cipher.encrypt(plaintext);
            let decrypted = cipher.decrypt(ciphertext);
            assert_eq!(
                plaintext, decrypted,
                "Failed for plaintext: {:#x}",
                plaintext
            );
        }
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let cipher1 = FeistelCipher::new(0x0000000000000001);
        let cipher2 = FeistelCipher::new(0x0000000000000002);
        let plaintext: u64 = 0x0123456789ABCDEF;

        let ciphertext1 = cipher1.encrypt(plaintext);
        let ciphertext2 = cipher2.encrypt(plaintext);

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_encryption_changes_plaintext() {
        let cipher = FeistelCipher::new(0xDEADBEEF);
        let plaintext: u64 = 0x0123456789ABCDEF;

        let ciphertext = cipher.encrypt(plaintext);

        assert_ne!(plaintext, ciphertext);
    }

    #[test]
    fn test_custom_rounds() {
        let cipher = FeistelCipher::with_rounds(0xDEADBEEF, 32);
        assert_eq!(cipher.rounds(), 32);

        let plaintext: u64 = 0x0123456789ABCDEF;
        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_single_round() {
        let cipher = FeistelCipher::with_rounds(0xDEADBEEF, 1);
        let plaintext: u64 = 0x0123456789ABCDEF;

        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_zero_key() {
        let cipher = FeistelCipher::new(0);
        let plaintext: u64 = 0x0123456789ABCDEF;

        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted);
    }
}
