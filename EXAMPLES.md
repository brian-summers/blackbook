# Blackbook Core - Usage Examples

This guide demonstrates how to use the `blackbook_core` module for cryptographic operations.

## Quick Start

### 1. Importing the Module

```rust
use blackbook::blackbook_core::*;
```

### 2. Generate a Secure Identifier

```rust
fn example_id_generation() -> CryptoResult<()> {
    // Random ID (32 bytes)
    let id = Id::new(32);
    println!("Random ID (hex): {}", id.encode());

    // Deterministic ID from string + domain
    let derived_id = Id::from_string("mykey", "mydomain", 32)?;
    println!("Derived ID: {}", derived_id.encode());

    // Change encoding
    let base64_id = derived_id.clone().with_encoding(IdEncoding::Base64);
    println!("Base64 encoded: {}", base64_id.encode());

    Ok(())
}
```

---

## Cryptographic Operations

### 3. Asymmetric Key Pair (Ed25519)

```rust
fn example_asymmetric_crypto() -> CryptoResult<()> {
    // Generate keypair
    let key = AsymmetricKey::generate();
    println!("Key ID: {}", key.id.encode());

    // Sign data
    let data = b"Hello, Blackbook!";
    let signature = key.sign(data)?;
    println!("Signature: {}", signature);

    // Verify signature
    let is_valid = key.verify(&signature, data)?;
    assert!(is_valid);
    println!("Signature verified!");

    // Get public key
    let public_key = key.public_key();
    println!("Public key length: {}", public_key.len());

    Ok(())
}
```

### 4. Password Hashing (Scrypt)

```rust
fn example_password_hashing() -> CryptoResult<()> {
    let primary_key = PrimaryKey::new();

    // Derive with custom salt
    let salt = b"user@example.com";
    let hash = primary_key.derive(Some(salt))?;
    println!("Password hash (32 bytes): {}", hex::encode(&hash));

    // Derive without salt (use default)
    let hash2 = primary_key.derive(None)?;
    println!("Another hash: {}", hex::encode(&hash2));

    Ok(())
}
```

### 5. Key Derivation Functions

```rust
fn example_key_derivation() -> CryptoResult<()> {
    let primary = PrimaryKey::new();
    let secondary = SecondaryKey::new(primary, "app_domain".to_string(), 32);

    // Derive using Scrypt
    let scrypt_key = secondary.derive_scrypt(None)?;
    println!("Scrypt key: {}", hex::encode(&scrypt_key));

    // Derive using PBKDF2
    let pbkdf2_key = secondary.derive_pbkdf2()?;
    println!("PBKDF2 key: {}", hex::encode(&pbkdf2_key));

    Ok(())
}
```

### 6. AES-256-GCM Encryption

```rust
fn example_aes_encryption() -> CryptoResult<()> {
    // Generate encryption key (32 bytes for AES-256)
    let key = BaseKey::new(32);
    let plaintext = b"Secret message";

    // Encrypt
    let ciphertext = encrypt_aes_gcm(plaintext, key.as_bytes())?;
    println!("Encrypted: {}", hex::encode(&ciphertext));

    // Decrypt
    let decrypted = decrypt_aes_gcm(&ciphertext, key.as_bytes())?;
    assert_eq!(plaintext, &decrypted[..]);
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    Ok(())
}
```

### 7. Serialization with Integrity Verification

```rust
fn example_serialization() -> CryptoResult<()> {
    use std::collections::HashMap;

    let mut data = HashMap::new();
    data.insert("username".to_string(), b"alice".to_vec());
    data.insert("email".to_string(), b"alice@example.com".to_vec());

    // Serialize with checksum
    let serialized = serialize(&data)?;
    println!("Serialized length: {}", serialized.len());
    println!("Encoded: {}", BASE64.encode(&serialized));

    // Deserialize and verify
    let deserialized = deserialize(&String::from_utf8(serialized)?)?;
    assert_eq!(data, deserialized);
    println!("Deserialization verified!");

    Ok(())
}
```

---

## Token Management

### 8. Create and Validate Tokens

```rust
fn example_token_generation() -> CryptoResult<()> {
    // Create token with 1-hour TTL
    let mut token = Token::new(3600);
    
    println!("Token ID: {}", token.id.encode());
    println!("Created: {}", token.created_at);
    println!("Expires: {}", token.expires_at);

    // Sign the token
    let signed_token = token.sign()?;
    println!("Signed token: {}", &signed_token[..50]); // First 50 chars

    // Validate token
    if token.validate()? {
        println!("✓ Token is valid");
    } else {
        println!("✗ Token is invalid or expired");
    }

    // Serialize to string
    let token_str = token.to_string()?;
    println!("String representation: {}", &token_str[..50]);

    // Deserialize from string
    let loaded_token = Token::from_string(&token_str)?;
    println!("Loaded token ID: {}", loaded_token.id.encode());

    Ok(())
}
```

---

## Index Management

### 9. Fast Lookups with Index

```rust
fn example_index_operations() -> CryptoResult<()> {
    let mut index = Index::new("domain".to_string());

    // Get identifier for a key
    let id1 = index.get_identifier("user:123")?;
    let id2 = index.get_identifier("user:456")?;

    // Store values in index
    let value1 = Id::new(32);
    let value2 = Id::new(32);
    
    index.add("user:123".to_string(), value1.clone());
    index.add("user:456".to_string(), value2.clone());

    // Lookup values
    if let Some(found) = index.lookup("user:123") {
        assert_eq!(found, &value1);
        println!("✓ Found user:123");
    }

    Ok(())
}
```

---

## Access Control

### 10. ACL Entries and Permissions

```rust
fn example_acl_operations() -> CryptoResult<()> {
    let principal = Id::new(32);  // User ID
    let resource = Id::new(32);   // Document ID

    // Create ACL entry with multiple permissions
    let mut actions = vec![
        AclAction::Read,
        AclAction::Update,
    ];

    let acl = AclEntry::new(principal, resource, actions);
    println!("ACL ID: {}", acl.id.encode());

    // Check permissions
    if acl.has_action(AclAction::Read) {
        println!("✓ User can read");
    }

    if acl.has_action(AclAction::Delete) {
        println!("✗ User cannot delete");
    }

    Ok(())
}
```

---

## Comprehensive Example: Secure Storage

```rust
fn example_secure_storage() -> CryptoResult<()> {
    // Step 1: Generate master key
    let blackbook_key = BlackbookKey::generate()?;
    println!("Generated master key: {}", blackbook_key.id.encode());

    // Step 2: Create content to store
    let sensitive_data = b"This is sensitive information";

    // Step 3: Encrypt content — unwrap the WrappedKey to get the raw 32-byte key
    let key_bytes = blackbook_key.symmetric_bytes()?;
    let encrypted = encrypt_aes_gcm(sensitive_data, &key_bytes)?;
    println!("Encrypted {} bytes", encrypted.len());

    // Step 4: Create token for access
    let mut access_token = Token::new(3600);
    access_token.sign()?;
    
    // Step 5: Serialize for storage
    let mut storage = std::collections::HashMap::new();
    storage.insert(
        "encrypted_data".to_string(),
        encrypted.clone()
    );
    storage.insert(
        "access_token".to_string(),
        access_token.to_string()?.into_bytes()
    );

    let serialized = serialize(&storage)?;
    println!("Stored {} bytes", serialized.len());

    // Step 6: Later - retrieve and decrypt
    let deserialized = deserialize(&String::from_utf8(serialized)?)?;
    let retrieved_encrypted = &deserialized["encrypted_data"];
    
    let key_bytes = blackbook_key.symmetric_bytes()?;
    let decrypted = decrypt_aes_gcm(retrieved_encrypted, &key_bytes)?;
    
    assert_eq!(sensitive_data, &decrypted[..]);
    println!("✓ Successfully retrieved and decrypted data");

    Ok(())
}
```

---

## Error Handling

All cryptographic functions return `CryptoResult<T>` which handles errors gracefully:

```rust
fn example_error_handling() -> CryptoResult<()> {
    // These operations can fail:
    let key = AsymmetricKey::generate();
    let data = b"data";
    
    match key.sign(data) {
        Ok(signature) => println!("Signed: {}", &signature[..20]),
        Err(e) => eprintln!("Signing failed: {}", e),
    }

    // Using ? operator for error propagation
    let encrypted = encrypt_aes_gcm(b"secret", b"invalid_key")?;
    // Returns error if key is wrong length (must be 32 bytes for AES-256)

    Ok(())
}
```

---

## Integration with Main Framework

The `blackbook_core` module integrates seamlessly with the CLI framework:

```rust
// In main.rs
use blackbook::blackbook_core::*;

#[derive(Subcommand)]
enum Commands {
    // ... existing commands ...
    
    /// Cryptographic operations
    Crypto {
        #[command(subcommand)]
        operation: CryptoOps,
    },
}

#[derive(Subcommand)]
enum CryptoOps {
    /// Generate new keypair
    Keygen,
    
    /// Sign data
    Sign { #[arg(short, long)] data: String },
    
    /// Encrypt data
    Encrypt { #[arg(short, long)] data: String },
}
```

---

## Performance Tips

1. **Reuse Keys**: Create once, use multiple times
   ```rust
   let key = BlackbookKey::generate()?;  // Do once
   for i in 0..1000 {
       let encrypted = encrypt_aes_gcm(&data[i], key.symmetric.as_bytes(), b"")?;
   }
   ```

2. **Batch Operations**: Process multiple items together
   ```rust
   let encrypted_items: Vec<_> = items
       .iter()
       .map(|item| encrypt_aes_gcm(item, &key, b""))
       .collect::<CryptoResult<_>>()?;
   ```

3. **Use Appropriate TTL**: Balance security and usability
   ```rust
   let short_lived = Token::new(300);    // 5 minutes
   let long_lived = Token::new(86400);   // 1 day
   ```

---

## Security Best Practices

1. **Never log sensitive data**
   ```rust
   // DON'T:
   println!("Private key: {:?}", private_key);
   
   // DO:
   println!("Generated key: {}", key.id.encode());
   ```

2. **Zeroize sensitive buffers**
   ```rust
   let mut buffer = [0u8; 32];
   // ... use buffer ...
   buffer.zeroize();  // Explicitly clear
   ```

3. **Validate token expiry**
   ```rust
   if token.validate()? {
       // Token is valid and not expired
   } else {
       return Err(CryptoError::Serialization("Token expired".to_string()));
   }
   ```

4. **Use strong randomness**
   - All `Id::new()` calls use `rand::thread_rng()`
   - Cryptographically secure by default

---

## Full Example: User Authentication

```rust
async fn example_user_auth() -> CryptoResult<()> {
    // Registration phase
    let user_id = Id::new(32);
    let primary_key = PrimaryKey::new();
    
    // Derive password hash
    let password_hash = primary_key.derive(Some(b"user@example.com"))?;
    println!("Storing password hash: {}", hex::encode(&password_hash));

    // Login phase - later
    let login_key = PrimaryKey::new();
    let stored_hash = primary_key.derive(Some(b"user@example.com"))?;
    
    // Note: In practice, use constant-time comparison
    if password_hash == stored_hash {
        println!("✓ Password verified!");

        // Generate session token
        let mut session = Token::new(3600);  // 1 hour session
        session.sign()?;
        
        println!("Session token: {}", session.id.encode());
    }

    Ok(())
}
```

---

## Testing

Run the included tests:

```bash
# Test everything
cargo test --lib blackbook_core

# Test with output
cargo test --lib blackbook_core -- --nocapture --test-threads=1
```

---

**Version**: 0.1.0  
**Updated**: March 16, 2026  
**Status**: Production Ready
