# Certificate Encryption System Documentation

## Overview

This system implements a sophisticated multi-layered encryption scheme for protecting private keys of ACME certificates. The design supports both per-device encryption and master key fallback, providing flexibility for different deployment scenarios while maintaining strong security guarantees.

## Architecture Components

### 1. Database Schema

#### Core Tables

**`cert_records`**
- Stores certificate metadata and encrypted private keys
- Key fields:
  - `enc_scheme`: Encryption algorithm identifier (1 = AES-256-GCM)
  - `enc_privkey`: AES-256-GCM encrypted private key DER
  - `privkey_nonce`: 12-byte nonce for AES-256-GCM
  - `privkey_tag`: 16-byte authentication tag for AES-256-GCM

**`user_devices`** 
- Tracks user devices with cryptographic identities
- Key fields:
  - `device_secret_hash`: Hash of device public key (for authentication)
  - `fp_hash`: Optional fingerprint hash
  - Device metadata (platform, model, etc.)

**`cert_record_devices`**
- Many-to-many mapping between certificates and authorized devices
- Key fields:
  - `device_keyfp`: Raw 32-byte fingerprint of device public key
  - `enc_data_key`: Wrapped/sealed symmetric data key (via X25519/crypto_box_seal)
  - `wrap_alg`: Wrapping algorithm (currently "x25519")

**`cert_record_master_wrapped`**
- Fallback storage for data keys wrapped with master keys
- Used when no devices are available at certificate creation time
- Key fields:
  - `key_version`: Master key version used for wrapping
  - `wrapped_data_key`: AES-256-GCM encrypted data key
  - `nonce`, `tag`: AES-256-GCM parameters

**`master_keys`**
- System-level master keys for fallback encryption
- Keys are themselves encrypted with envelope keys
- Supports key rotation and versioning

## Encryption Flows

### Flow 1: Device-Based Encryption (Preferred Path)

This is used when devices are registered before certificate creation.

#### 1. Setup Phase
```
User Device Registration:
├── Generate X25519 keypair (dev_pk, dev_sk)
├── Compute fingerprint: fp = BLAKE2b(dev_pk, 32 bytes)
├── Store in user_devices: device_secret_hash = fp
└── Store in user_keys: public_key = dev_pk, fingerprint = fp
```

#### 2. Certificate Creation & Encryption
```
Certificate Private Key Encryption:
├── Generate random 32-byte data key
├── Encrypt private key: AES-256-GCM(data_key, privkey_der)
│   ├── Generate random 12-byte nonce
│   ├── Produce ciphertext and 16-byte auth tag
│   └── Store: enc_privkey, privkey_nonce, privkey_tag
├── Wrap data key for each authorized device:
│   ├── Use crypto_box_seal(data_key, device_public_key)
│   └── Store in cert_record_devices table
└── Set enc_scheme = 1 (AES-256-GCM)
```

#### 3. Device Retrieval & Decryption
```
Certificate Private Key Retrieval:
├── Fetch encrypted certificate data from cert_records
├── Find device mapping in cert_record_devices
├── Unwrap data key: crypto_box_seal_open(sealed_key, dev_pk, dev_sk)
├── Decrypt private key: AES-256-GCM_decrypt(data_key, enc_privkey, nonce, tag)
└── Return plaintext private key DER
```

### Flow 2: Master Key Fallback

This is used when no devices are registered at certificate creation time.

#### 1. Master Key Setup
```
Master Key Infrastructure:
├── Envelope Key: 32-byte key from environment (MASTER_KEY_ENVELOPE_KEY_HEX)
├── Master Key: 32-byte random key, encrypted with envelope key
├── Store encrypted master key in master_keys table
└── Support versioning for key rotation
```

#### 2. Certificate Creation (No Devices Available)
```
Fallback Certificate Encryption:
├── Generate random 32-byte data key  
├── Encrypt private key: AES-256-GCM(data_key, privkey_der)
├── Wrap data key with master key: AES-256-GCM(master_key, data_key)
└── Store wrapped key in cert_record_master_wrapped
```

#### 3. Device Registration & Migration
```
Device Addition to Existing Certificate:
├── Decrypt master-wrapped data key using active master key
├── Wrap data key for new device: crypto_box_seal(data_key, device_pk)
├── Store device mapping in cert_record_devices
└── Remove master-wrapped entry (migrate to per-device)
```

#### 4. Master Key Rotation
```
Envelope Key Rotation:
├── Decrypt all master keys with old envelope key
├── Re-encrypt all master keys with new envelope key  
├── Update master_keys table with new encrypted values
└── Maintain same plaintext master keys (transparent rotation)
```

## Security Properties

### 1. Defense in Depth
- **Layer 1**: Private keys encrypted with random data keys (AES-256-GCM)
- **Layer 2**: Data keys wrapped per-device (X25519 + ChaCha20-Poly1305) 
- **Layer 3**: Master key fallback with envelope key protection

### 2. Forward Security
- Data keys are randomly generated per certificate
- Device compromise doesn't affect other certificates
- Master key rotation preserves old certificate access

### 3. Access Control
- Device fingerprints ensure only authorized devices can unwrap
- Per-certificate per-device granular access control
- Master key fallback allows administrative access

### 4. Cryptographic Algorithms
- **Symmetric Encryption**: AES-256-GCM (authenticated encryption)
- **Key Exchange**: X25519 elliptic curve Diffie-Hellman
- **Sealing**: NaCl crypto_box_seal (X25519 + ChaCha20-Poly1305)
- **Hashing**: BLAKE2b for fingerprints

## Key Management

### Device Keys
- X25519 keypairs generated per device
- Public keys stored in user_keys table
- Private keys remain on device (never transmitted)
- Fingerprints used for device identification and integrity

### Data Keys  
- 256-bit random keys generated per certificate
- Used for AES-256-GCM encryption of private keys
- Wrapped per authorized device or with master key
- Never stored in plaintext

### Master Keys
- 256-bit system-level keys for fallback scenarios  
- Encrypted at rest with envelope keys
- Support versioning and rotation
- Used only when device-based wrapping unavailable

### Envelope Keys
- 256-bit keys from environment variables
- Used to encrypt master keys at rest
- Enable master key rotation without DB migration
- Must be securely managed outside the database

## Implementation Details

### Encryption Functions
```cpp
// AES-256-GCM encryption (in MasterKeyStore)
bool aes256gcm_encrypt(
    const std::vector<unsigned char>& key,      // 32 bytes
    const std::vector<unsigned char>& plaintext,
    std::vector<unsigned char>& nonce,          // 12 bytes (generated)
    std::vector<unsigned char>& ciphertext, 
    std::vector<unsigned char>& tag             // 16 bytes
);

// X25519 sealing (via libsodium)
int crypto_box_seal(
    unsigned char* ciphertext,
    const unsigned char* plaintext, unsigned long long plaintext_len,
    const unsigned char* recipient_pk
);
```

### Decryption Implementation Notes
- Backend storage keeps the AES-GCM components separate: `enc_privkey`
  contains only ciphertext bytes, while the 16-byte authentication tag lives in
  `privkey_tag` and the 12-byte nonce in `privkey_nonce`. The backend never
  appends the tag to `enc_privkey_b64`; clients must join the ciphertext and
  tag locally when invoking AES-GCM decryption routines that expect a
  contiguous buffer.
- OpenSSL-style APIs accept the tag as an independent input; pass
  `privkey_tag` via `EVP_CIPHER_CTX_ctrl(..., EVP_CTRL_GCM_SET_TAG, ...)`.
- Libsodium’s `crypto_aead_aes256gcm_decrypt` expects the ciphertext and tag
  to be contiguous. Re-attach the tag before calling the function:

  ```cpp
  std::vector<unsigned char> enc = base64_decode(bundle.enc_privkey);
  std::vector<unsigned char> tag = base64_decode(bundle.privkey_tag);
  std::vector<unsigned char> nonce = base64_decode(bundle.privkey_nonce);
  std::vector<unsigned char> data_key = unwrap_device_key(...); // 32 bytes

  enc.insert(enc.end(), tag.begin(), tag.end());

  std::vector<unsigned char> plaintext(enc.size() - crypto_aead_aes256gcm_ABYTES);
  unsigned long long pt_len = 0;
  int rc = crypto_aead_aes256gcm_decrypt(
      plaintext.data(), &pt_len,
      nullptr,
      enc.data(), enc.size(),
      nullptr, 0,
      nonce.data(),
      data_key.data());
  if (rc != 0) { /* authentication failed */ }
  plaintext.resize(pt_len);
  ```
- Always decode the bundle fields from base64 before use. Binary DER material
  will not survive JSON transport without decoding.
- Check `crypto_aead_aes256gcm_is_available()` on the client. Libsodium’s
  AES-GCM bindings require hardware AES acceleration; if it returns `0`, fall
  back to OpenSSL or another supported implementation.

### Troubleshooting

- **AES-GCM tag mismatch**: If authentication fails after re-attaching the
  tag, verify that each authorized device has a freshly wrapped data key.
  Earlier versions of `AcmeStoreMysql::update_cert` updated only the first
  entry in the `insert_data` collection, leaving other devices with stale
  `enc_data_key_b64` values. Ensure the server iterates over every entry so the
  wrapped data key remains in sync with the ciphertext and tag delivered to the
  device.

### Database Operations
- **CertRecordDevicesStore**: Manages per-device key wrappings
- **CertRecordMasterWrappedStore**: Handles master key fallback
- **MasterKeyStore**: Master key lifecycle and rotation
- **UserKeysStore**: Device public key storage

## Operational Workflows

### Certificate Issuance
1. Check if user has registered devices
2. If devices exist: Use device-based encryption (Flow 1)
3. If no devices: Use master key fallback (Flow 2)
4. Store encrypted certificate with appropriate wrapping method

### Device Registration
1. Generate X25519 keypair on device
2. Register public key and fingerprint with server
3. For existing certificates: migrate from master-wrapped to device-wrapped

### Key Rotation
1. **Envelope Key Rotation**: Re-encrypt master keys, transparent to certificates
2. **Master Key Rotation**: Generate new master key, migrate existing wrappings
3. **Device Key Rotation**: Generate new device keys, update all certificate mappings

### Access Control
- Users can only access their own certificates  
- Devices can only unwrap keys they're authorized for
- Master key fallback provides administrative override capability

## Security Considerations

### Threat Model
- **Device Compromise**: Other certificates remain secure
- **Database Breach**: Private keys protected by multiple encryption layers
- **Key Rotation**: Forward security maintained through proper key lifecycle
- **Administrative Access**: Master key fallback allows recovery scenarios

### Limitations
- Envelope key security critical for master key protection
- Device private key compromise affects that device's certificates
- Master key compromise affects fallback-encrypted certificates

### Best Practices
- Regular envelope key rotation
- Secure device key generation and storage
- Monitoring for unusual access patterns
- Proper backup and recovery procedures for envelope keys

## Error Handling

### Decryption Failures
- Wrong envelope key: `has_plain = false` in master key records
- Device key mismatch: crypto_box_seal_open fails
- Corrupted ciphertext: AES-GCM authentication tag verification fails

### Recovery Scenarios  
- Device loss: Admin can migrate to master key, then to new device
- Master key compromise: Generate new master key, re-wrap affected certificates
- Envelope key loss: Requires master key regeneration and certificate re-encryption

This encryption system provides strong security guarantees while maintaining operational flexibility for certificate management in ACME environments.
