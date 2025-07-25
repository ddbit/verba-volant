# Verba Volant Protocol

## Overview

Verba Volant implements a secure, ephemeral, and forensic-resistant messaging protocol. It allows two users to establish a confidential, stateless, and anonymous communication session, with no persistent traces left on client or server.

The core of the protocol is an ephemeral ECDH key exchange, verified through a human-readable fingerprint (BIP39 words), and followed by end-to-end encryption using AES-GCM. Messages are decrypted only on user request, shown temporarily in the DOM, and never stored.

---

## Threat Model

* **Server is untrusted**: it relays messages but cannot decrypt them.
* **Out-of-band (OOB) channel**:

  * Authenticated (attacker cannot modify messages)
  * Observable (attacker may read but not alter them)
* **Attacker capabilities**:

  * Control of the relay server (MITM attempt)
  * RAM inspection via live malware during active session

---

## Protocol Flow

1. **Room ID generation**

   * Alice creates a random room ID (short string).

2. **Room ID shared via OOB**

   * Alice sends the ID to Bob via an authenticated but observable channel.

3. **Ephemeral key generation**

   * Both clients generate temporary ECDH key pairs (P-256 or X25519).

4. **Key exchange over WebSocket**

   * Public keys are exchanged through the relay server.

5. **Fingerprint computation**

   * Each party computes a hash of both public keys (canonical order)
   * First N×11 bits of the SHA-256 hash are mapped to N BIP39 words (default N = 5)

6. **Authcode sent via OOB**

   * Alice sends her 5-word code to Bob via the same OOB channel.

7. **Verification**

   * Bob computes the same code and compares: if it matches, key authenticity is verified.

8. **Session key derivation**

   * Shared key is derived and used for AES-GCM encryption.

9. **Message exchange**

   * Messages are encrypted client-side and decrypted only when requested.

---

## Fingerprint Derivation

```text
input = ordered(pubkeyA, pubkeyB)
hash = SHA-256(input)
bits = first N×11 bits
authcode = map bits to N BIP39 words
```

This guarantees that both parties compute the same verification code, without revealing secrets.

---

## DOM-Based Message Handling

* Encrypted messages remain in memory until explicitly decrypted.
* Decryption happens only on user request (e.g., click-to-reveal).
* The decrypted message is inserted into the DOM and never written to disk.
* When the page closes or reloads, the message disappears.
* No use of localStorage, IndexedDB, filesystem API, or cache.

---

## Cryptographic Design

* **Key Exchange**: ECDH (P-256 or X25519)
* **Key Derivation**: HKDF with SHA-256
* **Encryption**: AES-GCM with unique IV per message
* **Authentication**: BIP39-based fingerprint (default: 5 words = 55 bits)

---

## Security Properties

| Property              | Status                                       |
| --------------------- | -------------------------------------------- |
| End-to-End Encryption | ✅ Enabled (client-to-client only)            |
| Forward Secrecy       | ✅ Yes (ephemeral key pairs)                  |
| MITM Protection       | ✅ Via manual fingerprint check               |
| Metadata Protection   | ✅ No identifiers or long-term keys           |
| Message Storage       | ✅ None (not on disk, only RAM)               |
| Identity Traceability | ✅ None (no login, no device binding)         |
| Forensic Resistance   | ✅ Very high (RAM-only exposure window)       |
| Server Visibility     | ✅ Zero visibility (no key or message access) |

---

## Limitations

* RAM-level attacks are possible **only** if the device is compromised **during message viewing**.
* MITM attacks are possible if users skip fingerprint verification.

---

## Summary

Verba Volant offers a minimalist protocol focused on human-verifiable authentication, ephemeral keys, and zero persistence. It is built for highly sensitive contexts where leaving no trace is essential.

> **You shall not track.**
