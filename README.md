# Verba Volant: Technical Specifications for a Forensics resistant Web Chat Service with Diffie-Hellman

## Disclaimer

This software is intended to enhance user privacy in lawful scenarios such as journalism, corporate confidentiality, and personal communication. It is not designed, intended, or recommended for any use that violates the law.

## Threat Model

The system is designed under the assumption that the server operates outside the reach of any potential attacker, yet a compromised server won't affect the overall security goals of this app. The primary objective is to eliminate the possibility of future forensic analysis on user devices. This means:

* No persistent logs or data are stored locally or remotely.
* Messages are never written to disk.
* Encryption keys are derived ephemerally per session.
* Only encrypted content is transmitted; metadata is minimized.

The model assumes that Alice and Bob know each other and coordinate the conversation setup through a secure out-of-band channel. The room ID is shared securely and used to bootstrap a private session. If no attacker is present during this exchange, and the Diffie-Hellman key exchange proceeds without tampering, the system is effectively resistant to MITM attacks. The server is assumed to be honest-but-curious.

---

## Objective

Create a web service that allows two users to:

1. Connect to the same "room".
2. Perform a secure key exchange using Diffie-Hellman (DH).
3. Establish a shared key for end-to-end encryption.
4. Exchange encrypted messages using AES (true E2EE).

The server handles the connection but **has no access to the messages or the shared key**.

No message or event will be stored on the server, and to prevent any forensic analysis, the client operates in the following way:

* Alice writes a new message in a dedicated Send text area; the message is never stored on local or remote disk.
* The message exists only in the DOM.
* Once the message is sent to Bob, and Bob's client acknowledges receipt, the message is marked as delivered (but not necessarily read) on Alice's side.
* Bob receives the message in a dedicated Receive area and can reply using his own Send component, functioning in the same way as Alice’s.

The rationale is that messages remain only as long as needed and no logs or events are recorded locally or online. Forensic analysis should be unable to recover conversations from user devices. Likewise, data recovery from the online server is not possible, as chats are end-to-end encrypted.

To bootstrap a conversation, Alice generates a random ID and shares it with Bob through a secure external channel.

**Important Note:** Although deriving the AES key directly from the shared room ID might appear simpler, this approach would allow the server (which knows the room ID) to recreate the encryption key, defeating the purpose of E2EE. Therefore, the system uses a Diffie-Hellman key exchange to ensure the encryption key is never exposed to the server.

The threat model assumes that the server runs outside the reach of any attacker and aims to prevent any future forensic analysis on the user devices.

---

## Architecture

```
Client A         Server           Client B
   │               │                 │
   ├── join room ─▶│◀── join room ───┤
   │               │                 │
   ├─ send DH pubkey ──────────────▶│──────────────▶ Client B
   │               │                 │
   │◀────────────── pubkey B ────────┤
   │               │                 │
   ├─ derive shared key              ┤
   │               │                 │
   ├─ send encrypted message ──────▶│──────────────▶ Client B
```

---

## Technology Stack

| Component  | Technologies                                    |
| ---------- | ----------------------------------------------- |
| Backend    | Node.js + WebSocket (`ws`)                      |
| Frontend   | HTML + JavaScript (vanilla or optionally React) |
| Crypto     | Web Crypto API (browser) / Node.js `crypto`     |
| Encryption | AES-GCM with key derived from DH                |
| Keys       | Diffie-Hellman (ECDH over P-256 or X25519)      |

---

## System Features

### 1. Room Management

* User A creates a room (unique ID or name)
* User B joins the same room
* The server manages only message routing (WebSocket rooms)

### 2. DH Key Exchange

* Clients generate ephemeral DH key pairs
* Exchange public keys via WebSocket
* Derive the shared key client-side

### 3. AES Key Derivation

* HKDF/SHA-256 from DH secret
* AES-GCM for encryption/decryption
* Random IV (nonce) per message

### 4. Encrypted Message Exchange

* Messages are encrypted client-side with AES-GCM
* The server only relays encrypted messages
* The server stores nothing (RAM only or stateless)
* The client does not persist messages locally

---

## Privacy & Security

| Aspect                | Status     | Notes                                            |
| --------------------- | ---------- | ------------------------------------------------ |
| End-to-End Encryption | ✅ Active   | No private keys on server                        |
| Forward Secrecy       | ✅ Yes      | Thanks to ephemeral DH                           |
| Visible Metadata      | ✅ Limited  | Only IP, unless using Tor/VPN                    |
| Message Persistence   | ❌ No       | No logging or storage                            |
| Anonymity             | ✅ Possible | No login required                                |
| Decentralization      | ❌ No       | Centralized service, but extendable (e.g. onion) |
| Forensic Resistance   | ✅ Yes      | No disk storage, messages live in-memory only    |

---

## WebSocket Message Format

```json
{
  "type": "pubkey",
  "data": {
    "publicKey": "..."
  }
}

{
  "type": "message",
  "data": {
    "ciphertext": "...",
    "iv": "..."
  }
}
```

---

## Future Work: Optional MITM Mitigation

To eliminate even the minimal risk of a man-in-the-middle (MITM) attack during the key exchange, Verba Volant can be extended to support public key fingerprint verification:

* Each client would compute a fingerprint (e.g., SHA-256 hash) of its ephemeral DH public key.
* This fingerprint can then be shared out-of-band (alongside the room ID) and verified by the peer before continuing communication.
* This additional step ensures the authenticity of the key exchange and closes the MITM attack vector.

This enhancement is not part of the initial version and may be considered for future implementation.

---

## Additional Considerations

* No login or user identity used
* No public publishing interface (only 1:1 communication)
* Future extension possible for group messaging using MLS (Messaging Layer Security)
* Possible QR code integration for initial exchange
* Secure bootstrap using random room ID shared out-of-band

---

## Comparison with Nostr, Signal, and Verba Volant

### Feature Comparison

| Aspect               | Nostr     | Verba Volant                                   | Signal                          |   |
| -------------------- | --------- | ---------------------------------------------- | ------------------------------- | - |
| Content Encryption   | ✅ Yes     | ✅ Yes                                          | ✅ Yes                           |   |
| Forward Secrecy      | ❌ No      | ✅ Yes                                          | ✅ Yes (Double Ratchet)          |   |
| Metadata Privacy     | ❌ No      | ✅ Yes                                          | ⚠️ Partial (requires efforts)   |   |
| Anonymity            | ❌ Limited | ✅ Full                                         | ❌ Requires phone number         |   |
| Decentralization     | ✅ High    | ❌ Low (but extendable)                         | ❌ No                            |   |
| Client Compatibility | ✅ Wide    | ❌ Only dedicated clients                       | ✅ Wide                          |   |
| Forensic Resistance  | ❌ No      | ✅ Yes                                          | ⚠️ Partial (some logs possible) |   |
| MITM Resistance      | ❌ No      | ✅ Yes (with optional fingerprint verification) | ✅ Yes (with key verification)   |   |

|   |
| - |
