# Verba Volant: Technical Specifications for a Forensics resistant Web Chat Service with Diffie-Hellman

## Disclaimer

This software is intended to enhance user privacy in lawful scenarios such as journalism, corporate confidentiality, and personal communication. It is not designed, intended, or recommended for any use that violates the law.

## Threat Model

The system is designed under the assumption that a compromised server won't affect the overall security goals of this app which are: 

- to eliminate the possibility of future forensic analysis on user devices; 
- to keep conversation private end-to-end. 

This means:

* No persistent logs or data are stored locally or remotely.
* Messages are never written to disk.
* Encryption keys are derived ephemerally per session.
* Only encrypted content is transmitted; metadata is minimized.

The model assumes that Alice and Bob know each other and coordinate the conversation setup through a out-of-band channel. The out-of-band (OOB) channel is assumed to be:

- insecure in terms of privacy: Alice accepts that the attacker is able to observe the messages in the out-of-band channel.

- authenticated: Alice can safely assume that the other end in the out-of-band is Bob.


The room ID is shared on the OOB and used to bootstrap a private session. The system shall be resistant to MITM attacks. 

---

## Objective

Create a web service that allows two users to:

1. Connect to the same "room".
2. Authenticate each other (but not with the server)
3. Perform a secure key exchange using Diffie-Hellman (DH).
4. Establish a shared key for end-to-end encryption.
5. Exchange encrypted messages using AES (true E2EE).

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

**Critical Security Requirement - Client Code Distribution:**

For maximum security, the client code (HTML, JavaScript, CSS) must be distributed separately from the server and never downloaded from the server during runtime. This ensures:

* Users can verify the client code before use
* No possibility of server-side code injection or tampering
* Client can be stored locally and used offline for connection
* Complete separation between server (message routing) and client (encryption)

The client application should be distributed as a self-contained package that users can download, verify, and run independently. The server only provides WebSocket connectivity for message routing.

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

## MITM Attack Mitigation

As an additional defense against man-in-the-middle attacks during the key exchange, the Verba Volant client may generate a 4-digit PIN derived from the user's ephemeral public key (e.g., using SHA-256 and a modulo operation).

This PIN can be shared out-of-band (e.g., via voice call, secure message, or QR code) before the session begins.

The receiving client computes the PIN from the received public key and compares it with the expected value.

If the PINs do not match, the session is considered compromised and should be aborted.

### Practical Out-of-Band Channel Considerations

In practice, if users have access to an out-of-band channel that is not confidential (i.e., messages may be observed) but is authentic (i.e., the identity of the counterpart is known and trusted), that channel can serve as a lightweight certification mechanism for verifying the authenticity of a public key.

For example, messaging platforms like WhatsApp or Signal — although not anonymous or metadata-free — offer identity persistence and authentication guarantees. If Alice receives a 4-digit PIN or a public key fingerprint from Bob via such a channel, and she knows it's really Bob, she can reasonably assume the key is authentic, even if the message may be observable.

In this sense, authentic but observable channels can act as informal certification authorities, enabling secure bootstrapping of trust without requiring a formal PKI or identity infrastructure.



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
