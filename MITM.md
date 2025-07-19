# Verba Volant: MITM Risk and Mitigation Strategy

WORK IN PROGRESS ...

## Overview

The Verba Volant architecture is designed to provide end-to-end encrypted (E2EE) messaging between two clients connected via an untrusted server. One of the critical threats in such a model is the **man-in-the-middle (MITM) attack** during the key exchange phase. This document outlines the nature of the MITM risk, the assumptions made, and the mechanism implemented to mitigate it, without relying on persistent identities or formal public key infrastructure (PKI).

## Threat: MITM During Ephemeral Key Exchange

Verba Volant uses ephemeral ECDH (e.g., over P-256) to derive a shared AES-GCM session key. Public keys are exchanged over a WebSocket channel routed through a server that is considered honest-but-curious. While the server cannot decrypt messages post key exchange, it can potentially perform a MITM attack by intercepting and replacing the public keys exchanged during session setup. This would allow the server to derive two separate shared keys (one with Alice, one with Bob) and transparently proxy encrypted messages.

## Assumptions

### About the Room ID

The very first out-of-band message between Alice and Bob must be used to share the room ID. This room ID can be any arbitrary string or identifier, and is assumed to be observable by the server. Once used to create or join a session, the server knows this identifier, and thus it should not be relied upon for any form of secrecy or authentication.

* Clients run verified, local code (not loaded dynamically from the server)
* The server may be observed or controlled by an attacker
* There exists an out-of-band (OOB) channel between users that is:

  * **Authentic**: identities are known
  * **Observable**: contents may be read by an attacker, but cannot be altered

## Recommended Mitigation: Joint Public Key Authentication Code

To provide mutual authentication while minimizing the complexity of the out-of-band exchange, Verba Volant uses a code derived from both parties' ephemeral public keys:

### Protocol Flow

1. Alice and Bob both generate their ephemeral public keys and join the same room.

2. Once both public keys are exchanged, **Alice** computes:

   ```
   authcode = BIP39(SHA256(min(pubkey_Alice, pubkey_Bob) || max(pubkey_Alice, pubkey_Bob)))[0:5]
   ```

   where `min` and `max` refer to lexicographical ordering to ensure determinism.

3. Alice sends the resulting **5-word authentication code** to Bob via an out-of-band channel (e.g., Signal, WhatsApp, voice call).

4. Bob receives the same public keys via the WebSocket channel, performs the same calculation, and verifies the code.

5. If the codes match, the session is mutually authenticated.

## Cryptographic Strength

* The BIP-39 word list contains 2048 words.

* Using 5 words yields:

  ```
  log2(2048^5) = 11 × 5 = 55 bits of entropy
  ```

* This provides a secure preimage resistance against brute-force attacks, even if the attacker observes the out-of-band message and controls the server.

* The attacker would need to compute approximately $2^{54}$ key pairs to find a matching code, which is computationally infeasible.

## Advantages of This Approach

* **Mutual authentication** with only one out-of-band message
* **No persistent keys**, signatures, or digital certificates
* **Human-verifiable code**: 5 BIP-39 words are easy to read and compare
* **Resistance to MITM** even under strong attacker capabilities
* **Deterministic and symmetric**: both parties compute the same code regardless of their roles

## Alternatives Considered

Other approaches were considered and documented:

### A. Code Derived from One Public Key

* Only one party (e.g., Alice) generates a code from their own public key.
* Bob receives the code OOB and verifies it once he receives Alice’s key in-band.
* This authenticates only one direction and is vulnerable to preimage attacks on just 55 bits.

### B. Each Party Sends Their Own Code

* Both Alice and Bob generate separate codes from their own keys and exchange them OOB.
* Requires two messages, increases complexity.
* Still subject to individual brute-force attempts.

### C. SAS Based on Concatenated Keys (Recommended)

* Both public keys are used as input.
* No way to precompute or spoof a code without knowing both keys.
* A single code exchanged OOB is sufficient.

## Final Notes

This mechanism provides a lightweight but effective layer of authentication on top of the E2EE protocol. It is particularly suited for environments where infrastructure is minimal, but where trust between participants is established through existing social or secure channels.

The model does not aim to protect anonymity or metadata, but focuses on ensuring that the encrypted session truly occurs between the intended peers, even if the server or transport channel is compromised.
