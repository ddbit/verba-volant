Verba Volant Protocol
=============


**Overview**
Verba Volant uses ephemeral ECDH (e.g., over P-256) to derive a shared AES-GCM session key. Public keys are exchanged over a WebSocket channel routed through a server. While the server cannot decrypt messages post key exchange, it can potentially perform a MITM attack by intercepting and replacing the public keys exchanged during session setup. This would allow the server to derive two separate shared keys (one with Alice, one with Bob) and transparently proxy encrypted messages.

---

**Protocol Flow**

1. **Alice generates a Room ID**

   * A random string used to establish the session.

2. **Alice sends the Room ID via an OOB channel**

   * This channel is authentic (Bob knows it's from Alice) but may be observable.

3. **Alice and Bob each generate ephemeral ECDH key pairs**

   * These keys are used once, then discarded.

4. **Each client sends its public key to the server**

   * The server forwards the keys to the opposite party.

5. **Alice computes an authentication code (authcode)**

   * Derived from a hash of both ephemeral public keys.
   * Only the first N×11 bits of the hash are used and mapped to N BIP39 words (with N selectable by the user).

6. **Alice sends the N-word authcode via the OOB channel**

7. **Bob computes the same fingerprint and compares it to Alice's message**

   * If the words match, Bob confirms:

     * The key received from Alice is genuine.
     * Alice has also received his real key.
     * No MITM attack occurred.

---

**Fingerprint Derivation**

1. `input = ordered(pubkeyA, pubkeyB)`
2. `hash = SHA-256(input)`
3. `bits = first N×11 bits of hash`
4. `authcode = map bits to N BIP39 words (each word = 11 bits)`

Canonical ordering ensures both parties compute the same input regardless of direction, eliminating ambiguity.

In the Verba Volant app, the parameter N (number of BIP39 words) can be selected by the user, balancing **usability** and **security**. A higher N increases entropy but makes verification more burdensome.

The default and recommended value is **N = 5**, which is used in the following analysis.

---

**Cryptographic Strength of 5-Word Fingerprint**

* 5 BIP39 words = 55 bits of entropy
* Second preimage resistance = 2^55

**Attack Feasibility Table**

| Attacker Resources  | Hash Rate   | Attempts in 60s | % of 2^55 Space |
| ------------------- | ----------- | --------------- | --------------- |
| Standard CPU        | 100,000/sec | 6 × 10^6        | \~1.7 × 10^-10  |
| Single high-end GPU | 10^7/sec    | 6 × 10^8        | \~1.7 × 10^-8   |
| 1000-GPU cluster    | 10^10/sec   | 6 × 10^11       | \~1.7 × 10^-5   |

Conclusion: Forgery is infeasible under realistic time/resource constraints.

---

**Comparison with Signal's ZRTP Short Authentication String (SAS)**

| Feature                    | Signal ZRTP SAS                    | Verba Volant Fingerprint            |
| -------------------------- | ---------------------------------- | ----------------------------------- |
| Key persistence            | Required (long-term ID + pre-keys) | None (ephemeral keys only)          |
| Hash input basis           | Shared secret (post-handshake)     | Public keys only (pre-handshake)    |
| Authcode format            | 6 digits or 2 words (24 bits)      | N BIP39 words (default: 5, 55 bits) |
| Verification direction     | Mutual                             | One-way (sufficient for both sides) |
| Role of human verification | Confirmation after secure session  | Bootstraps trust before encryption  |
| Identity traceability      | Persistent                         | Stateless and unlinkable            |
| Suitable for               | Ongoing secure communication       | Temporary, untraceable exchanges    |

---

**Justification**
Signal's ZRTP SAS is used *after* secure session establishment and based on long-term identities. Verba Volant provides a stateless alternative, authenticating users in real time with no persistent identifiers. This aligns with the project’s goal:

> **You shall not track.**

The N-word BIP39 fingerprint is short enough for voice-based or messaging-based confirmation and strong enough to resist forgery during the limited verification window. Users can adjust N according to their threat model and tolerance for manual verification effort.

---

**Summary**

* Effective MITM detection without persistent keys or identities
* Strong practical security using only ephemeral public keys and SHA-256
* Compact, human-verifiable authentication via configurable BIP39 words (N)
* Zero-trace architecture, suitable for environments requiring forensics resistance

The approach is minimalist, privacy-preserving, and intentionally transient. It assumes no infrastructure, no long-term keys, and no secrets stored anywhere.
