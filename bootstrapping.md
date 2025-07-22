# Verba Volant: Bootstrapping and MITM mitigation

## Overview

The Verba Volant architecture is designed to provide end-to-end encrypted (E2EE) messaging between two clients connected via an untrusted server. One of the critical threats in such a model is the **man-in-the-middle (MITM) attack** during the key exchange phase. This document outlines the nature of the MITM risk, the assumptions made, and the mechanism implemented to mitigate it, without relying on persistent identities or formal public key infrastructure (PKI).

## Threat: MITM During Ephemeral Key Exchange

Verba Volant uses ephemeral ECDH (e.g., over P-256) to derive a shared AES-GCM session key. Public keys are exchanged over a WebSocket channel routed through a server. While the server cannot decrypt messages post key exchange, it can potentially perform a MITM attack by intercepting and replacing the public keys exchanged during session setup. This would allow the server to derive two separate shared keys (one with Alice, one with Bob) and transparently proxy encrypted messages.

## Setup the communication

### Select the Room ID

The very first out-of-band message between Alice and Bob must be used to share the room ID. This room ID can be any arbitrary string or identifier, and is assumed to be observable by the server. Once used to create or join a session, the server knows this identifier, and thus it should not be relied upon for any form of secrecy or authentication.

* Clients run verified, local code (not loaded dynamically from the server)
* The server may be observed or controlled by an attacker
* There exists an out-of-band (OOB) channel between users that is:

  * **Authentic**: identities are known
  * **Observable**: contents may be read by an attacker, but cannot be altered


## Verba Volant – Protocol Flow 

1. **Alice generates the Room ID**
   Alice creates a random or arbitrary identifier that will define the communication session.

2. **Alice sends the Room ID via the OOB channel**
   Alice shares the Room ID using an out-of-band channel (e.g., Signal, WhatsApp, voice call).

3. **The OOB channel delivers the Room ID to Bob**
   Bob receives the Room ID through the same out-of-band channel.

4. **Alice generates her ephemeral public key and sends it to the server**
   This key is part of an ephemeral ECDH key pair, used to establish the shared session key.

5. **Bob generates his ephemeral public key and sends it to the server**
   Bob also creates an ephemeral ECDH key pair and sends the public key to the server.

6. **The server forwards Bob’s public key to Alice**

7. **The server forwards Alice’s public key to Bob**

8. **Alice computes the authentication code (5 words)**
   Using both ephemeral public keys (hers and Bob's), she computes:

   ```
   authcode = BIP39(SHA256(min(pubkey_Alice, pubkey_Bob) || max(pubkey_Alice, pubkey_Bob)))[0:5]
   ```

9. **Alice sends the 5-word authentication code via the OOB channel**

10. **The OOB channel delivers the 5-word code to Bob**

11. **Bob recomputes the code locally and verifies that it matches**
    If it matches, Bob can be confident that:

    * He has the correct public key from Alice
    * Alice has received his correct public key
    * No MITM attack occurred during key exchange



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


## Final Notes

This mechanism provides a lightweight but effective layer of authentication on top of the E2EE protocol. It is particularly suited for environments where infrastructure is minimal, but where trust between participants is established through existing social or secure channels.

The mnemonic nature of Bitcoin words makes possible the exchange of the session authentication code in many possible ways, including phone calls, whatsapp or others.

The model does not aim to protect anonymity or metadata, but focuses on ensuring that the encrypted session truly occurs between the intended peers, even if the server or transport channel is compromised.


### Why Not Use a Single User Key?

One might ask: why not generate a single persistent key per user and derive a fixed 5-word authentication code from it, instead of generating new ephemeral keys for every session?

While simpler, this approach introduces a stable identity, which can be tracked across sessions. Verba Volant explicitly avoids persistent identifiers to ensure unlinkability and forward secrecy.

**Ephemeral session keys** are essential to the protocol’s goal:

> **no identity must be tracked, ever.**

