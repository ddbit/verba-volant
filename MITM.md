# Verba Volant: MITM Risk and Mitigation Strategy

WORK IN PROGRESS...

## Overview

The Verba Volant architecture is designed to provide end-to-end encrypted (E2EE) messaging between two clients connected via an untrusted server. One of the critical threats in such a model is the **man-in-the-middle (MITM) attack** during the key exchange phase. This document outlines the nature of the MITM risk, the assumptions made, and the lightweight mechanisms implemented to mitigate it without relying on persistent identities or a formal public key infrastructure (PKI).

## Threat: MITM During Ephemeral Key Exchange

The current protocol uses ephemeral ECDH (e.g., over P-256) to derive a shared AES-GCM session key. Public keys are exchanged over a WebSocket channel routed through the server.

While the server cannot decrypt messages post key exchange, it could potentially perform a MITM attack during key exchange by intercepting and replacing public keys. This would allow the server to derive two separate shared keys (one with Alice, one with Bob) and proxy encrypted messages in both directions.

## Mitigation Strategy: Out-of-Band Key Authentication

### Minimal Trust Assumption

We assume that Alice and Bob can communicate via a secondary **out-of-band (OOB) channel** that is:

* **Authentic**: each party knows the identity of the sender.
* **Observable**: the content of the communication may be monitored by an attacker (e.g., WhatsApp, Signal, voice call).

Even if the OOB channel is not encrypted, as long as it ensures authenticity, it can be used to bind a public key to an identity.

### Lightweight SAS-Based Authentication 

To avoid the complexity of exchanging full public keys manually, Verba Volant implements a short authentication string (SAS) model using a (to be done)


#### One-Way Authentication Flow

1. Alice generates a room ID and ephemeral public key.
2. She sends the room ID to Bob via an OOB channel.
3. Bob joins the room, generates his ephemeral public key, and derives an authentication code (e.g., 5 bitcoin words ...to be explained).
4. Bob sends the AUTHCODE to Alice via the same OOB channel.
5. Alice, upon seeing a new public key in the room, derives the AUTHCODE from it and compares it to the one she received.

If they match, she can be reasonably confident that the key belongs to Bob.

#### Limitation

This approach authenticates Bob to Alice, but not vice versa. Bob has no guarantee that the peer in the room is actually Alice.

### Mutual Authentication Flow

To ensure **mutual authentication**, both parties must generate and exchange their respective AUTHCODEs:

1. Alice generates her public key and derives AUTHCODE\_A.
2. Alice sends Bob the room ID and AUTHCODE\_A via the OOB channel.
3. Bob connects, generates his public key and AUTHCODE\_B.
4. Bob sends AUTHCODE\_B to Alice via the OOB channel.
5. After both public keys are exchanged via WebSocket:

   * Alice computes AUTHCODE\_B from the received key and compares it.
   * Bob computes AUTHCODE\_A from the received key and compares it.

If both checks pass, the session is mutually authenticated.

## Security Model

This method assumes that:

* The attacker **cannot impersonate** participants on the OOB channel.
* The server **cannot interfere** with the OOB AUTHCODE exchange.

In this sense, the OOB channel acts as a **lightweight certification authority**, allowing clients to authenticate each other's ephemeral keys without the need for persistent keys or digital signatures.

## Benefits

* No persistent identity or PKI required
* No signatures or long-term key storage
* Human-readable AUTHCODEs suitable for voice/SMS/QR transmission
* Can be implemented with minimal UI



## Conclusion

Verba Volant mitigates MITM risks by binding ephemeral public keys to real-world identities using short AUTHCODEs exchanged over an authentic out-of-band channel. This approach enables secure communication bootstrapAUTHCODEg without the complexity of centralized identity systems or cryptographic signatures.
