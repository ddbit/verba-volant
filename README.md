# Verba Volant

**Privacy without traces. Ephemeral and secure communication.**

## What is Verba Volant

Verba Volant is a messaging application designed for those who need the highest level of privacy and **forensic resistance**. Its goal is simple and radical: **no message should leave a trace**, neither on the user’s device nor on the server.

Unlike apps like Signal, Telegram, or WhatsApp, which store encrypted messages on disk or create automatic backups, Verba Volant works completely differently:

* No phone number or identity required
* No message ever written to disk
* No backup or logging, on client or server
* No automatic message decryption
* No persistence: everything lives only in browser RAM, and only when necessary

---

![you shall not track](./shall-not-track-small.png)

## Goals

* Ensure **complete confidentiality** in conversations
* Provide a **forensically clean** system: nothing to recover, even after deep analysis
* Protect against **man-in-the-middle attacks**
* Eliminate the need for persistent identifiers or keys
* Offer a tool that is simple to use, but extremely secure

---

## How it works (briefly)

1. **Alice creates a “room”**: a shared code (Room ID) that identifies the conversation.
2. **Bob receives this code** from Alice through a separate channel (e.g., SMS, voice, etc.).
3. Both browsers connect via WebSocket and exchange **ephemeral ECDH keys**.
4. Both derive a shared secret key.
5. Alice sends Bob a “verification code” made of words, which Bob checks to confirm authenticity.
6. Only after confirmation, messages can be sent and read.

---

## What makes Verba Volant unique

One of its most distinctive features is the use of **BIP39 words**—commonly used in cryptocurrency wallets—for manual fingerprint verification. This gives Verba Volant a rare combination of cryptographic strength and human readability, enabling users to verify key authenticity with minimal effort.

### 🔐 True end-to-end encryption

Keys are generated locally and **never known to the server**. No message ever travels in plaintext. Not even for a millisecond.

### 🧠 Decryption only on request

Messages are visible only **if the user activates them** manually. They remain encrypted in the browser's RAM until the user chooses to read them.

### 🗑️ No traces, ever

No disk writes. No cache. No logs. No IndexedDB. The message exists only in the **DOM**, in RAM, and only temporarily.

### 🕵️‍♂️ Forensic attack resistance

Even professional tools cannot recover messages **after the page is closed**. The only possible attack? Malware actively inspecting RAM **while the user is reading the message**.

### ⚖️ Simple human verification

To prevent MITM attacks, users compare a 5-word (customizable) code via a separate channel. If the words match, the exchange is authentic.

These words are selected from the well-known **BIP39 dictionary** (used in cryptocurrency wallets), making them both easy to read aloud and resistant to forgery. This design provides a strong balance between usability and cryptographic integrity.

---

## When to use it

* When confidentiality is not optional, but essential
* For sensitive conversations between journalists, activists, researchers, companies
* When you want to ensure that **no server, OS, or passive malware** can recover messages

> "You shall not track."

---

## Technology in brief

* **ECDH** on standard curves (P-256 or X25519)
* **AES-GCM** for symmetric encryption
* **SHA-256 + BIP39** for manual fingerprint verification
* Frontend in HTML/JS, backend with WebSocket for relaying (but cannot read anything)
* Offline distribution: the client can be used without ever downloading code from the server

---

## Disclaimer

Verba Volant is designed for **lawful use** in scenarios where privacy is a fundamental right. It is not intended to support illegal activity or violate applicable laws. Misuse is the sole responsibility of the user.
