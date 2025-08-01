# Verba Volant: Technical Roadmap

## Project Overview
A forensics-resistant web chat service with end-to-end encryption using Diffie-Hellman key exchange. The system prioritizes privacy, forward secrecy, and resistance to forensic analysis.

## Phase 1: Foundation & Core Infrastructure (Milestone 1)

### 1.1 Project Setup
- [X] Initialize Node.js project structure
- [X] Set up package.json with dependencies (ws, crypto modules)
- [X] Create basic folder structure (src/server, src/client, public)
- [X] Configure development environment and build tools
- [X] Set up basic HTML/CSS structure for client interface

### 1.2 WebSocket Server Implementation
- [X] Create basic WebSocket server using `ws` library
- [X] Implement room management system (join/leave rooms)
- [X] Add connection handling and client tracking
- [ ] Implement message routing between clients in same room
- [X] Add basic error handling and connection cleanup

### 1.3 Basic Client Interface
- [X] Create HTML structure with Send and Receive areas
- [X] Implement room join functionality, only two participants allowed Alice and Bob. Also in the webpage, put name 'Alice' in the UI. When the second user joins put name 'Bob' in his UI. Do not accept more participants.
- [X] Add basic WebSocket client connection
- [X] Create message input/output interface
- [X] Add connection status indicators
- [X] Once connected to a room the room id can't be changed by user, add a leave button and reload the page as a fresh session

**Security Requirement**: All client code must be self-contained and never downloaded from the server. Client files should be distributed separately for user verification and local execution.

## Phase 2: Cryptographic Implementation (Milestone 2)

### 2.1 Diffie-Hellman Key Exchange
- [X] Implement DH key pair generation using Web Crypto API with both "deriveKey" and "deriveBits" usages for ECDH operations
- [X] Create key exchange message format (pubkey type)
- [X] Add public key transmission via WebSocket
- [X] Implement shared secret derivation from DH exchange using deriveBits() to get raw key material for HKDF input, show in the UI of participants that the secret has been derived.
- [X] Add key exchange state management

### 2.2 AES-GCM Encryption System
- [X] Implement AES key derivation using HKDF/SHA-256 from ECDH raw key material, use deterministic salt for consistent key derivation between participants, update status in UI when AES key is ready
- [X] Create AES-GCM encryption functions with encryptMessage() that generates random 12-byte IV and returns {ciphertext, iv} object
- [X] Add IV/nonce generation for each message using crypto.getRandomValues() with 12 bytes for GCM mode
- [X] Implement decryption functions with decryptMessage() that takes ciphertext, iv, and aesKey parameters
- [X] Add encryption error handling with try-catch blocks and detailed error logging
- [X] Update UI when encryption is ready: change placeholder text, button text to "Send Encrypted", show "Ready for encrypted messaging" status with pulse animation

### 2.3 Message Encryption Flow
- [X] Integrate encryption into message sending: check keyExchangeCompleted && aesKey, encrypt with encryptMessage(), send as 'encrypted_message' type with ciphertext/iv arrays and sender role
- [X] Implement encrypted message format with server relay: ciphertext + IV as byte arrays, sender identification, server broadcasts to room excluding sender
- [X] Default encrypted display with individual toggle: messages show encrypted by default (globalShowPlaintext=false), each message has lock/unlock icon (🔒/🔓) in message header beside sender name, click toggles between hex preview and plaintext
- [X] Individual message encryption toggle: both sent and received messages have clickable lock icons, encrypted text shows as "🔒 [hex20bytes...]", stores encryptedData and plaintextContent on messageDiv DOM element
- [X] Global lock/unlock all button: positioned below security status outside scrolling area, button text shows action to perform ("🔓 Unlock All" when locked, "🔒 Lock All" when unlocked), applies to all messages with encryption data
- [X] Message structure with encryption: message header contains sender name and lock icon, message content shows encrypted hex or plaintext based on state, auto-scroll with multiple timing attempts for visibility
- [X] **ENHANCED SECURITY**: Updated lock behavior to hold-to-view mode: messages display encrypted ciphertext by default, individual lock icons require holding down (mousedown/touchstart) to temporarily show plaintext, global "Hold to Show All" button works similarly - all messages return to encrypted state when released for maximum security


### 2.4 Recent Security Enhancements (December 2024)
- [X] **Hold-to-View Security Model**: Implemented enhanced security where encrypted messages are displayed as ciphertext by default with no persistent plaintext visibility
- [X] **Individual Message Security**: Each message lock icon (🔒) requires active holding (mouse/touch) to temporarily reveal plaintext - releases immediately when pressure stops
- [X] **Global Message Security**: "Hold to Show All" button (🔒 Hold to Show All) applies hold-to-view behavior to all encrypted messages simultaneously
- [X] **Multi-Platform Support**: Added both mouse events (mousedown/mouseup/mouseleave) and touch events (touchstart/touchend) for mobile compatibility
- [X] **Forensic Resistance**: Enhanced forensic resistance by eliminating persistent plaintext display - messages automatically return to encrypted state without user action
- [X] **UI/UX Security**: Updated button labels and tooltips to clearly indicate hold-to-view functionality, preventing accidental plaintext exposure

## Phase 3: MITM Protection & BIP39 Authentication (Milestone 3)

### 3.1 BIP39 Wordlist Integration
- [X] Import BIP39 English wordlist (2048 words) into client code
- [X] Create wordlist validation and lookup functions
- [X] Implement bit-to-word mapping functions (11 bits per word)
- [X] Add word-to-index conversion for verification
- [X] Test wordlist integrity and completeness

### 3.2 Fingerprint Generation System
- [X] Implement public key ordering function (canonical order for consistency)
- [X] Create SHA-256 hash function for combined public keys: `hash = SHA-256(ordered(pubkeyA, pubkeyB))`
- [X] Extract first N×11 bits from hash (default N=5 for 55-bit security)
- [X] Map extracted bits to BIP39 words using bit slicing
- [X] Generate human-readable authcode (e.g., "abandon ability able about above")

### 3.3 Authentication Flow Implementation
- [ ] Add fingerprint computation after successful key exchange
- [ ] Display Alice's 5-word authcode in UI with copy-to-clipboard functionality
- [ ] Create verification input field for Bob to enter received authcode
- [ ] Implement string comparison for authcode verification
- [ ] Add visual feedback for successful/failed verification
- [ ] Block message sending until authentication is complete

### 3.4 User Interface for MITM Protection
- [ ] Design authentication dialog/modal for fingerprint display
- [ ] Add "Copy Authcode" button for Alice to share via OOB channel
- [ ] Create "Enter Authcode" input field for Bob with paste functionality
- [ ] Implement "Verify" button that compares computed vs received authcode
- [ ] Add clear success/failure indicators with appropriate messaging
- [ ] Show security status: "Verified" vs "Unverified" in connection status

### 3.5 Security State Management
- [ ] Add `isAuthenticated` flag to track verification status
- [ ] Prevent message encryption/sending until authentication completes
- [ ] Update security status indicators to show authentication state
- [ ] Add re-verification mechanism if key exchange resets
- [ ] Implement authentication timeout and retry mechanisms
- [ ] Store authentication state only in memory (no persistence)

### 3.6 Out-of-Band (OOB) Channel Integration
- [ ] Add guidance text explaining OOB channel requirement
- [ ] Create user instructions for secure authcode sharing (SMS, voice, in-person)
- [ ] Implement QR code generation for authcode sharing (optional)
- [ ] Add warning messages about MITM risks if verification is skipped
- [ ] Create "Skip Verification" option with clear security warnings
- [ ] Document OOB channel security requirements and recommendations

## Phase 4: User Experience & Interface (Milestone 4)

### 4.1 User Interface Enhancement
- [ ] Create intuitive room creation/joining flow
- [ ] Add visual indicators for encryption status
- [ ] Implement typing indicators (encrypted)
- [ ] Add message delivery status display
- [ ] Create responsive design for mobile devices

### 4.2 Security Indicators
- [ ] Add key exchange completion indicators
- [ ] Implement connection security status
- [ ] Create visual encryption confirmations
- [ ] Add session security warnings
- [ ] Implement fingerprint display (optional)

### 4.3 Error Handling & User Feedback
- [ ] Add comprehensive error messages
- [ ] Implement connection failure handling
- [ ] Create key exchange failure recovery
- [ ] Add user guidance for security features
- [ ] Implement graceful degradation

## Phase 5: Testing & Validation (Milestone 5)

### 5.1 Unit Testing
- [ ] Test cryptographic functions
- [ ] Validate key exchange mechanisms
- [ ] Test message encryption/decryption
- [ ] Verify memory management
- [ ] Test WebSocket communication

### 5.2 Integration Testing
- [ ] Test end-to-end message flow
- [ ] Validate multi-client scenarios
- [ ] Test room management functionality
- [ ] Verify security properties
- [ ] Test error scenarios

### 5.3 Security Testing
- [ ] Penetration testing for key exchange
- [ ] Validate forward secrecy implementation
- [ ] Test memory forensics resistance
- [ ] Verify no data persistence
- [ ] Test MITM attack resistance

## Phase 6: Deployment & Documentation (Milestone 6)

### 6.1 Production Preparation
- [ ] Create production build configuration
- [ ] Implement environment-specific settings
- [ ] Add performance optimizations
- [ ] Create deployment scripts
- [ ] Set up monitoring and logging (minimal)

### 6.2 Documentation
- [ ] Create user documentation
- [ ] Write security analysis document
- [ ] Document API and message formats
- [ ] Create deployment guide
- [ ] Add troubleshooting guide

### 6.3 Optional Extensions
- [ ] QR code integration for room sharing
- [ ] Public key fingerprint verification
- [ ] Multi-device session handling
- [ ] Group messaging preparation (MLS)
- [ ] Tor/onion service support

## Technical Specifications by Component

### Server (Node.js + WebSocket)
- **Technology**: Node.js with `ws` library
- **Responsibilities**: Message routing, room management, connection handling
- **Security**: Stateless operation, no message storage, minimal metadata
- **Performance**: Handle multiple concurrent rooms and connections

### Client (HTML + JavaScript)
- **Technology**: Vanilla JavaScript with Web Crypto API
- **Responsibilities**: UI, encryption/decryption, key management
- **Security**: No persistent storage, secure memory handling
- **Compatibility**: Modern browsers with Web Crypto API support

### Cryptography
- **Key Exchange**: ECDH over P-256 or X25519
- **Encryption**: AES-GCM with HKDF-derived keys
- **Security Properties**: Forward secrecy, ephemeral keys, secure random generation
- **Implementation**: Web Crypto API for client, Node.js crypto for server

## Success Criteria

### Security Requirements
- [ ] True end-to-end encryption (server cannot decrypt)
- [ ] Forward secrecy through ephemeral keys
- [ ] No persistent storage of messages or keys
- [ ] Resistance to forensic analysis
- [ ] Protection against MITM attacks

### Functional Requirements
- [ ] Two users can join the same room
- [ ] Successful DH key exchange
- [ ] Encrypted message exchange
- [ ] Message delivery confirmation
- [ ] Clean session termination

### Privacy Requirements
- [ ] No user registration or identity required
- [ ] Minimal metadata exposure
- [ ] No server-side message storage
- [ ] No client-side message persistence
- [ ] Anonymous communication support

## Risk Mitigation

### Technical Risks
- **Browser compatibility**: Use progressive enhancement and fallbacks
- **Key exchange failures**: Implement retry mechanisms and error recovery
- **Memory leaks**: Implement proper cleanup and monitoring
- **Performance issues**: Optimize crypto operations and message handling

### Security Risks
- **MITM attacks**: Optional fingerprint verification system
- **Memory forensics**: Secure memory clearing and minimal data lifetime
- **Side-channel attacks**: Use timing-safe operations where possible
- **Implementation bugs**: Comprehensive testing and security review

## Timeline Estimate

- **Phase 1**: 2-3 weeks (Foundation)
- **Phase 2**: 3-4 weeks (Cryptography)
- **Phase 3**: 2-3 weeks (Security)
- **Phase 4**: 2-3 weeks (UI/UX)
- **Phase 5**: 2-3 weeks (Testing)
- **Phase 6**: 1-2 weeks (Deployment)

**Total Estimated Time**: 12-18 weeks

## Dependencies

### External Libraries
- `ws` (WebSocket server)
- Web Crypto API (browser support)
- Node.js `crypto` module

### Browser Requirements
- Modern browsers with Web Crypto API support
- WebSocket support
- ES6+ JavaScript support

### Infrastructure
- Node.js runtime environment
- Optional: Reverse proxy for production
- Optional: Tor support for enhanced anonymity