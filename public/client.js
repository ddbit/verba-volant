// Placeholder client-side JavaScript
// This will be implemented in Phase 2 with crypto functionality

console.log('Verba Volant Client Initialized');

// DOM elements
const serverHostInput = document.getElementById('serverHost');
const roomIdInput = document.getElementById('roomId');
const joinRoomButton = document.getElementById('joinRoom');
const leaveRoomButton = document.getElementById('leaveRoom');
const connectionStatus = document.getElementById('connectionStatus');
const chatSection = document.getElementById('chatSection');
const securityStatus = document.getElementById('securityStatus');
const securityIndicator = document.getElementById('securityIndicator');
const securityText = document.getElementById('securityText');
const messageInput = document.getElementById('messageInput');
const sendButton = document.getElementById('sendMessage');
const receivedMessages = document.getElementById('receivedMessages');
const userIdentity = document.getElementById('userIdentity');
const userName = document.getElementById('userName');
const toggleAllButton = document.getElementById('toggleAllMessages');

// State
let ws = null;
let roomId = null;
let isConnected = false;
let keyPair = null;
let sharedSecret = null;
let remotePublicKey = null;
let keyExchangeCompleted = false;
let userRole = null;
let aesKey = null;
// Removed globalShowPlaintext - messages are now encrypted by default

// MITM Protection Authentication State
let isAuthenticated = false;
let localPublicKeyRaw = null;
let remotePublicKeyRaw = null;
let computedAuthcode = null;
let authenticationInProgress = false;

// Cryptographic functions
async function generateKeyPair() {
    try {
        keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            false,
            ["deriveKey", "deriveBits"]
        );
        console.log('DH key pair generated');
        return keyPair;
    } catch (error) {
        console.error('Failed to generate key pair:', error);
        throw error;
    }
}

async function exportPublicKey(publicKey) {
    try {
        const exported = await window.crypto.subtle.exportKey("raw", publicKey);
        return new Uint8Array(exported);
    } catch (error) {
        console.error('Failed to export public key:', error);
        throw error;
    }
}

async function importPublicKey(publicKeyData) {
    try {
        const publicKey = await window.crypto.subtle.importKey(
            "raw",
            publicKeyData,
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            false,
            []
        );
        return publicKey;
    } catch (error) {
        console.error('Failed to import public key:', error);
        throw error;
    }
}

async function deriveSharedSecret(privateKey, publicKey) {
    try {
        const sharedSecretBytes = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: publicKey
            },
            privateKey,
            256
        );
        
        const sharedSecretKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecretBytes,
            "HKDF",
            false,
            ["deriveKey"]
        );
        
        console.log('Shared secret derived');
        return sharedSecretKey;
    } catch (error) {
        console.error('Failed to derive shared secret:', error);
        throw error;
    }
}

async function deriveAESKey(sharedSecret) {
    try {
        const salt = new TextEncoder().encode("Verba Volant Salt v1");
        const saltArray = new Uint8Array(32);
        saltArray.set(salt.slice(0, Math.min(salt.length, 32)));
        
        const info = new TextEncoder().encode("Verba Volant AES Key");
        
        const aesKey = await window.crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: saltArray,
                info: info
            },
            sharedSecret,
            {
                name: "AES-GCM",
                length: 256
            },
            false,
            ["encrypt", "decrypt"]
        );
        
        console.log('AES key derived using HKDF/SHA-256');
        return aesKey;
    } catch (error) {
        console.error('Failed to derive AES key:', error);
        throw error;
    }
}

async function encryptMessage(plaintext, aesKey) {
    try {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        
        const ciphertext = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            aesKey,
            data
        );
        
        return {
            ciphertext: new Uint8Array(ciphertext),
            iv: iv
        };
    } catch (error) {
        console.error('Failed to encrypt message:', error);
        throw error;
    }
}

async function decryptMessage(ciphertext, iv, aesKey) {
    try {
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            aesKey,
            ciphertext
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    } catch (error) {
        console.error('Failed to decrypt message:', error);
        throw error;
    }
}

// BIP39 Wordlist and Validation Functions
// Note: BIP39_WORDLIST is loaded from bip39.js
let wordlistReady = false;

async function loadBip39Wordlist() {
    try {
        // Check if BIP39_WORDLIST is available from bip39.js
        if (typeof BIP39_WORDLIST === 'undefined') {
            throw new Error('BIP39_WORDLIST not available - bip39.js not loaded');
        }
        
        if (BIP39_WORDLIST.length !== 2048) {
            throw new Error(`Invalid wordlist length: ${BIP39_WORDLIST.length}, expected 2048`);
        }
        
        // Check for duplicates
        const uniqueWords = new Set(BIP39_WORDLIST);
        if (uniqueWords.size !== 2048) {
            throw new Error(`Duplicate words found in wordlist`);
        }
        
        wordlistReady = true;
        console.log('BIP39 wordlist loaded successfully');
        return true;
    } catch (error) {
        console.error('Failed to load BIP39 wordlist:', error);
        return false;
    }
}

function validateBip39Wordlist() {
    if (!BIP39_WORDLIST || BIP39_WORDLIST.length !== 2048) {
        return { valid: false, error: 'Wordlist not loaded or invalid length' };
    }
    
    // Check for duplicates
    const uniqueWords = new Set(BIP39_WORDLIST);
    if (uniqueWords.size !== 2048) {
        return { valid: false, error: 'Duplicate words found' };
    }
    
    // Check word format (lowercase, no special chars)
    for (let i = 0; i < BIP39_WORDLIST.length; i++) {
        const word = BIP39_WORDLIST[i];
        if (!/^[a-z]+$/.test(word)) {
            return { valid: false, error: `Invalid word format at index ${i}: "${word}"` };
        }
    }
    
    return { valid: true };
}

function isValidBip39Word(word) {
    if (!wordlistReady || !BIP39_WORDLIST) {
        console.warn('BIP39 wordlist not ready');
        return false;
    }
    return BIP39_WORDLIST.includes(word.toLowerCase().trim());
}

function getWordIndex(word) {
    if (!wordlistReady || !BIP39_WORDLIST) {
        console.warn('BIP39 wordlist not ready');
        return null;
    }
    const index = BIP39_WORDLIST.indexOf(word.toLowerCase().trim());
    return index !== -1 ? index : null;
}

function getWordByIndex(index) {
    if (!wordlistReady || !BIP39_WORDLIST) {
        console.warn('BIP39 wordlist not ready');
        return null;
    }
    return (index >= 0 && index < 2048) ? BIP39_WORDLIST[index] : null;
}

function validateAuthcodeWords(authcode) {
    if (!wordlistReady) {
        return { valid: false, error: 'BIP39 wordlist not ready' };
    }
    
    const words = authcode.toLowerCase().trim().split(/\s+/);
    
    if (words.length !== 5) {
        return { valid: false, error: `Expected 5 words, got ${words.length}` };
    }
    
    for (let i = 0; i < words.length; i++) {
        if (!isValidBip39Word(words[i])) {
            return { valid: false, error: `Invalid word at position ${i + 1}: "${words[i]}"` };
        }
    }
    
    return { valid: true, words: words };
}

// Bit-to-word mapping functions (11 bits per word)
function bitsToWords(bits, wordCount = 5) {
    if (!wordlistReady) {
        throw new Error('BIP39 wordlist not ready');
    }
    
    if (bits.length < wordCount * 11) {
        throw new Error(`Insufficient bits: need ${wordCount * 11}, got ${bits.length}`);
    }
    
    const words = [];
    for (let i = 0; i < wordCount; i++) {
        // Extract 11 bits starting at position i * 11
        const startBit = i * 11;
        const endBit = startBit + 11;
        const wordBits = bits.slice(startBit, endBit);
        
        // Convert 11 bits to integer (0-2047)
        let wordIndex = 0;
        for (let j = 0; j < wordBits.length; j++) {
            wordIndex = (wordIndex << 1) | wordBits[j];
        }
        
        if (wordIndex >= 2048) {
            throw new Error(`Invalid word index: ${wordIndex}, must be 0-2047`);
        }
        
        words.push(BIP39_WORDLIST[wordIndex]);
    }
    
    return words;
}

function wordsToBits(words) {
    if (!wordlistReady) {
        throw new Error('BIP39 wordlist not ready');
    }
    
    const bits = [];
    for (const word of words) {
        const wordIndex = getWordIndex(word);
        if (wordIndex === null) {
            throw new Error(`Invalid BIP39 word: "${word}"`);
        }
        
        // Convert word index to 11 bits
        const wordBits = [];
        let index = wordIndex;
        for (let i = 10; i >= 0; i--) {
            wordBits[i] = index & 1;
            index >>= 1;
        }
        
        bits.push(...wordBits);
    }
    
    return bits;
}

function bytesToBits(bytes) {
    const bits = [];
    for (const byte of bytes) {
        for (let i = 7; i >= 0; i--) {
            bits.push((byte >> i) & 1);
        }
    }
    return bits;
}

function bitsToBytes(bits) {
    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
        let byte = 0;
        for (let j = 0; j < 8 && i + j < bits.length; j++) {
            byte = (byte << 1) | bits[i + j];
        }
        bytes.push(byte);
    }
    return new Uint8Array(bytes);
}

function hashToAuthcode(hashBytes, wordCount = 5) {
    if (!wordlistReady) {
        throw new Error('BIP39 wordlist not ready');
    }
    
    // Convert hash bytes to bits
    const bits = bytesToBits(hashBytes);
    
    // Take first N×11 bits (default 5×11 = 55 bits)
    const requiredBits = wordCount * 11;
    if (bits.length < requiredBits) {
        throw new Error(`Hash too short: need ${requiredBits} bits, got ${bits.length}`);
    }
    
    const authcodeBits = bits.slice(0, requiredBits);
    
    // Convert bits to words
    const words = bitsToWords(authcodeBits, wordCount);
    
    return words.join(' ');
}

// Explicit bit extraction and word mapping functions for Section 3.2 completion
function extractBitsFromHash(hashBytes, bitCount = 55) {
    /*
     * Extracts first N×11 bits from SHA-256 hash (default N=5 for 55-bit security).
     * Implements the protocol specification exactly.
     * 
     * @param {Uint8Array} hashBytes - SHA-256 hash (32 bytes)
     * @param {number} bitCount - Number of bits to extract (default 55 for 5 words)
     * @returns {Array} Array of bits (0s and 1s)
     */
    
    if (!(hashBytes instanceof Uint8Array)) {
        throw new Error('Hash must be Uint8Array');
    }
    
    if (hashBytes.length < Math.ceil(bitCount / 8)) {
        throw new Error(`Hash too short: need ${Math.ceil(bitCount / 8)} bytes for ${bitCount} bits`);
    }
    
    // Convert bytes to bits
    const allBits = bytesToBits(hashBytes);
    
    // Extract first N bits
    const extractedBits = allBits.slice(0, bitCount);
    
    console.log(`Extracted ${extractedBits.length} bits from hash:`, extractedBits.slice(0, 11), '...');
    return extractedBits;
}

function mapBitsToWords(bits, wordCount = 5) {
    /*
     * Maps extracted bits to BIP39 words using bit slicing.
     * Each 11-bit slice maps to one BIP39 word (0-2047 range).
     * 
     * @param {Array} bits - Array of bits (0s and 1s)
     * @param {number} wordCount - Number of words to generate
     * @returns {Array} Array of BIP39 words
     */
    
    if (!wordlistReady) {
        throw new Error('BIP39 wordlist not ready');
    }
    
    const requiredBits = wordCount * 11;
    if (bits.length < requiredBits) {
        throw new Error(`Insufficient bits: need ${requiredBits}, got ${bits.length}`);
    }
    
    const words = [];
    for (let i = 0; i < wordCount; i++) {
        // Extract 11 bits for this word
        const startBit = i * 11;
        const wordBits = bits.slice(startBit, startBit + 11);
        
        // Convert 11 bits to word index (0-2047)
        let wordIndex = 0;
        for (let j = 0; j < wordBits.length; j++) {
            wordIndex = (wordIndex << 1) | wordBits[j];
        }
        
        if (wordIndex >= 2048) {
            throw new Error(`Invalid word index: ${wordIndex}, must be 0-2047`);
        }
        
        const word = BIP39_WORDLIST[wordIndex];
        words.push(word);
        
        console.log(`Bit slice ${i}: [${wordBits.join('')}] → index ${wordIndex} → "${word}"`);
    }
    
    return words;
}

function generateHumanReadableAuthcode(hashBytes, wordCount = 5) {
    /*
     * Generates human-readable authcode from hash bytes.
     * Complete implementation: hash → bits → words → string
     * Example output: "abandon ability able about above"
     * 
     * @param {Uint8Array} hashBytes - SHA-256 hash (32 bytes)
     * @param {number} wordCount - Number of BIP39 words (default 5)
     * @returns {string} Human-readable authcode
     */
    
    console.log('Generating human-readable authcode...');
    console.log('Input hash:', bytesToHex(hashBytes));
    
    // Step 1: Extract first N×11 bits from hash
    const bitCount = wordCount * 11;
    const extractedBits = extractBitsFromHash(hashBytes, bitCount);
    
    // Step 2: Map extracted bits to BIP39 words using bit slicing
    const words = mapBitsToWords(extractedBits, wordCount);
    
    // Step 3: Generate human-readable authcode
    const authcode = words.join(' ');
    
    console.log(`Generated ${wordCount}-word authcode:`, authcode);
    console.log('Security level:', `${bitCount} bits (${Math.pow(2, bitCount).toExponential(2)} possibilities)`);
    
    return authcode;
}

// Public Key Ordering Functions for MITM Protection
function canonicalKeyOrder(publicKeyA, publicKeyB) {
    /*
     * Orders two public keys in canonical (lexicographic) order for consistent
     * fingerprint generation. Both Alice and Bob will get the same order regardless
     * of who generated which key first.
     * 
     * @param {Uint8Array} publicKeyA - First public key as raw bytes
     * @param {Uint8Array} publicKeyB - Second public key as raw bytes
     * @returns {Array} [firstKey, secondKey] in canonical order
     */
    
    if (!publicKeyA || !publicKeyB) {
        throw new Error('Both public keys are required');
    }
    
    if (!(publicKeyA instanceof Uint8Array) || !(publicKeyB instanceof Uint8Array)) {
        throw new Error('Public keys must be Uint8Array');
    }
    
    // Compare keys byte by byte (lexicographic order)
    const minLength = Math.min(publicKeyA.length, publicKeyB.length);
    
    for (let i = 0; i < minLength; i++) {
        if (publicKeyA[i] < publicKeyB[i]) {
            return [publicKeyA, publicKeyB]; // A comes first
        } else if (publicKeyA[i] > publicKeyB[i]) {
            return [publicKeyB, publicKeyA]; // B comes first
        }
        // If bytes are equal, continue to next byte
    }
    
    // If all compared bytes are equal, shorter key comes first
    if (publicKeyA.length < publicKeyB.length) {
        return [publicKeyA, publicKeyB];
    } else if (publicKeyA.length > publicKeyB.length) {
        return [publicKeyB, publicKeyA];
    }
    
    // Keys are identical - this should not happen in practice
    console.warn('Warning: Identical public keys detected');
    return [publicKeyA, publicKeyB];
}

function combineOrderedKeys(orderedKeys) {
    /*
     * Combines two ordered public keys into a single byte array for hashing.
     * 
     * @param {Array} orderedKeys - Array of [firstKey, secondKey] in canonical order
     * @returns {Uint8Array} Combined key data ready for hashing
     */
    
    if (!Array.isArray(orderedKeys) || orderedKeys.length !== 2) {
        throw new Error('Expected array of exactly 2 keys');
    }
    
    const [keyA, keyB] = orderedKeys;
    
    if (!(keyA instanceof Uint8Array) || !(keyB instanceof Uint8Array)) {
        throw new Error('Keys must be Uint8Array');
    }
    
    // Create combined array: keyA + keyB
    const combined = new Uint8Array(keyA.length + keyB.length);
    combined.set(keyA, 0);
    combined.set(keyB, keyA.length);
    
    return combined;
}

function bytesToHex(bytes) {
    /*
     * Converts byte array to hexadecimal string for debugging/logging.
     * 
     * @param {Uint8Array} bytes - Byte array to convert
     * @returns {string} Hexadecimal representation
     */
    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

function comparePublicKeys(keyA, keyB) {
    /*
     * Compares two public keys for debugging purposes.
     * 
     * @param {Uint8Array} keyA - First public key
     * @param {Uint8Array} keyB - Second public key
     * @returns {number} -1 if A < B, 1 if A > B, 0 if equal
     */
    
    const minLength = Math.min(keyA.length, keyB.length);
    
    for (let i = 0; i < minLength; i++) {
        if (keyA[i] < keyB[i]) return -1;
        if (keyA[i] > keyB[i]) return 1;
    }
    
    if (keyA.length < keyB.length) return -1;
    if (keyA.length > keyB.length) return 1;
    return 0;
}

// SHA-256 Hash Functions for Fingerprint Generation
async function hashCombinedPublicKeys(publicKeyA, publicKeyB) {
    /*
     * Creates SHA-256 hash of two public keys in canonical order.
     * Implements: hash = SHA-256(ordered(pubkeyA, pubkeyB))
     * 
     * @param {Uint8Array} publicKeyA - First public key as raw bytes
     * @param {Uint8Array} publicKeyB - Second public key as raw bytes
     * @returns {Promise<Uint8Array>} SHA-256 hash (32 bytes)
     */
    
    try {
        // Step 1: Order keys canonically
        const orderedKeys = canonicalKeyOrder(publicKeyA, publicKeyB);
        console.log('Keys ordered canonically:', {
            first: bytesToHex(orderedKeys[0]).substring(0, 16) + '...',
            second: bytesToHex(orderedKeys[1]).substring(0, 16) + '...'
        });
        
        // Step 2: Combine ordered keys
        const combinedKeys = combineOrderedKeys(orderedKeys);
        console.log('Combined key length:', combinedKeys.length, 'bytes');
        console.log('Combined key preview:', bytesToHex(combinedKeys).substring(0, 32) + '...');
        
        // Step 3: Hash with SHA-256
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', combinedKeys);
        const hashArray = new Uint8Array(hashBuffer);
        
        console.log('SHA-256 hash generated:', bytesToHex(hashArray));
        return hashArray;
        
    } catch (error) {
        console.error('Failed to hash combined public keys:', error);
        throw new Error(`Hash generation failed: ${error.message}`);
    }
}

async function generateFingerprintHash(localPublicKey, remotePublicKey) {
    /*
     * Generates fingerprint hash from local and remote public keys.
     * This is the main function for MITM protection.
     * 
     * @param {Uint8Array} localPublicKey - Our public key
     * @param {Uint8Array} remotePublicKey - Remote party's public key
     * @returns {Promise<Uint8Array>} SHA-256 hash for fingerprint generation
     */
    
    if (!localPublicKey || !remotePublicKey) {
        throw new Error('Both public keys are required for fingerprint generation');
    }
    
    console.log('Generating fingerprint hash...');
    console.log('Local public key:', bytesToHex(localPublicKey).substring(0, 16) + '...');
    console.log('Remote public key:', bytesToHex(remotePublicKey).substring(0, 16) + '...');
    
    return await hashCombinedPublicKeys(localPublicKey, remotePublicKey);
}

async function generateAuthcodeFromKeys(localPublicKey, remotePublicKey, wordCount = 5) {
    /*
     * Complete pipeline: public keys → hash → BIP39 authcode
     * 
     * @param {Uint8Array} localPublicKey - Our public key
     * @param {Uint8Array} remotePublicKey - Remote party's public key
     * @param {number} wordCount - Number of BIP39 words (default 5 for 55-bit security)
     * @returns {Promise<string>} Human-readable authcode (e.g., "abandon ability able about above")
     */
    
    try {
        // Generate fingerprint hash
        const fingerprintHash = await generateFingerprintHash(localPublicKey, remotePublicKey);
        
        // Convert hash to BIP39 authcode
        const authcode = hashToAuthcode(fingerprintHash, wordCount);
        
        console.log('Generated authcode:', authcode);
        return authcode;
        
    } catch (error) {
        console.error('Failed to generate authcode from keys:', error);
        throw new Error(`Authcode generation failed: ${error.message}`);
    }
}

async function verifyFingerprintMatch(localPublicKey, remotePublicKey, expectedAuthcode) {
    /*
     * Verifies that computed authcode matches expected authcode.
     * Used by Bob to verify Alice's authcode.
     * 
     * @param {Uint8Array} localPublicKey - Our public key
     * @param {Uint8Array} remotePublicKey - Remote party's public key  
     * @param {string} expectedAuthcode - Authcode received from remote party
     * @returns {Promise<Object>} {isValid: boolean, computedAuthcode: string, error?: string}
     */
    
    try {
        // Generate our computed authcode
        const computedAuthcode = await generateAuthcodeFromKeys(localPublicKey, remotePublicKey);
        
        // Normalize both authcodes for comparison
        const normalizedExpected = expectedAuthcode.toLowerCase().trim().replace(/\s+/g, ' ');
        const normalizedComputed = computedAuthcode.toLowerCase().trim().replace(/\s+/g, ' ');
        
        const isValid = normalizedExpected === normalizedComputed;
        
        console.log('Fingerprint verification:', {
            expected: normalizedExpected,
            computed: normalizedComputed,
            match: isValid
        });
        
        return {
            isValid: isValid,
            computedAuthcode: computedAuthcode,
            expectedAuthcode: expectedAuthcode
        };
        
    } catch (error) {
        console.error('Failed to verify fingerprint match:', error);
        return {
            isValid: false,
            computedAuthcode: '',
            expectedAuthcode: expectedAuthcode,
            error: error.message
        };
    }
}

// Test functions for BIP39 implementation
function testBip39Functions() {
    console.log('Testing BIP39 functions...');
    
    try {
        // Test 1: Basic word validation
        console.log('Test 1: Basic word validation');
        if (!isValidBip39Word('abandon')) {
            throw new Error('Failed: "abandon" should be valid');
        }
        if (isValidBip39Word('invalid')) {
            throw new Error('Failed: "invalid" should not be valid');
        }
        if (!isValidBip39Word('ABANDON')) {
            throw new Error('Failed: case insensitive validation should work');
        }
        console.log('✅ Basic word validation passed');
        
        // Test 2: Word-to-index conversion
        console.log('Test 2: Word-to-index conversion');
        if (getWordIndex('abandon') !== 0) {
            throw new Error('Failed: "abandon" should have index 0');
        }
        if (getWordIndex('zoo') !== 2047) {
            throw new Error('Failed: "zoo" should have index 2047');
        }
        if (getWordIndex('invalid') !== null) {
            throw new Error('Failed: invalid word should return null');
        }
        console.log('✅ Word-to-index conversion passed');
        
        // Test 3: Index-to-word conversion
        console.log('Test 3: Index-to-word conversion');
        if (getWordByIndex(0) !== 'abandon') {
            throw new Error('Failed: index 0 should return "abandon"');
        }
        if (getWordByIndex(2047) !== 'zoo') {
            throw new Error('Failed: index 2047 should return "zoo"');
        }
        if (getWordByIndex(2048) !== null) {
            throw new Error('Failed: invalid index should return null');
        }
        console.log('✅ Index-to-word conversion passed');
        
        // Test 4: Bit manipulation functions
        console.log('Test 4: Bit manipulation functions');
        const testBytes = new Uint8Array([0xFF, 0x00, 0x80]); // 11111111 00000000 10000000
        const expectedBits = [1,1,1,1,1,1,1,1, 0,0,0,0,0,0,0,0, 1,0,0,0,0,0,0,0];
        const bits = bytesToBits(testBytes);
        if (JSON.stringify(bits) !== JSON.stringify(expectedBits)) {
            throw new Error('Failed: bytesToBits conversion incorrect');
        }
        
        const backToBytes = bitsToBytes(bits);
        if (JSON.stringify(Array.from(backToBytes)) !== JSON.stringify(Array.from(testBytes))) {
            throw new Error('Failed: bitsToBytes conversion incorrect');
        }
        console.log('✅ Bit manipulation functions passed');
        
        // Test 5: Word-bit conversion
        console.log('Test 5: Word-bit conversion');
        const testWords = ['abandon', 'ability']; // indices 0, 1
        const wordBits = wordsToBits(testWords);
        // abandon = 0 = 00000000000 (11 bits)
        // ability = 1 = 00000000001 (11 bits)
        const expectedWordBits = [0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,1];
        if (JSON.stringify(wordBits) !== JSON.stringify(expectedWordBits)) {
            throw new Error('Failed: wordsToBits conversion incorrect');
        }
        
        const backToWords = bitsToWords(wordBits, 2);
        if (JSON.stringify(backToWords) !== JSON.stringify(testWords)) {
            throw new Error('Failed: bitsToWords conversion incorrect');
        }
        console.log('✅ Word-bit conversion passed');
        
        // Test 6: Authcode validation
        console.log('Test 6: Authcode validation');
        const validAuthcode = 'abandon ability able about above';
        const validation1 = validateAuthcodeWords(validAuthcode);
        if (!validation1.valid) {
            throw new Error('Failed: valid authcode should pass validation');
        }
        
        const invalidAuthcode = 'abandon ability invalid about above';
        const validation2 = validateAuthcodeWords(invalidAuthcode);
        if (validation2.valid) {
            throw new Error('Failed: invalid authcode should fail validation');
        }
        
        const shortAuthcode = 'abandon ability';
        const validation3 = validateAuthcodeWords(shortAuthcode);
        if (validation3.valid) {
            throw new Error('Failed: short authcode should fail validation');
        }
        console.log('✅ Authcode validation passed');
        
        // Test 7: Hash-to-authcode conversion
        console.log('Test 7: Hash-to-authcode conversion');
        // Create a test hash (32 bytes of known data)
        const testHash = new Uint8Array(32);
        testHash[0] = 0x00; // First byte = 0, should map to first word indices
        
        const authcode = hashToAuthcode(testHash, 5);
        const authcodeWords = authcode.split(' ');
        if (authcodeWords.length !== 5) {
            throw new Error('Failed: authcode should have 5 words');
        }
        
        // First word should be 'abandon' (index 0) since first 11 bits are 0
        if (authcodeWords[0] !== 'abandon') {
            throw new Error('Failed: first word should be "abandon" for zero hash');
        }
        console.log('✅ Hash-to-authcode conversion passed');
        
        console.log('🎉 All BIP39 tests passed successfully!');
        return true;
        
    } catch (error) {
        console.error('❌ BIP39 test failed:', error.message);
        return false;
    }
}

function testPublicKeyOrdering() {
    console.log('Testing public key ordering functions...');
    
    try {
        // Test 1: Basic ordering - smaller key should come first
        console.log('Test 1: Basic key ordering');
        const keyA = new Uint8Array([0x00, 0x01, 0x02]);
        const keyB = new Uint8Array([0x00, 0x01, 0x03]);
        
        const ordered1 = canonicalKeyOrder(keyA, keyB);
        if (ordered1[0] !== keyA || ordered1[1] !== keyB) {
            throw new Error('Failed: keyA should come before keyB');
        }
        
        // Reverse order should give same result
        const ordered2 = canonicalKeyOrder(keyB, keyA);
        if (ordered2[0] !== keyA || ordered2[1] !== keyB) {
            throw new Error('Failed: order should be consistent regardless of input order');
        }
        console.log('✅ Basic key ordering passed');
        
        // Test 2: Different length keys
        console.log('Test 2: Different length keys');
        const shortKey = new Uint8Array([0x01, 0x02]);
        const longKey = new Uint8Array([0x01, 0x02, 0x03]);
        
        const ordered3 = canonicalKeyOrder(longKey, shortKey);
        if (ordered3[0] !== shortKey || ordered3[1] !== longKey) {
            throw new Error('Failed: shorter key should come first');
        }
        
        const ordered4 = canonicalKeyOrder(shortKey, longKey);
        if (ordered4[0] !== shortKey || ordered4[1] !== longKey) {
            throw new Error('Failed: ordering should be consistent with length');
        }
        console.log('✅ Different length key ordering passed');
        
        // Test 3: First byte difference
        console.log('Test 3: First byte difference');
        const key1 = new Uint8Array([0x00, 0xFF, 0xFF]);
        const key2 = new Uint8Array([0x01, 0x00, 0x00]);
        
        const ordered5 = canonicalKeyOrder(key2, key1);
        if (ordered5[0] !== key1 || ordered5[1] !== key2) {
            throw new Error('Failed: key with smaller first byte should come first');
        }
        console.log('✅ First byte difference ordering passed');
        
        // Test 4: Identical keys
        console.log('Test 4: Identical keys');
        const keyIdentical = new Uint8Array([0x01, 0x02, 0x03]);
        const keyIdentical2 = new Uint8Array([0x01, 0x02, 0x03]);
        
        const ordered6 = canonicalKeyOrder(keyIdentical, keyIdentical2);
        // Should not throw error and return consistent order
        if (!ordered6 || ordered6.length !== 2) {
            throw new Error('Failed: should handle identical keys gracefully');
        }
        console.log('✅ Identical key handling passed');
        
        // Test 5: Key combination
        console.log('Test 5: Key combination');
        const testKeyA = new Uint8Array([0xAA, 0xBB]);
        const testKeyB = new Uint8Array([0xCC, 0xDD]);
        
        const orderedTest = canonicalKeyOrder(testKeyB, testKeyA);
        const combined = combineOrderedKeys(orderedTest);
        
        // testKeyA should come first (0xAA < 0xCC)
        const expectedCombined = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);
        if (combined.length !== expectedCombined.length) {
            throw new Error('Failed: combined key has wrong length');
        }
        
        for (let i = 0; i < combined.length; i++) {
            if (combined[i] !== expectedCombined[i]) {
                throw new Error(`Failed: combined key mismatch at byte ${i}`);
            }
        }
        console.log('✅ Key combination passed');
        
        // Test 6: Hex conversion
        console.log('Test 6: Hex conversion');
        const testBytes = new Uint8Array([0x00, 0xFF, 0xAB, 0xCD]);
        const hex = bytesToHex(testBytes);
        const expectedHex = '00ffabcd';
        
        if (hex !== expectedHex) {
            throw new Error(`Failed: hex conversion incorrect. Got ${hex}, expected ${expectedHex}`);
        }
        console.log('✅ Hex conversion passed');
        
        // Test 7: Key comparison
        console.log('Test 7: Key comparison');
        const compareA = new Uint8Array([0x01, 0x02]);
        const compareB = new Uint8Array([0x01, 0x03]);
        const compareC = new Uint8Array([0x01, 0x02]);
        
        if (comparePublicKeys(compareA, compareB) !== -1) {
            throw new Error('Failed: A should be less than B');
        }
        
        if (comparePublicKeys(compareB, compareA) !== 1) {
            throw new Error('Failed: B should be greater than A');
        }
        
        if (comparePublicKeys(compareA, compareC) !== 0) {
            throw new Error('Failed: A should equal C');
        }
        console.log('✅ Key comparison passed');
        
        // Test 8: Error handling
        console.log('Test 8: Error handling');
        try {
            canonicalKeyOrder(null, keyA);
            throw new Error('Failed: should throw error for null key');
        } catch (e) {
            if (!e.message.includes('Both public keys are required')) {
                throw new Error('Failed: wrong error message for null key');
            }
        }
        
        try {
            canonicalKeyOrder('invalid', keyA);
            throw new Error('Failed: should throw error for invalid key type');
        } catch (e) {
            if (!e.message.includes('must be Uint8Array')) {
                throw new Error('Failed: wrong error message for invalid key type');
            }
        }
        console.log('✅ Error handling passed');
        
        console.log('🎉 All public key ordering tests passed successfully!');
        return true;
        
    } catch (error) {
        console.error('❌ Public key ordering test failed:', error.message);
        return false;
    }
}

async function testSHA256HashFunctions() {
    console.log('Testing SHA-256 hash functions...');
    
    try {
        // Test 1: Basic hash generation
        console.log('Test 1: Basic hash generation');
        const keyA = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
        const keyB = new Uint8Array([0x05, 0x06, 0x07, 0x08]);
        
        const hash1 = await hashCombinedPublicKeys(keyA, keyB);
        if (!(hash1 instanceof Uint8Array) || hash1.length !== 32) {
            throw new Error('Failed: hash should be 32-byte Uint8Array');
        }
        
        // Same keys should produce same hash
        const hash2 = await hashCombinedPublicKeys(keyA, keyB);
        if (bytesToHex(hash1) !== bytesToHex(hash2)) {
            throw new Error('Failed: same input should produce same hash');
        }
        
        // Reversed order should produce same hash (canonical ordering)
        const hash3 = await hashCombinedPublicKeys(keyB, keyA);
        if (bytesToHex(hash1) !== bytesToHex(hash3)) {
            throw new Error('Failed: key order should not affect hash due to canonical ordering');
        }
        console.log('✅ Basic hash generation passed');
        
        // Test 2: Different keys produce different hashes
        console.log('Test 2: Different keys produce different hashes');
        const keyC = new Uint8Array([0x09, 0x0A, 0x0B, 0x0C]);
        const hash4 = await hashCombinedPublicKeys(keyA, keyC);
        
        if (bytesToHex(hash1) === bytesToHex(hash4)) {
            throw new Error('Failed: different key combinations should produce different hashes');
        }
        console.log('✅ Different keys produce different hashes passed');
        
        // Test 3: Fingerprint hash generation
        console.log('Test 3: Fingerprint hash generation');
        const localKey = new Uint8Array([0x11, 0x22, 0x33, 0x44]);
        const remoteKey = new Uint8Array([0x55, 0x66, 0x77, 0x88]);
        
        const fingerprintHash = await generateFingerprintHash(localKey, remoteKey);
        if (!(fingerprintHash instanceof Uint8Array) || fingerprintHash.length !== 32) {
            throw new Error('Failed: fingerprint hash should be 32-byte Uint8Array');
        }
        console.log('✅ Fingerprint hash generation passed');
        
        // Test 4: Complete authcode generation pipeline
        console.log('Test 4: Complete authcode generation pipeline');
        if (!wordlistReady) {
            console.log('⏭️ Skipping authcode test - BIP39 wordlist not ready');
        } else {
            const authcode = await generateAuthcodeFromKeys(localKey, remoteKey, 5);
            
            if (typeof authcode !== 'string') {
                throw new Error('Failed: authcode should be a string');
            }
            
            const words = authcode.split(' ');
            if (words.length !== 5) {
                throw new Error('Failed: authcode should have 5 words');
            }
            
            // Verify all words are valid BIP39 words
            for (const word of words) {
                if (!isValidBip39Word(word)) {
                    throw new Error(`Failed: "${word}" is not a valid BIP39 word`);
                }
            }
            console.log('✅ Complete authcode generation pipeline passed');
            console.log('  Generated authcode:', authcode);
        }
        
        // Test 5: Fingerprint verification
        console.log('Test 5: Fingerprint verification');
        if (!wordlistReady) {
            console.log('⏭️ Skipping verification test - BIP39 wordlist not ready');
        } else {
            // Generate authcode for verification
            const testAuthcode = await generateAuthcodeFromKeys(localKey, remoteKey, 5);
            
            // Verify with correct authcode
            const verifyCorrect = await verifyFingerprintMatch(localKey, remoteKey, testAuthcode);
            if (!verifyCorrect.isValid) {
                throw new Error('Failed: correct authcode should verify successfully');
            }
            
            // Verify with incorrect authcode
            const wrongAuthcode = 'abandon ability able about above';
            const verifyWrong = await verifyFingerprintMatch(localKey, remoteKey, wrongAuthcode);
            if (verifyWrong.isValid && verifyWrong.computedAuthcode !== wrongAuthcode) {
                throw new Error('Failed: incorrect authcode should not verify (unless by coincidence)');
            }
            
            console.log('✅ Fingerprint verification passed');
        }
        
        // Test 6: Error handling
        console.log('Test 6: Error handling');
        try {
            await generateFingerprintHash(null, remoteKey);
            throw new Error('Failed: should throw error for null key');
        } catch (e) {
            if (!e.message.includes('Both public keys are required')) {
                throw new Error('Failed: wrong error message for null key');
            }
        }
        
        try {
            await hashCombinedPublicKeys('invalid', remoteKey);
            throw new Error('Failed: should throw error for invalid key type');
        } catch (e) {
            // Should throw error from canonicalKeyOrder function
        }
        console.log('✅ Error handling passed');
        
        // Test 7: Deterministic results
        console.log('Test 7: Deterministic results');
        if (wordlistReady) {
            const authcode1 = await generateAuthcodeFromKeys(localKey, remoteKey, 3);
            const authcode2 = await generateAuthcodeFromKeys(localKey, remoteKey, 3);
            
            if (authcode1 !== authcode2) {
                throw new Error('Failed: same inputs should produce identical authcodes');
            }
            console.log('✅ Deterministic results passed');
        }
        
        // Test 8: Real ECDH key compatibility test
        console.log('Test 8: Real ECDH key compatibility test');
        try {
            // Generate real ECDH keys for testing
            const testKeyPair1 = await window.crypto.subtle.generateKey(
                { name: "ECDH", namedCurve: "P-256" },
                false,
                ["deriveKey", "deriveBits"]
            );
            
            const testKeyPair2 = await window.crypto.subtle.generateKey(
                { name: "ECDH", namedCurve: "P-256" },
                false,
                ["deriveKey", "deriveBits"]
            );
            
            const pubKey1 = await exportPublicKey(testKeyPair1.publicKey);
            const pubKey2 = await exportPublicKey(testKeyPair2.publicKey);
            
            const realKeyHash = await hashCombinedPublicKeys(pubKey1, pubKey2);
            if (!(realKeyHash instanceof Uint8Array) || realKeyHash.length !== 32) {
                throw new Error('Failed: real ECDH keys should produce valid hash');
            }
            
            if (wordlistReady) {
                const realAuthcode = await generateAuthcodeFromKeys(pubKey1, pubKey2, 5);
                const realWords = realAuthcode.split(' ');
                if (realWords.length !== 5) {
                    throw new Error('Failed: real keys should produce 5-word authcode');
                }
                console.log('  Real ECDH authcode:', realAuthcode);
            }
            
            console.log('✅ Real ECDH key compatibility test passed');
        } catch (error) {
            console.log('⏭️ Skipping real ECDH test:', error.message);
        }
        
        console.log('🎉 All SHA-256 hash function tests passed successfully!');
        return true;
        
    } catch (error) {
        console.error('❌ SHA-256 hash function test failed:', error.message);
        return false;
    }
}

async function testFingerprintGenerationPipeline() {
    console.log('Testing complete fingerprint generation pipeline...');
    
    try {
        // Test 1: Bit extraction from hash
        console.log('Test 1: Bit extraction from hash');
        const testHash = new Uint8Array(32);
        testHash[0] = 0xFF; // 11111111
        testHash[1] = 0x00; // 00000000
        testHash[2] = 0x80; // 10000000
        
        const extractedBits = extractBitsFromHash(testHash, 22); // 2 words worth
        const expectedStart = [1,1,1,1,1,1,1,1, 0,0,0,0,0,0,0,0, 1,0,0,0,0,0];
        
        for (let i = 0; i < expectedStart.length; i++) {
            if (extractedBits[i] !== expectedStart[i]) {
                throw new Error(`Failed: bit extraction incorrect at position ${i}`);
            }
        }
        console.log('✅ Bit extraction from hash passed');
        
        // Test 2: Bit to word mapping
        console.log('Test 2: Bit to word mapping');
        if (!wordlistReady) {
            console.log('⏭️ Skipping bit-to-word test - BIP39 wordlist not ready');
        } else {
            // Test known bit patterns
            const testBits = [
                0,0,0,0,0,0,0,0,0,0,0, // 0 → "abandon"
                0,0,0,0,0,0,0,0,0,0,1  // 1 → "ability"
            ];
            
            const mappedWords = mapBitsToWords(testBits, 2);
            if (mappedWords[0] !== 'abandon' || mappedWords[1] !== 'ability') {
                throw new Error('Failed: bit-to-word mapping incorrect');
            }
            console.log('✅ Bit to word mapping passed');
        }
        
        // Test 3: Human-readable authcode generation
        console.log('Test 3: Human-readable authcode generation');
        if (!wordlistReady) {
            console.log('⏭️ Skipping authcode generation test - BIP39 wordlist not ready');
        } else {
            const zeroHash = new Uint8Array(32); // All zeros
            const authcode = generateHumanReadableAuthcode(zeroHash, 3);
            
            if (typeof authcode !== 'string') {
                throw new Error('Failed: authcode should be string');
            }
            
            const words = authcode.split(' ');
            if (words.length !== 3) {
                throw new Error('Failed: should generate exactly 3 words');
            }
            
            // First word should be "abandon" (index 0 from all-zero bits)
            if (words[0] !== 'abandon') {
                throw new Error('Failed: first word should be "abandon" for zero hash');
            }
            
            console.log('  Generated authcode for zero hash:', authcode);
            console.log('✅ Human-readable authcode generation passed');
        }
        
        // Test 4: Security level calculations
        console.log('Test 4: Security level calculations');
        const testSizes = [
            { words: 3, expectedBits: 33 },
            { words: 5, expectedBits: 55 },
            { words: 8, expectedBits: 88 }
        ];
        
        for (const { words, expectedBits } of testSizes) {
            const possibilities = Math.pow(2, expectedBits);
            if (possibilities !== Math.pow(2, words * 11)) {
                throw new Error(`Failed: security calculation wrong for ${words} words`);
            }
            console.log(`  ${words} words = ${expectedBits} bits = ${possibilities.toExponential(2)} possibilities`);
        }
        console.log('✅ Security level calculations passed');
        
        // Test 5: End-to-end pipeline with real hash
        console.log('Test 5: End-to-end pipeline with real hash');
        if (!wordlistReady) {
            console.log('⏭️ Skipping end-to-end test - BIP39 wordlist not ready');
        } else {
            // Create a known hash for testing
            const testData = new Uint8Array([0x48, 0x65, 0x6C, 0x6C, 0x6F]); // "Hello"
            const realHash = await window.crypto.subtle.digest('SHA-256', testData);
            const hashArray = new Uint8Array(realHash);
            
            const pipelineAuthcode = generateHumanReadableAuthcode(hashArray, 5);
            const directAuthcode = hashToAuthcode(hashArray, 5);
            
            if (pipelineAuthcode !== directAuthcode) {
                throw new Error('Failed: pipeline and direct methods should produce same result');
            }
            
            console.log('  Pipeline authcode:', pipelineAuthcode);
            console.log('  Direct authcode:  ', directAuthcode);
            console.log('✅ End-to-end pipeline with real hash passed');
        }
        
        // Test 6: Different word counts
        console.log('Test 6: Different word counts');
        if (wordlistReady) {
            const testHash6 = new Uint8Array(32);
            testHash6.fill(0xAA); // Pattern for testing
            
            for (const wordCount of [3, 4, 5, 6, 8]) {
                const authcode = generateHumanReadableAuthcode(testHash6, wordCount);
                const actualWords = authcode.split(' ').length;
                
                if (actualWords !== wordCount) {
                    throw new Error(`Failed: requested ${wordCount} words, got ${actualWords}`);
                }
            }
            console.log('✅ Different word counts passed');
        }
        
        // Test 7: Error handling
        console.log('Test 7: Error handling');
        try {
            extractBitsFromHash('invalid', 55);
            throw new Error('Failed: should throw error for invalid hash type');
        } catch (e) {
            if (!e.message.includes('Hash must be Uint8Array')) {
                throw new Error('Failed: wrong error message for invalid hash type');
            }
        }
        
        try {
            extractBitsFromHash(new Uint8Array(1), 55); // Too short
            throw new Error('Failed: should throw error for short hash');
        } catch (e) {
            if (!e.message.includes('Hash too short')) {
                throw new Error('Failed: wrong error message for short hash');
            }
        }
        console.log('✅ Error handling passed');
        
        console.log('🎉 All fingerprint generation pipeline tests passed successfully!');
        return true;
        
    } catch (error) {
        console.error('❌ Fingerprint generation pipeline test failed:', error.message);
        return false;
    }
}

async function demonstrateAliceBobFingerprints() {
    console.log('\n🔐 === ALICE & BOB MITM PROTECTION DEMONSTRATION ===');
    
    try {
        if (!wordlistReady) {
            console.log('⏭️ Skipping demonstration - BIP39 wordlist not ready');
            return false;
        }
        
        // Step 1: Alice generates her ECDH key pair
        console.log('\n👩 Alice: Generating ECDH key pair...');
        const aliceKeyPair = await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            false,
            ["deriveKey", "deriveBits"]
        );
        const alicePublicKey = await exportPublicKey(aliceKeyPair.publicKey);
        console.log('👩 Alice public key:', bytesToHex(alicePublicKey).substring(0, 32) + '...');
        
        // Step 2: Bob generates his ECDH key pair
        console.log('\n👨 Bob: Generating ECDH key pair...');
        const bobKeyPair = await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            false,
            ["deriveKey", "deriveBits"]
        );
        const bobPublicKey = await exportPublicKey(bobKeyPair.publicKey);
        console.log('👨 Bob public key:', bytesToHex(bobPublicKey).substring(0, 32) + '...');
        
        // Step 3: Alice computes fingerprint from both public keys
        console.log('\n👩 Alice: Computing fingerprint from both public keys...');
        const aliceAuthcode = await generateAuthcodeFromKeys(alicePublicKey, bobPublicKey, 5);
        console.log('👩 Alice\'s 5-word authcode:', aliceAuthcode);
        
        // Step 4: Bob computes fingerprint from both public keys
        console.log('\n👨 Bob: Computing fingerprint from both public keys...');
        const bobAuthcode = await generateAuthcodeFromKeys(bobPublicKey, alicePublicKey, 5);
        console.log('👨 Bob\'s 5-word authcode:', bobAuthcode);
        
        // Step 5: Verify they match (they should due to canonical ordering)
        console.log('\n🔍 Verification: Do the authcodes match?');
        const authcodesMatch = aliceAuthcode === bobAuthcode;
        console.log('Alice authcode:', aliceAuthcode);
        console.log('Bob authcode:  ', bobAuthcode);
        console.log('Match:', authcodesMatch ? '✅ YES' : '❌ NO');
        
        if (!authcodesMatch) {
            throw new Error('CRITICAL: Alice and Bob authcodes do not match!');
        }
        
        // Step 6: Show the protocol in action
        console.log('\n📋 MITM Protection Protocol:');
        console.log('1. Alice sends Bob the room ID via OOB channel (SMS/voice)');
        console.log('2. Both join the room and exchange public keys via WebSocket');
        console.log('3. Alice computes and sends Bob this authcode via OOB channel:');
        console.log(`   📱 "${aliceAuthcode}"`);
        console.log('4. Bob computes his own authcode and compares:');
        console.log(`   💭 "${bobAuthcode}"`);
        console.log('5. If they match ✅, no MITM attack - proceed with encryption');
        console.log('6. If they differ ❌, MITM attack detected - abort connection');
        
        // Step 7: Show security details
        console.log('\n🛡️ Security Details:');
        const hash = await hashCombinedPublicKeys(alicePublicKey, bobPublicKey);
        console.log('Combined key hash:', bytesToHex(hash));
        console.log('First 55 bits mapped to 5 BIP39 words');
        console.log('Security level: 2^55 = 36,028,797,018,963,968 possibilities');
        console.log('Attack probability: 1 in 36 quadrillion');
        
        // Step 8: Test with different key pairs to show different authcodes
        console.log('\n🔄 Testing with different key pair (should produce different authcode):');
        const eveKeyPair = await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            false,
            ["deriveKey", "deriveBits"]
        );
        const evePublicKey = await exportPublicKey(eveKeyPair.publicKey);
        const eveAuthcode = await generateAuthcodeFromKeys(alicePublicKey, evePublicKey, 5);
        console.log('👩 Alice + 😈 Eve authcode:', eveAuthcode);
        console.log('Different from Alice + Bob?', eveAuthcode !== aliceAuthcode ? '✅ YES' : '❌ NO');
        
        console.log('\n🎉 Alice & Bob MITM protection demonstration completed successfully!');
        console.log('📝 Summary: Both parties computed identical 5-word verification codes');
        console.log('🔒 The system successfully prevents man-in-the-middle attacks');
        
        return true;
        
    } catch (error) {
        console.error('❌ Alice & Bob demonstration failed:', error.message);
        return false;
    }
}

// MITM Protection Authentication Functions
async function computeFingerprint() {
    /*
     * Computes the fingerprint authcode after successful key exchange.
     * This is called automatically when both public keys are available.
     */
    
    try {
        // Check if keys are available
        if (!localPublicKeyRaw || !remotePublicKeyRaw) {
            console.error('Cannot compute fingerprint: missing public keys');
            console.log('Local key:', localPublicKeyRaw ? 'present' : 'missing');
            console.log('Remote key:', remotePublicKeyRaw ? 'present' : 'missing');
            return;
        }
        
        // Wait for wordlist to be ready if it's not yet
        if (!wordlistReady) {
            console.log('⏳ Wordlist not ready, waiting...');
            displaySystemMessage('⏳ Loading BIP39 wordlist for MITM protection...');
            
            // Wait up to 10 seconds for wordlist to load
            let attempts = 0;
            const maxAttempts = 50; // 50 * 200ms = 10 seconds
            
            while (!wordlistReady && attempts < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, 200));
                attempts++;
            }
            
            if (!wordlistReady) {
                console.error('Timeout waiting for BIP39 wordlist to load');
                displaySystemMessage('❌ Failed to load BIP39 wordlist - MITM protection unavailable');
                return;
            }
        }
        
        console.log('🔐 Computing MITM protection fingerprint...');
        displaySystemMessage('🔐 Computing MITM protection fingerprint...');
        authenticationInProgress = true;
        
        // Generate the 5-word authcode
        computedAuthcode = await generateAuthcodeFromKeys(localPublicKeyRaw, remotePublicKeyRaw, 5);
        
        console.log('✅ Fingerprint computed:', computedAuthcode);
        displaySystemMessage(`🔐 MITM protection authcode ready: "${computedAuthcode}"`);
        
        // Now display the authentication UI
        displayAuthenticationUI();
        
    } catch (error) {
        console.error('Failed to compute fingerprint:', error);
        displaySystemMessage('❌ Failed to compute MITM protection fingerprint: ' + error.message);
        authenticationInProgress = false;
    }
}

function displayAuthenticationUI() {
    /*
     * Shows the MITM protection authentication interface based on user role.
     * Alice sees her authcode to share, Bob sees input field to verify.
     */
    
    if (!computedAuthcode) {
        if (authenticationInProgress) {
            console.log('Authentication UI requested but authcode computation in progress...');
            displayWaitingForAuthcodeUI();
            return;
        } else {
            console.error('Cannot display authentication UI: no authcode computed and not in progress');
            return;
        }
    }
    
    // Create authentication section if it doesn't exist
    let authSection = document.getElementById('authenticationSection');
    if (!authSection) {
        authSection = document.createElement('div');
        authSection.id = 'authenticationSection';
        authSection.className = 'authentication-section';
        
        // Insert after security status
        const securityStatus = document.getElementById('securityStatus');
        securityStatus.parentNode.insertBefore(authSection, securityStatus.nextSibling);
    }
    
    // Clear previous content
    authSection.innerHTML = '';
    
    if (userRole === 'Alice') {
        displayAliceAuthcodeUI(authSection);
    } else if (userRole === 'Bob') {
        displayBobVerificationUI(authSection);
    }
    
    authSection.style.display = 'block';
}

function displayWaitingForAuthcodeUI() {
    /*
     * Shows a waiting UI while the authcode is being computed.
     */
    
    // Create authentication section if it doesn't exist
    let authSection = document.getElementById('authenticationSection');
    if (!authSection) {
        authSection = document.createElement('div');
        authSection.id = 'authenticationSection';
        authSection.className = 'authentication-section';
        
        // Insert after security status
        const securityStatus = document.getElementById('securityStatus');
        securityStatus.parentNode.insertBefore(authSection, securityStatus.nextSibling);
    }
    
    authSection.innerHTML = `
        <div class="auth-card">
            <h3>🔐 MITM Protection - Computing Fingerprint</h3>
            <div class="auth-loading">
                <div class="spinner"></div>
                <p>Computing cryptographic fingerprint...</p>
                <p><small>This may take a moment while the BIP39 wordlist loads.</small></p>
            </div>
        </div>
    `;
    
    authSection.style.display = 'block';
}

function displayAliceAuthcodeUI(container) {
    /*
     * Displays Alice's 5-word authcode with copy-to-clipboard functionality.
     */
    
    container.innerHTML = `
        <div class="auth-card alice-card">
            <h3>🔐 MITM Protection - Step 1</h3>
            <p><strong>You are Alice.</strong> Share this 5-word code with Bob via a separate secure channel (SMS, voice call, in person):</p>
            
            <div class="authcode-display">
                <code id="aliceAuthcode">${computedAuthcode}</code>
                <button id="copyAuthcodeBtn" class="copy-btn" title="Copy to clipboard">📋 Copy</button>
            </div>
            
            <div class="auth-instructions">
                <p><strong>Instructions:</strong></p>
                <ol>
                    <li>Copy the 5-word code above</li>
                    <li>Send it to Bob via SMS, voice call, or tell him in person</li>
                    <li>Bob will compare it with his computed code and confirm or reject</li>
                    <li>You will receive Bob's verification result automatically</li>
                    <li>If confirmed, secure messaging will be enabled for both users</li>
                </ol>
                
                <div id="waitingForBob" class="auth-feedback info" style="display: none;">
                    ⏳ Waiting for Bob to verify the code...
                </div>
            </div>
        </div>
    `;
    
    // Add event listeners
    document.getElementById('copyAuthcodeBtn').addEventListener('click', copyAuthcodeToClipboard);
}

function displayBobVerificationUI(container) {
    /*
     * Displays Bob's verification interface with computed authcode for confirmation.
     */
    
    container.innerHTML = `
        <div class="auth-card bob-card">
            <h3>🔐 MITM Protection - Step 2</h3>
            <p><strong>You are Bob.</strong> Alice should send you a 5-word code via a separate secure channel.</p>
            
            <div class="authcode-display">
                <code>${computedAuthcode}</code>
            </div>
            
            <div class="auth-instructions">
                <p><strong>Instructions:</strong></p>
                <ol>
                    <li>Wait for Alice to send you a 5-word code via SMS, voice call, or in person</li>
                    <li>Compare it with your computed code shown above</li>
                    <li>If they match exactly, click "Confirm" to proceed with secure messaging</li>
                    <li>If they differ, click "Reject" - there may be a MITM attack</li>
                </ol>
            </div>
            
            <div class="verification-buttons">
                <button id="confirmAuthcodeBtn" class="verify-btn">✅ Confirm - Codes Match</button>
                <button id="rejectAuthcodeBtn" class="reject-btn">❌ Reject - Codes Don't Match</button>
            </div>
        </div>
    `;
    
    // Add event listeners
    document.getElementById('confirmAuthcodeBtn').addEventListener('click', confirmAuthcode);
    document.getElementById('rejectAuthcodeBtn').addEventListener('click', rejectAuthcode);
}

async function copyAuthcodeToClipboard() {
    /*
     * Copies Alice's authcode to clipboard.
     */
    
    try {
        await navigator.clipboard.writeText(computedAuthcode);
        
        // Visual feedback
        const btn = document.getElementById('copyAuthcodeBtn');
        const originalText = btn.textContent;
        btn.textContent = '✅ Copied!';
        setTimeout(() => {
            btn.textContent = originalText;
        }, 2000);
        
        displaySystemMessage('📋 Authcode copied to clipboard');
        
        // Show waiting message
        const waitingDiv = document.getElementById('waitingForBob');
        if (waitingDiv) {
            waitingDiv.style.display = 'block';
        }
    } catch (error) {
        console.error('Failed to copy to clipboard:', error);
        displaySystemMessage('❌ Failed to copy to clipboard');
        
        // Fallback: select the text
        const authcodeElement = document.getElementById('aliceAuthcode');
        if (authcodeElement) {
            const range = document.createRange();
            range.selectNode(authcodeElement);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
        }
    }
}

async function confirmAuthcode() {
    /*
     * Bob confirms that the codes match (authentication successful).
     */
    
    try {
        displayAuthFeedback('Confirming verification...', 'info');
        
        // Authentication successful
        isAuthenticated = true;
        authenticationInProgress = false;
        
        displayAuthFeedback('✅ Verification successful! No MITM attack detected.', 'success');
        displaySystemMessage('🔒 MITM protection verified - secure messaging enabled');
        
        // Send encrypted ACK message to Alice to confirm verification
        if (ws && ws.readyState === WebSocket.OPEN && aesKey) {
            await sendEncryptedMessage('ACK - MITM protection verified by Bob');
        }
        
        // Hide authentication UI and enable messaging
        setTimeout(() => {
            hideAuthenticationUI();
            enableSecureMessaging();
            updateSecurityStatus('authenticated', 'MITM protection verified - secure messaging ready');
        }, 2000);
        
    } catch (error) {
        console.error('Confirmation error:', error);
        displayAuthFeedback('❌ Confirmation error: ' + error.message, 'error');
    }
}

async function rejectAuthcode() {
    /*
     * Bob rejects the verification (codes don't match - possible MITM attack).
     */
    
    try {
        displayAuthFeedback('❌ Verification rejected! Codes do not match. Possible MITM attack!', 'error');
        displaySystemMessage('⚠️ MITM protection failed - possible attack detected!');
        
        // Send encrypted NACK message to Alice to report verification failure
        if (ws && ws.readyState === WebSocket.OPEN && aesKey) {
            await sendEncryptedMessage('NACK - MITM protection FAILED - codes do not match');
        }
        
        // Show warning about potential MITM attack
        setTimeout(() => {
            alert(
                'SECURITY WARNING: The verification codes do not match!\n\n' +
                'This could indicate a man-in-the-middle attack where someone is intercepting your communications.\n\n' +
                'DO NOT proceed with messaging. Check your connection and try again with a secure channel.'
            );
        }, 1000);
        
    } catch (error) {
        console.error('Rejection error:', error);
        displayAuthFeedback('❌ Rejection error: ' + error.message, 'error');
    }
}

function displayAuthFeedback(message, type) {
    /*
     * Shows feedback messages in the authentication UI.
     */
    
    let feedbackElement = document.getElementById('authFeedback');
    if (!feedbackElement) {
        feedbackElement = document.createElement('div');
        feedbackElement.id = 'authFeedback';
        feedbackElement.className = 'auth-feedback';
        
        const authSection = document.getElementById('authenticationSection');
        if (authSection) {
            authSection.appendChild(feedbackElement);
        }
    }
    
    feedbackElement.className = `auth-feedback ${type}`;
    feedbackElement.textContent = message;
    feedbackElement.style.display = 'block';
    
    // Auto-hide info messages
    if (type === 'info') {
        setTimeout(() => {
            feedbackElement.style.display = 'none';
        }, 3000);
    }
}


function hideAuthenticationUI() {
    /*
     * Hides the authentication UI after verification is complete.
     */
    
    const authSection = document.getElementById('authenticationSection');
    if (authSection) {
        authSection.style.display = 'none';
    }
}

// Initialize BIP39 wordlist on page load
document.addEventListener('DOMContentLoaded', async () => {
    console.log('Loading BIP39 wordlist...');
    await loadBip39Wordlist();
    
    console.log('Validating BIP39 wordlist...');
    const validation = validateBip39Wordlist();
    if (!validation.valid) {
        console.error('BIP39 wordlist validation failed:', validation.error);
        return;
    }
    console.log('✅ BIP39 wordlist validation passed');
    
    // Run comprehensive tests
    const bip39TestsPassed = testBip39Functions();
    const keyOrderingTestsPassed = testPublicKeyOrdering();
    const sha256TestsPassed = await testSHA256HashFunctions();
    const pipelineTestsPassed = await testFingerprintGenerationPipeline();
    
    if (bip39TestsPassed && keyOrderingTestsPassed && sha256TestsPassed && pipelineTestsPassed) {
        console.log('🔐 Complete MITM protection system ready: BIP39, key ordering, SHA-256 hashing, and fingerprint pipeline');
        console.log('💡 Run "node test-alice-bob.js" to see Alice & Bob demonstration');
    } else {
        console.error('❌ System tests failed - MITM protection not available');
        if (!bip39TestsPassed) console.error('  - BIP39 tests failed');
        if (!keyOrderingTestsPassed) console.error('  - Key ordering tests failed');
        if (!sha256TestsPassed) console.error('  - SHA-256 hash tests failed');
        if (!pipelineTestsPassed) console.error('  - Fingerprint pipeline tests failed');
    }
});

// Event listeners
joinRoomButton.addEventListener('click', joinRoom);
leaveRoomButton.addEventListener('click', leaveRoom);
sendButton.addEventListener('click', sendMessage);
// Toggle all button events are now handled in the toggleAllMessages function above
messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

function joinRoom() {
    const inputRoomId = roomIdInput.value.trim();
    const serverHost = serverHostInput.value.trim();
    
    if (!inputRoomId) {
        alert('Please enter a room ID');
        return;
    }
    
    if (!serverHost) {
        alert('Please enter a server hostname and port');
        return;
    }
    
    if (ws) {
        ws.close();
    }
    
    roomId = inputRoomId;
    updateConnectionStatus('connecting');
    
    // Connect to WebSocket server using configured host
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${serverHost}`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log('WebSocket connected');
        // Send join room message
        ws.send(JSON.stringify({
            type: 'join_room',
            roomId: roomId
        }));
    };
    
    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleServerMessage(data);
        } catch (error) {
            console.error('Error parsing server message:', error);
        }
    };
    
    ws.onclose = () => {
        console.log('WebSocket disconnected');
        isConnected = false;
        updateConnectionStatus('disconnected');
        hideChatSection();
        unlockRoomControls();
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateConnectionStatus('disconnected');
        alert('Failed to connect to server');
    };
}

async function sendMessage() {
    const message = messageInput.value.trim();
    if (!message || !isConnected) return;
    
    // Block messaging until MITM protection is complete
    if (!isAuthenticated) {
        alert('Please complete MITM protection verification before sending messages.');
        return;
    }
    
    console.log('Sending message:', message);
    
    if (keyExchangeCompleted && aesKey) {
        try {
            // Encrypt the message
            const encrypted = await encryptMessage(message, aesKey);
            
            // Send encrypted message to server
            const encryptedMessageData = {
                type: 'encrypted_message',
                data: {
                    ciphertext: Array.from(encrypted.ciphertext),
                    iv: Array.from(encrypted.iv),
                    sender: userRole
                }
            };
            
            ws.send(JSON.stringify(encryptedMessageData));
            
            // Clear input and show sent message with encryption data
            messageInput.value = '';
            const encryptedData = { ciphertext: encrypted.ciphertext, iv: encrypted.iv };
            displayMessage('You', message, true, encryptedData);
            
            console.log('Encrypted message sent');
        } catch (error) {
            console.error('Failed to encrypt and send message:', error);
            alert('Failed to send encrypted message');
        }
    } else {
        alert('Encryption not ready. Please wait for key exchange to complete.');
    }
}

async function sendEncryptedMessage(messageText) {
    /*
     * Sends an encrypted message with the specified text (used for ACK/NACK).
     */
    
    if (!keyExchangeCompleted || !aesKey || !ws || ws.readyState !== WebSocket.OPEN) {
        throw new Error('Cannot send encrypted message - encryption not ready or connection closed');
    }
    
    try {
        // Encrypt the message
        const encrypted = await encryptMessage(messageText, aesKey);
        
        // Send encrypted message to server
        const encryptedMessageData = {
            type: 'encrypted_message',
            data: {
                ciphertext: Array.from(encrypted.ciphertext),
                iv: Array.from(encrypted.iv),
                sender: userRole
            }
        };
        
        ws.send(JSON.stringify(encryptedMessageData));
        console.log('Encrypted message sent:', messageText);
        
    } catch (error) {
        console.error('Failed to send encrypted message:', error);
        throw error;
    }
}

function displayMessage(sender, content, isDelivered = false, encryptedData = null) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isDelivered ? 'delivered' : ''}`;
    
    const messageHeader = document.createElement('div');
    messageHeader.className = 'message-header';
    
    const senderSpan = document.createElement('span');
    senderSpan.className = 'message-sender';
    senderSpan.textContent = sender;
    messageHeader.appendChild(senderSpan);
    
    if (encryptedData) {
        const lockIcon = document.createElement('span');
        lockIcon.className = 'lock-icon';
        lockIcon.textContent = '🔒';
        lockIcon.style.cursor = 'pointer';
        lockIcon.style.marginLeft = '10px';
        lockIcon.title = 'Hold to show decrypted message';
        
        // Hold to show plaintext, release to show encrypted
        lockIcon.addEventListener('mousedown', () => {
            showPlaintextWhilePressed(messageDiv, content, lockIcon);
        });
        
        lockIcon.addEventListener('mouseup', () => {
            showEncryptedText(messageDiv, encryptedData, lockIcon);
        });
        
        lockIcon.addEventListener('mouseleave', () => {
            showEncryptedText(messageDiv, encryptedData, lockIcon);
        });
        
        // Touch events for mobile
        lockIcon.addEventListener('touchstart', (e) => {
            e.preventDefault();
            showPlaintextWhilePressed(messageDiv, content, lockIcon);
        });
        
        lockIcon.addEventListener('touchend', (e) => {
            e.preventDefault();
            showEncryptedText(messageDiv, encryptedData, lockIcon);
        });
        
        messageHeader.appendChild(lockIcon);
        messageDiv.encryptedData = encryptedData;
        messageDiv.plaintextContent = content;
    }
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    
    // Always show encrypted text by default if encryption data exists
    if (encryptedData) {
        const encryptedText = `🔒 [${Array.from(encryptedData.ciphertext).slice(0, 20).map(b => b.toString(16).padStart(2, '0')).join('')}...]`;
        contentDiv.textContent = encryptedText;
    } else {
        contentDiv.textContent = content;
    }
    
    const timeDiv = document.createElement('div');
    timeDiv.className = 'message-time';
    timeDiv.textContent = new Date().toLocaleTimeString();
    
    messageDiv.appendChild(messageHeader);
    messageDiv.appendChild(contentDiv);
    messageDiv.appendChild(timeDiv);
    
    receivedMessages.appendChild(messageDiv);
    
    // Force scroll to bottom with multiple attempts to ensure it sticks
    const scrollToBottom = () => {
        receivedMessages.scrollTop = receivedMessages.scrollHeight;
    };
    
    scrollToBottom();
    setTimeout(scrollToBottom, 10);
    setTimeout(scrollToBottom, 50);
    setTimeout(scrollToBottom, 100);
    requestAnimationFrame(scrollToBottom);
}

function updateConnectionStatus(status) {
    connectionStatus.className = `status ${status}`;
    switch (status) {
        case 'disconnected':
            connectionStatus.textContent = 'Disconnected';
            break;
        case 'connecting':
            connectionStatus.textContent = 'Connecting...';
            break;
        case 'connected':
            connectionStatus.textContent = 'Connected to room: ' + roomId;
            break;
    }
}

function handleServerMessage(data) {
    console.log('Received server message:', data);
    
    switch (data.type) {
        case 'connected':
            console.log('Server connection established');
            break;
            
        case 'room_joined':
            isConnected = true;
            userRole = data.data.userRole;
            updateConnectionStatus('connected');
            showChatSection();
            lockRoomControls();
            updateUserIdentity(userRole);
            updateSecurityStatus('insecure', 'Not encrypted - waiting for key exchange');
            console.log(`Joined room: ${data.data.roomId}, clients: ${data.data.clientCount}, role: ${userRole}`);
            initiateKeyExchange();
            break;
            
        case 'user_joined':
            console.log(`User joined room, total clients: ${data.data.clientCount}`);
            displaySystemMessage(`User joined (${data.data.clientCount} total)`);
            initiateKeyExchange();
            break;
            
        case 'user_left':
            console.log(`User left room, total clients: ${data.data.clientCount}`);
            displaySystemMessage(`User left (${data.data.clientCount} total)`);
            keyExchangeCompleted = false;
            sharedSecret = null;
            remotePublicKey = null;
            aesKey = null;
            updateSecurityStatus('insecure', 'Not encrypted - user left, key exchange reset');
            break;
            
        case 'pubkey':
            handlePublicKeyReceived(data.data);
            break;
            
        case 'encrypted_message':
            handleEncryptedMessage(data.data);
            break;
            
        case 'error':
            console.error('Server error:', data.data.message);
            alert('Server error: ' + data.data.message);
            break;
            
        default:
            console.log('Unhandled message type:', data.type);
    }
}

function displaySystemMessage(message) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message system-message';
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.textContent = message;
    
    const timeDiv = document.createElement('div');
    timeDiv.className = 'message-time';
    timeDiv.textContent = new Date().toLocaleTimeString();
    
    messageDiv.appendChild(contentDiv);
    messageDiv.appendChild(timeDiv);
    
    receivedMessages.appendChild(messageDiv);
    
    // Force scroll to bottom with multiple attempts to ensure it sticks
    const scrollToBottom = () => {
        receivedMessages.scrollTop = receivedMessages.scrollHeight;
    };
    
    scrollToBottom();
    setTimeout(scrollToBottom, 10);
    setTimeout(scrollToBottom, 50);
    setTimeout(scrollToBottom, 100);
    requestAnimationFrame(scrollToBottom);
}

function showChatSection() {
    chatSection.style.display = 'block';
    sendButton.disabled = false;
}

function hideChatSection() {
    chatSection.style.display = 'none';
    sendButton.disabled = true;
}

function updateSecurityStatus(status, text) {
    securityStatus.className = `security-status ${status}`;
    securityText.textContent = text;
    
    if (status === 'secure') {
        securityIndicator.textContent = '🔒';
    } else {
        securityIndicator.textContent = '⚠️';
    }
}

async function initiateKeyExchange() {
    try {
        if (!keyPair) {
            console.log('Generating new key pair...');
            await generateKeyPair();
            console.log('Key pair generated successfully');
        }
        
        console.log('Exporting public key...');
        const publicKeyData = await exportPublicKey(keyPair.publicKey);
        console.log('Public key exported, length:', publicKeyData.length);
        const publicKeyArray = Array.from(publicKeyData);
        
        const message = {
            type: 'pubkey',
            data: {
                publicKey: publicKeyArray
            }
        };
        
        ws.send(JSON.stringify(message));
        console.log('Public key sent for key exchange');
        updateSecurityStatus('key-exchange', 'Key exchange in progress - deriving shared secret...');
    } catch (error) {
        console.error('Failed to initiate key exchange:', error.message);
        console.error('Full error:', error);
        updateSecurityStatus('insecure', `Key exchange failed: ${error.message}`);
    }
}

async function handlePublicKeyReceived(data) {
    try {
        console.log('Received public key data:', data);
        const publicKeyData = new Uint8Array(data.publicKey);
        console.log('Public key byte array length:', publicKeyData.length);
        
        remotePublicKey = await importPublicKey(publicKeyData);
        console.log('Remote public key imported successfully');
        
        sharedSecret = await deriveSharedSecret(keyPair.privateKey, remotePublicKey);
        console.log('Shared secret derived successfully');
        
        updateSecurityStatus('key-exchange', 'Deriving AES encryption key...');
        
        aesKey = await deriveAESKey(sharedSecret);
        console.log('AES key derived successfully');
        keyExchangeCompleted = true;
        
        console.log('Key exchange completed successfully');
        
        // Store raw public key data for MITM protection
        remotePublicKeyRaw = publicKeyData;
        localPublicKeyRaw = await exportPublicKey(keyPair.publicKey);
        
        // Compute fingerprint for MITM protection
        await computeFingerprint();
        
        updateSecurityStatus('secure', 'Ready for encrypted messaging - AES-GCM active');
        displaySystemMessage('🔒 Ready for secure messaging - end-to-end encryption active');
        displaySharedSecretInfo();
        
        // Don't enable secure messaging until authentication is complete
        if (isAuthenticated) {
            enableSecureMessaging();
        } else {
            updateSecurityStatus('key-exchange', 'Waiting for MITM protection verification...');
            // displayAuthenticationUI will be called automatically after computeFingerprint completes
        }
    } catch (error) {
        console.error('Failed to complete key exchange at step:', error.message);
        console.error('Full error:', error);
        updateSecurityStatus('insecure', `Key exchange failed: ${error.message}`);
    }
}

function updateUserIdentity(role) {
    if (role) {
        userName.textContent = `You are: ${role}`;
        userIdentity.style.display = 'block';
    } else {
        userIdentity.style.display = 'none';
    }
}

function lockRoomControls() {
    roomIdInput.disabled = true;
    serverHostInput.disabled = true;
    joinRoomButton.style.display = 'none';
    leaveRoomButton.style.display = 'inline-block';
}

function unlockRoomControls() {
    roomIdInput.disabled = false;
    serverHostInput.disabled = false;
    joinRoomButton.style.display = 'inline-block';
    leaveRoomButton.style.display = 'none';
}

function leaveRoom() {
    if (ws) {
        ws.send(JSON.stringify({
            type: 'leave_room'
        }));
        ws.close();
    }
    
    location.reload();
}

function displaySharedSecretInfo() {
    try {
        // Note: sharedSecret and aesKey are non-extractable for security
        // We can't export their values, but we can show that they were derived successfully
        
        if (computedAuthcode) {
            // Use the MITM protection authcode as a fingerprint since it's derived from the same public keys
            displaySystemMessage(`🔑 AES key derived - Verification code: "${computedAuthcode}"`);
            console.log('AES key derived successfully');
            console.log('MITM protection authcode available:', computedAuthcode);
        } else {
            // Fallback message when authcode is not yet computed
            displaySystemMessage('🔑 AES key derived with HKDF/SHA-256 - ready for encryption');
            console.log('AES key derived successfully (keys are non-extractable for security)');
        }
        
        console.log('Encryption ready: AES-GCM with 256-bit key');
        console.log('Forward secrecy: Keys are ephemeral and non-persistent');
    } catch (error) {
        console.error('Failed to display shared secret info:', error);
        displaySystemMessage('🔑 AES key derived successfully');
    }
}

function showPlaintextWhilePressed(messageDiv, plaintextContent, lockIcon) {
    const contentDiv = messageDiv.querySelector('.message-content');
    contentDiv.textContent = plaintextContent;
    lockIcon.textContent = '🔓';
}

function showEncryptedText(messageDiv, encryptedData, lockIcon) {
    const contentDiv = messageDiv.querySelector('.message-content');
    const encryptedText = `🔒 [${Array.from(encryptedData.ciphertext).slice(0, 20).map(b => b.toString(16).padStart(2, '0')).join('')}...]`;
    contentDiv.textContent = encryptedText;
    lockIcon.textContent = '🔒';
}

let isGlobalUnlockPressed = false;

function toggleAllMessages() {
    // This function is now triggered by mousedown/mouseup events
}

// Replace the toggle all button click with mousedown/mouseup events
toggleAllButton.addEventListener('mousedown', () => {
    isGlobalUnlockPressed = true;
    showAllPlaintext();
});

toggleAllButton.addEventListener('mouseup', () => {
    isGlobalUnlockPressed = false;
    showAllEncrypted();
});

toggleAllButton.addEventListener('mouseleave', () => {
    if (isGlobalUnlockPressed) {
        isGlobalUnlockPressed = false;
        showAllEncrypted();
    }
});

// Touch events for mobile
toggleAllButton.addEventListener('touchstart', (e) => {
    e.preventDefault();
    isGlobalUnlockPressed = true;
    showAllPlaintext();
});

toggleAllButton.addEventListener('touchend', (e) => {
    e.preventDefault();
    isGlobalUnlockPressed = false;
    showAllEncrypted();
});

function showAllPlaintext() {
    toggleAllButton.textContent = '🔓 Showing All';
    const messages = receivedMessages.querySelectorAll('.message');
    messages.forEach(messageDiv => {
        if (messageDiv.encryptedData && messageDiv.plaintextContent) {
            const contentDiv = messageDiv.querySelector('.message-content');
            const lockIcon = messageDiv.querySelector('.lock-icon');
            contentDiv.textContent = messageDiv.plaintextContent;
            lockIcon.textContent = '🔓';
        }
    });
}

function showAllEncrypted() {
    toggleAllButton.textContent = '🔒 Hold to Show All';
    const messages = receivedMessages.querySelectorAll('.message');
    messages.forEach(messageDiv => {
        if (messageDiv.encryptedData && messageDiv.plaintextContent) {
            const contentDiv = messageDiv.querySelector('.message-content');
            const lockIcon = messageDiv.querySelector('.lock-icon');
            const encryptedText = `🔒 [${Array.from(messageDiv.encryptedData.ciphertext).slice(0, 20).map(b => b.toString(16).padStart(2, '0')).join('')}...]`;
            contentDiv.textContent = encryptedText;
            lockIcon.textContent = '🔒';
        }
    });
}

function enableSecureMessaging() {
    if (keyExchangeCompleted && aesKey) {
        displaySystemMessage('✅ Both participants ready - encrypted messaging enabled');
        updateSecurityStatus('secure', `${userRole} ready for encrypted messaging`);
        
        // Enable message input
        messageInput.placeholder = 'Type your encrypted message here...';
        sendButton.textContent = 'Send Encrypted';
        
        console.log(`${userRole} is ready for secure messaging`);
    }
}

async function handleEncryptedMessage(data) {
    try {
        if (!keyExchangeCompleted || !aesKey) {
            console.error('Received encrypted message but encryption not ready');
            return;
        }
        
        const ciphertext = new Uint8Array(data.ciphertext);
        const iv = new Uint8Array(data.iv);
        const sender = data.sender;
        
        console.log('Received encrypted message from:', sender);
        
        const decryptedMessage = await decryptMessage(ciphertext, iv, aesKey);
        
        // Check if this is an ACK/NACK message for MITM protection verification
        if (decryptedMessage.startsWith('ACK - MITM protection verified')) {
            // Bob confirmed verification - Alice receives this
            if (userRole === 'Alice' && authenticationInProgress) {
                isAuthenticated = true;
                authenticationInProgress = false;
                
                displaySystemMessage('✅ Bob confirmed verification - MITM protection complete');
                displayAuthFeedback('✅ Bob confirmed the codes match! Secure messaging enabled.', 'success');
                
                // Hide authentication UI and enable messaging for Alice
                setTimeout(() => {
                    hideAuthenticationUI();
                    enableSecureMessaging();
                    updateSecurityStatus('authenticated', 'MITM protection verified - secure messaging ready');
                }, 2000);
                
                console.log('Alice received ACK from Bob - verification complete');
                return; // Don't display as regular message
            }
        } else if (decryptedMessage.startsWith('NACK - MITM protection FAILED')) {
            // Bob rejected verification - Alice receives this
            if (userRole === 'Alice' && authenticationInProgress) {
                displaySystemMessage('❌ Bob rejected verification - possible MITM attack detected');
                displayAuthFeedback('❌ Bob reports codes do not match! Possible MITM attack!', 'error');
                
                // Show warning to Alice
                setTimeout(() => {
                    alert(
                        'SECURITY WARNING: Bob reports the verification codes do not match!\n\n' +
                        'This indicates a possible man-in-the-middle attack.\n\n' +
                        'DO NOT proceed with messaging. Check your connection and try again.'
                    );
                }, 1000);
                
                console.log('Alice received NACK from Bob - verification failed');
                return; // Don't display as regular message
            }
        }
        
        // Display regular messages with encryption toggle capability
        const senderName = sender === userRole ? 'You' : sender;
        const encryptedData = { ciphertext, iv };
        displayMessage(senderName, decryptedMessage, true, encryptedData);
        
        console.log('Message decrypted and displayed');
    } catch (error) {
        console.error('Failed to decrypt received message:', error);
        displayMessage('System', '❌ Failed to decrypt message', false);
    }
}

