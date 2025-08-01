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
let BIP39_WORDLIST = null;
let wordlistReady = false;

async function loadBip39Wordlist() {
    try {
        const response = await fetch('../bip39/english.txt');
        const text = await response.text();
        BIP39_WORDLIST = text.trim().split('\n').map(word => word.trim().toLowerCase());
        
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
    const testsPassed = testBip39Functions();
    if (testsPassed) {
        console.log('🔐 BIP39 system ready for MITM protection');
    } else {
        console.error('❌ BIP39 system tests failed - MITM protection not available');
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
        updateSecurityStatus('secure', 'Ready for encrypted messaging - AES-GCM active');
        displaySystemMessage('🔒 Ready for secure messaging - end-to-end encryption active');
        displaySharedSecretInfo();
        enableSecureMessaging();
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

async function displaySharedSecretInfo() {
    try {
        const secretBytes = await window.crypto.subtle.exportKey("raw", sharedSecret);
        const secretArray = new Uint8Array(secretBytes);
        const secretHex = Array.from(secretArray)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
        
        const shortFingerprint = secretHex.substring(0, 16);
        displaySystemMessage(`🔑 AES key derived with HKDF/SHA-256 (${shortFingerprint}...)`);
        
        console.log('Shared secret fingerprint:', shortFingerprint);
        console.log('AES key ready for encryption/decryption');
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
        
        // Display the message with encryption toggle capability
        const senderName = sender === userRole ? 'You' : sender;
        const encryptedData = { ciphertext, iv };
        displayMessage(senderName, decryptedMessage, true, encryptedData);
        
        console.log('Message decrypted and displayed');
    } catch (error) {
        console.error('Failed to decrypt received message:', error);
        displayMessage('System', '❌ Failed to decrypt message', false);
    }
}