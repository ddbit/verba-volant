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