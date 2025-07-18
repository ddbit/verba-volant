// Placeholder client-side JavaScript
// This will be implemented in Phase 2 with crypto functionality

console.log('Verba Volant Client Initialized');

// DOM elements
const serverHostInput = document.getElementById('serverHost');
const roomIdInput = document.getElementById('roomId');
const joinRoomButton = document.getElementById('joinRoom');
const connectionStatus = document.getElementById('connectionStatus');
const chatSection = document.getElementById('chatSection');
const securityStatus = document.getElementById('securityStatus');
const securityIndicator = document.getElementById('securityIndicator');
const securityText = document.getElementById('securityText');
const messageInput = document.getElementById('messageInput');
const sendButton = document.getElementById('sendMessage');
const receivedMessages = document.getElementById('receivedMessages');

// State
let ws = null;
let roomId = null;
let isConnected = false;

// Event listeners
joinRoomButton.addEventListener('click', joinRoom);
sendButton.addEventListener('click', sendMessage);
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
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateConnectionStatus('disconnected');
        alert('Failed to connect to server');
    };
}

function sendMessage() {
    const message = messageInput.value.trim();
    if (!message || !isConnected) return;
    
    console.log('Sending message:', message);
    
    // Placeholder: Will implement encryption in Phase 2
    // For now, just clear the input
    messageInput.value = '';
    
    // Simulate message sending
    displayMessage('You', message, true);
}

function displayMessage(sender, content, isDelivered = false) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isDelivered ? 'delivered' : ''}`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.textContent = content;
    
    const timeDiv = document.createElement('div');
    timeDiv.className = 'message-time';
    timeDiv.textContent = new Date().toLocaleTimeString();
    
    messageDiv.appendChild(contentDiv);
    messageDiv.appendChild(timeDiv);
    
    receivedMessages.appendChild(messageDiv);
    receivedMessages.scrollTop = receivedMessages.scrollHeight;
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
            updateConnectionStatus('connected');
            showChatSection();
            updateSecurityStatus('insecure', 'Not encrypted - waiting for key exchange');
            console.log(`Joined room: ${data.data.roomId}, clients: ${data.data.clientCount}`);
            break;
            
        case 'user_joined':
            console.log(`User joined room, total clients: ${data.data.clientCount}`);
            displaySystemMessage(`User joined (${data.data.clientCount} total)`);
            break;
            
        case 'user_left':
            console.log(`User left room, total clients: ${data.data.clientCount}`);
            displaySystemMessage(`User left (${data.data.clientCount} total)`);
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
    receivedMessages.scrollTop = receivedMessages.scrollHeight;
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