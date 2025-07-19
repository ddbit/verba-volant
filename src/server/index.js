const WebSocket = require('ws');
const http = require('http');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 31415;

const rooms = new Map();

const server = http.createServer((req, res) => {
  // Security: No static file serving - client files must be distributed separately
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Static files not served. Use distributed client files.');
});

const wss = new WebSocket.Server({ server });

function joinRoom(ws, roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, new Set());
  }
  
  const room = rooms.get(roomId);
  
  if (room.size >= 2) {
    ws.send(JSON.stringify({
      type: 'error',
      data: { message: 'Room is full. Only Alice and Bob are allowed.' }
    }));
    return;
  }
  
  room.add(ws);
  ws.roomId = roomId;
  
  const userRole = room.size === 1 ? 'Alice' : 'Bob';
  ws.userRole = userRole;
  
  console.log(`Client joined room: ${roomId} as ${userRole} (${room.size} clients in room)`);
  
  ws.send(JSON.stringify({
    type: 'room_joined',
    data: { 
      roomId: roomId,
      clientCount: room.size,
      userRole: userRole
    }
  }));
  
  broadcastToRoom(roomId, {
    type: 'user_joined',
    data: { clientCount: room.size }
  }, ws);
}

function leaveRoom(ws) {
  if (ws.roomId) {
    const room = rooms.get(ws.roomId);
    if (room) {
      room.delete(ws);
      console.log(`Client left room: ${ws.roomId} (${room.size} clients remaining)`);
      
      if (room.size === 0) {
        rooms.delete(ws.roomId);
        console.log(`Room ${ws.roomId} deleted (empty)`);
      } else {
        broadcastToRoom(ws.roomId, {
          type: 'user_left',
          data: { clientCount: room.size }
        });
      }
    }
    ws.roomId = null;
  }
}

function broadcastToRoom(roomId, message, excludeWs = null) {
  const room = rooms.get(roomId);
  if (room) {
    room.forEach(client => {
      if (client !== excludeWs && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(message));
      }
    });
  }
}

wss.on('connection', (ws) => {
  console.log('New client connected');
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      console.log('Received:', data);
      
      switch (data.type) {
        case 'join_room':
          if (data.roomId) {
            leaveRoom(ws);
            joinRoom(ws, data.roomId);
          } else {
            ws.send(JSON.stringify({
              type: 'error',
              data: { message: 'Room ID is required' }
            }));
          }
          break;
          
        case 'leave_room':
          leaveRoom(ws);
          ws.send(JSON.stringify({
            type: 'room_left',
            data: { message: 'Left room successfully' }
          }));
          break;
          
        case 'pubkey':
          if (ws.roomId) {
            broadcastToRoom(ws.roomId, {
              type: 'pubkey',
              data: data.data
            }, ws);
            console.log(`Public key relayed in room: ${ws.roomId}`);
          } else {
            ws.send(JSON.stringify({
              type: 'error',
              data: { message: 'Not in a room' }
            }));
          }
          break;
          
        case 'encrypted_message':
          if (ws.roomId) {
            broadcastToRoom(ws.roomId, {
              type: 'encrypted_message',
              data: data.data
            }, ws);
            console.log(`Encrypted message relayed in room: ${ws.roomId} from ${data.data.sender}`);
          } else {
            ws.send(JSON.stringify({
              type: 'error',
              data: { message: 'Not in a room' }
            }));
          }
          break;
          
        default:
          ws.send(JSON.stringify({
            type: 'echo',
            data: data
          }));
      }
    } catch (error) {
      console.error('Error parsing message:', error);
      ws.send(JSON.stringify({
        type: 'error',
        data: { message: 'Invalid message format' }
      }));
    }
  });
  
  ws.on('close', () => {
    console.log('Client disconnected');
    leaveRoom(ws);
  });
  
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    leaveRoom(ws);
  });
  
  ws.send(JSON.stringify({
    type: 'connected',
    data: { message: 'Connected to Verba Volant server' }
  }));
});

server.listen(PORT, () => {
  console.log(`Verba Volant server running on port ${PORT}`);
});