const socketIo = require('socket.io');

function setupSocket(server) {
  const io = socketIo(server, {
    cors: {
      origin: '*',
      methods: ['GET', 'POST']
    }
  });

  const rooms = new Map();
  const callStates = new Map(); // Track call states per room

  io.on('connection', (socket) => {
    console.log('New client connected');

    // Broadcast updated online user count to all clients
    const onlineUsers = io.sockets.sockets.size;
    io.emit('onlineUsersUpdate', onlineUsers);
    console.log(`Online users: ${onlineUsers}`);

    // Handle background changes
    socket.on('changeBackground', ({ roomCode, backgroundImage }) => {
      try {
        const room = rooms.get(roomCode);
        if (room) {
          // Store the background image in room data
          room.backgroundImage = backgroundImage;
          // Broadcast to ALL users in the room including sender
          io.in(roomCode).emit('backgroundChanged', { backgroundImage });
          console.log(`Background changed in room ${roomCode}`);
        }
      } catch (error) {
        console.error('Error handling background change:', error);
      }
    });

    socket.on('createRoom', (username, callback) => {
      try {
        // Generate a random 6-character room code
        const roomCode = Math.random().toString(36).substring(2, 8).toUpperCase();

        // Create room data structure
        rooms.set(roomCode, {
          users: [{ id: socket.id, username }],
          messages: [],
          backgroundImage: null // Initialize background image
        });

        // Join socket to the room
        socket.join(roomCode);

        // Send room code back to client
        callback(roomCode);

        // Notify room of new user
        io.to(roomCode).emit('message', {
          username: 'System',
          message: `${username} has created the room`,
          timestamp: new Date().toLocaleTimeString()
        });

        console.log(`Room ${roomCode} created by ${username}`);
      } catch (error) {
        console.error('Error creating room:', error);
        callback({ error: 'Failed to create room' });
      }
    });

    socket.on('joinRoom', ({ roomCode, username }, callback) => {
      try {
        const room = rooms.get(roomCode);

        if (!room) {
          callback({ error: 'Room not found' });
          return;
        }

        // Add user to room
        room.users.push({ id: socket.id, username });

        // Join socket to the room
        socket.join(roomCode);

        // Store room code for disconnection handling
        socket.roomCode = roomCode;

        // Send current room background to the joining user
        if (room.backgroundImage) {
          socket.emit('roomBackground', { backgroundImage: room.backgroundImage });
          console.log(`Sent background to new user in room ${roomCode}`);
        }

        // Send room history to the joining user
        if (room.messages) {
          socket.emit('roomHistory', { messages: room.messages });
        }

        // Send updated user list to all users in the room
        const users = room.users.map(user => user.username);
        io.to(roomCode).emit('roomUsers', { users });

        // Notify room of new user
        io.to(roomCode).emit('userJoined', { username, users });

        callback({ success: true });

        console.log(`${username} joined room ${roomCode}`);
      } catch (error) {
        console.error('Error joining room:', error);
        callback({ error: 'Failed to join room' });
      }
    });

    socket.on('chatMessage', ({ roomCode, message }) => {
      try {
        const room = rooms.get(roomCode);

        if (!room) {
          console.error(`Room ${roomCode} not found`);
          return;
        }

        // Log message type
        console.log(`Message with ${message.audioBase64 ? 'audio' : ''} ${message.attachmentBase64 ? 'attachment' : ''} in room ${roomCode}`);

        // Limit base64 data size for very large files if needed
        if (message.audioBase64 && message.audioBase64.length > 10 * 1024 * 1024) { // 10MB limit
          console.warn('Audio too large, truncating');
          message.audioBase64 = message.audioBase64.substring(0, 10 * 1024 * 1024);
        }

        if (message.attachmentBase64 && message.attachmentBase64.length > 10 * 1024 * 1024) { // 10MB limit
          console.warn('Attachment too large, truncating');
          message.attachmentBase64 = message.attachmentBase64.substring(0, 10 * 1024 * 1024);
        }

        // Store message in room history (with attachments)
        room.messages.push(message);

        // Broadcast to all users in the room except sender
        socket.to(roomCode).emit('message', message);

      } catch (error) {
        console.error('Error sending message:', error);
      }
    });

    // Handle messages including attachments
    socket.on('sendMessage', (message) => {
      console.log(`Message received from ${message.username} in room ${message.roomCode}`);

      // Store message in room history
      const room = rooms.get(message.roomCode);
      if (room) {
        if (!room.messages) {
          room.messages = [];
        }
        room.messages.push(message);
      }

      // Broadcast to everyone in the room including sender
      io.in(message.roomCode).emit('receiveMessage', message);
    });

    // Add message edit handler
    socket.on('editMessage', ({ roomCode, messageId, newContent }) => {
      console.log(`Edit request received for message ${messageId} in room ${roomCode}`);

      const room = rooms.get(roomCode);
      if (room && room.messages) {
        const messageIndex = room.messages.findIndex(msg => msg.id === messageId);
        if (messageIndex !== -1) {
          // Update the message content
          room.messages[messageIndex].message = newContent;
          room.messages[messageIndex].isEdited = true;
          room.messages[messageIndex].editedAt = new Date().toISOString();

          // Broadcast the edited message to all users in the room
          io.in(roomCode).emit('messageEdited', room.messages[messageIndex]);
        }
      }
    });

    // Add message delete handler
    socket.on('deleteMessage', ({ roomCode, messageId }) => {
      console.log(`Delete request received for message ${messageId} in room ${roomCode}`);

      const room = rooms.get(roomCode);
      if (room && room.messages) {
        const messageIndex = room.messages.findIndex(msg => msg.id === messageId);
        if (messageIndex !== -1) {
          const deletedMessage = room.messages[messageIndex];
          // Remove the message from the room's message history
          room.messages.splice(messageIndex, 1);

          // Broadcast the deletion to all users in the room with the username
          io.in(roomCode).emit('messageDeleted', {
            messageId,
            roomCode,
            username: deletedMessage.username
          });
        }
      }
    });

    // WebRTC Signaling Handlers
    socket.on('signal', ({ to, data }) => {
      console.log(`WebRTC signal from ${socket.id} to ${to}`, data);
      const targetSocket = io.sockets.sockets.get(to);
      if (targetSocket) {
        targetSocket.emit('signal', { from: socket.id, data });
      }
    });

    socket.on('join', (room) => {
      console.log(`User ${socket.id} joining room ${room}`);
      socket.join(room);
      socket.room = room;

      // Get all users in the room
      const roomSockets = io.sockets.adapter.rooms.get(room);
      if (roomSockets) {
        const users = Array.from(roomSockets).filter(id => id !== socket.id);
        socket.emit('all-users', users);

        // Notify other users about the new user
        socket.to(room).emit('user-joined', socket.id);

        // Send user count to all users in the room
        const userCount = roomSockets.size;
        io.to(room).emit('user-count', userCount);
      }
    });

    socket.on('offer', ({ to, offer }) => {
      console.log(`WebRTC offer from ${socket.id} to ${to}`);
      const targetSocket = io.sockets.sockets.get(to);
      if (targetSocket) {
        targetSocket.emit('offer', { from: socket.id, offer });
      }
    });

    socket.on('answer', ({ to, answer }) => {
      console.log(`WebRTC answer from ${socket.id} to ${to}`);
      const targetSocket = io.sockets.sockets.get(to);
      if (targetSocket) {
        targetSocket.emit('answer', { from: socket.id, answer });
      }
    });

    socket.on('iceCandidate', ({ to, candidate }) => {
      console.log(`ICE candidate from ${socket.id} to ${to}`);
      const targetSocket = io.sockets.sockets.get(to);
      if (targetSocket) {
        targetSocket.emit('iceCandidate', { from: socket.id, candidate });
      }
    });

    // Call management handlers
    socket.on('callRequest', ({ roomCode, from, participants, message }) => {
      console.log(`Call request from ${from} in room ${roomCode} with participants:`, participants);

      // Initialize call state for the room
      if (!callStates.has(roomCode)) {
        callStates.set(roomCode, {
          isActive: false,
          participants: [],
          initiator: null
        });
      }

      const callState = callStates.get(roomCode);
      callState.isActive = true;
      callState.participants = participants || [];
      callState.initiator = from;

      // Emit call request to all users in the room
      io.to(roomCode).emit('callRequest', {
        from,
        roomCode,
        participants: callState.participants,
        message: message || `${from} is calling everyone in the room`
      });
    });

    socket.on('callAccepted', ({ from, roomCode }) => {
      console.log(`Call accepted by ${from} in room ${roomCode}`);

      const callState = callStates.get(roomCode);
      if (callState && callState.isActive) {
        // Add user to call participants if not already there
        if (!callState.participants.includes(from)) {
          callState.participants.push(from);
        }

        io.to(roomCode).emit('callAccepted', {
          from,
          roomCode,
          callParticipants: callState.participants,
          callState: 'connected'
        });
      }
    });

    socket.on('callRejected', ({ from, roomCode }) => {
      console.log(`Call rejected by ${from} in room ${roomCode}`);

      const callState = callStates.get(roomCode);
      if (callState) {
        // Remove user from participants
        callState.participants = callState.participants.filter(p => p !== from);

        // If no participants left, end the call
        if (callState.participants.length === 0) {
          callState.isActive = false;
          callState.initiator = null;
        }
      }

      io.to(roomCode).emit('callRejected', { from, roomCode });
    });

    socket.on('callEnded', ({ roomCode, from }) => {
      console.log(`Call ended by ${from} in room ${roomCode}`);

      // Clear call state
      callStates.delete(roomCode);

      io.to(roomCode).emit('callEnded', {
        from,
        roomCode,
        message: `${from} ended the call`
      });
    });

    socket.on('userJoinedCall', ({ username, roomCode }) => {
      console.log(`User ${username} joined call in room ${roomCode}`);

      const callState = callStates.get(roomCode);
      if (callState && callState.isActive) {
        // Add user to call participants if not already there
        if (!callState.participants.includes(username)) {
          callState.participants.push(username);
        }

        io.to(roomCode).emit('userJoinedCall', {
          username,
          roomCode,
          callParticipants: callState.participants
        });
      }
    });

    socket.on('userLeftCall', ({ username, roomCode }) => {
      console.log(`User ${username} left call in room ${roomCode}`);

      const callState = callStates.get(roomCode);
      if (callState) {
        // Remove user from participants
        callState.participants = callState.participants.filter(p => p !== username);

        // If no participants left, end the call
        if (callState.participants.length === 0) {
          callState.isActive = false;
          callState.initiator = null;
        }
      }

      io.to(roomCode).emit('userLeftCall', {
        username,
        roomCode,
        callParticipants: callState.participants || [],
        callState: callState && callState.participants.length > 0 ? 'connected' : 'idle'
      });
    });

    socket.on('videoStateChanged', ({ roomCode, username, isVideoEnabled }) => {
      console.log(`Video state changed for ${username} in room ${roomCode}: ${isVideoEnabled}`);
      io.to(roomCode).emit('videoStateChanged', { username, isVideoEnabled });
    });

    // Get room participants
    socket.on('getRoomParticipants', ({ roomCode }) => {
      console.log(`Getting participants for room ${roomCode}`);
      const room = rooms.get(roomCode);
      if (room) {
        const participants = room.users.map(user => user.username);
        socket.emit('roomParticipants', { participants });
      }
    });

    // Get socket ID for a username
    socket.on('getSocketId', ({ username }, callback) => {
      console.log(`Getting socket ID for username: ${username}`);
      // Search through all rooms to find the user
      for (const [roomCode, room] of rooms.entries()) {
        const user = room.users.find(u => u.username === username);
        if (user) {
          console.log(`Found socket ID ${user.id} for username ${username}`);
          callback({ socketId: user.id });
          return;
        }
      }
      console.log(`User ${username} not found in any room`);
      callback({ error: 'User not found' });
    });

    // Get username for a socket ID
    socket.on('getUsername', ({ socketId }, callback) => {
      console.log(`Getting username for socket ID: ${socketId}`);
      // Search through all rooms to find the user
      for (const [roomCode, room] of rooms.entries()) {
        const user = room.users.find(u => u.id === socketId);
        if (user) {
          console.log(`Found username ${user.username} for socket ID ${socketId}`);
          callback({ username: user.username });
          return;
        }
      }
      console.log(`Socket ID ${socketId} not found in any room`);
      callback({ error: 'User not found' });
    });

    // Register user
    socket.on('register', (username) => {
      console.log(`User ${username} registered with socket ${socket.id}`);
      socket.username = username;
    });

    // Typing indicator
    socket.on('typing', ({ room, username, isTyping }) => {
      console.log(`User ${username} ${isTyping ? 'started' : 'stopped'} typing in room ${room}`);
      socket.to(room).emit('userTyping', { username, isTyping });
    });

    // Like message
    socket.on('likeMessage', ({ roomCode, messageId }) => {
      console.log(`Message ${messageId} liked in room ${roomCode}`);
      const room = rooms.get(roomCode);
      if (room && room.messages) {
        const message = room.messages.find(msg => msg.id === messageId);
        if (message) {
          if (!message.likes) message.likes = [];
          if (!message.likes.includes(socket.username)) {
            message.likes.push(socket.username);
            io.to(roomCode).emit('messageLiked', { messageId, likes: message.likes });
          }
        }
      }
    });

    socket.on('disconnect', () => {
      try {
        console.log('Client disconnected');

        // Broadcast updated online user count to all remaining clients
        setTimeout(() => {
          const onlineUsers = io.sockets.sockets.size;
          io.emit('onlineUsersUpdate', onlineUsers);
          console.log(`Online users after disconnect: ${onlineUsers}`);
        }, 100);

        // Handle voice call cleanup
        if (socket.room) {
          socket.to(socket.room).emit('user-left', socket.id);

          // Update user count for remaining users
          const roomSockets = io.sockets.adapter.rooms.get(socket.room);
          if (roomSockets) {
            const userCount = roomSockets.size;
            io.to(socket.room).emit('user-count', userCount);
          }
        }

        // Handle user leaving rooms
        const roomCode = socket.roomCode;

        if (roomCode && rooms.has(roomCode)) {
          const room = rooms.get(roomCode);

          // Find user in room
          const userIndex = room.users.findIndex(user => user.id === socket.id);

          if (userIndex !== -1) {
            const user = room.users[userIndex];

            // Remove user from room
            room.users.splice(userIndex, 1);

            // Send updated user list to remaining users
            const users = room.users.map(u => u.username);
            io.to(roomCode).emit('userLeft', { username: user.username, users });

            // If room is empty, delete it
            if (room.users.length === 0) {
              rooms.delete(roomCode);
              console.log(`Room ${roomCode} deleted (empty)`);
            }
          }
        }
      } catch (error) {
        console.error('Error handling disconnect:', error);
      }
    });
  });

  return io;
}

module.exports = setupSocket; 