import { io } from 'socket.io-client';

const SOCKET_URL = import.meta.env.VITE_API_URL || 'http://localhost:4000';

let socket = null;

export function getSocket() {
  if (!socket) {
    socket = io(SOCKET_URL, { autoConnect: false });
    // Re-join admins room on EVERY (re)connect — fixes the timing bug
    socket.on('connect', () => {
      socket.emit('join:admins');
      console.log('[socket] Connected & joined admins room:', socket.id);
    });
    socket.on('disconnect', (reason) => {
      console.log('[socket] Disconnected:', reason);
    });
  }
  return socket;
}

export function connectSocket() {
  const s = getSocket();
  if (!s.connected) s.connect();
  return s;
}

export function disconnectSocket() {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
}
