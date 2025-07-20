const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const history = require('connect-history-api-fallback');
const crypto = require('crypto');
const requestIp = require('request-ip');

const app = express();
const server = http.createServer(app);

// Middleware para obtener IP
app.use(requestIp.mw());

// Middleware para solucionar problema de rutas
app.use(history());

// Configuración de CORS para Socket.IO
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Configuración de la base de datos
const db = new sqlite3.Database('./chat.db');

// Crear tablas si no existen
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      nickname TEXT NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      banned BOOLEAN NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      room TEXT NOT NULL,
      sender_id TEXT NOT NULL,
      text TEXT NOT NULL,
      banned BOOLEAN NOT NULL DEFAULT 0,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(sender_id) REFERENCES users(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token TEXT NOT NULL UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS banned_ips (
      id TEXT PRIMARY KEY,
      ip TEXT NOT NULL,
      reason TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS reported_messages (
      id TEXT PRIMARY KEY,
      message_id TEXT NOT NULL,
      reporter_id TEXT NOT NULL,
      reason TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(message_id) REFERENCES messages(id),
      FOREIGN KEY(reporter_id) REFERENCES users(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS moderation_log (
      id TEXT PRIMARY KEY,
      moderator_id TEXT NOT NULL,
      action_type TEXT NOT NULL,
      target TEXT NOT NULL,
      reason TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(moderator_id) REFERENCES users(id)
    )
  `);
  
  // Nueva tabla para tokens SSO de administradores
  db.run(`
    CREATE TABLE IF NOT EXISTS admin_sso_tokens (
      id TEXT PRIMARY KEY,
      token TEXT NOT NULL UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME
    )
  `);
});

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Usuarios en línea
let onlineUsers = [];

// Función para generar ID único
function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

// Función para generar token de sesión
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Función para obtener un usuario por nombre de usuario
function getUserByUsername(username, callback) {
  db.get('SELECT * FROM users WHERE username = ?', [username], callback);
}

// Función para crear un nuevo usuario
function createUser(nickname, username, password, callback) {
  const userId = generateId();
  
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return callback(err);
    
    db.run(
      'INSERT INTO users (id, nickname, username, password) VALUES (?, ?, ?, ?)',
      [userId, nickname, username, hash],
      function(err) {
        if (err) return callback(err);
        callback(null, {
          id: userId,
          nickname,
          username,
          role: 'user' // Rol por defecto
        });
      }
    );
  });
}

// Función para crear una sesión
function createSession(userId, callback) {
  const sessionId = generateId();
  const token = generateToken();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 días
  
  db.run(
    'INSERT INTO sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)',
    [sessionId, userId, token, expiresAt.toISOString()],
    function(err) {
      if (err) return callback(err);
      callback(null, token);
    }
  );
}

// Función para validar una sesión
function validateSession(token, callback) {
  db.get(`
    SELECT s.user_id, u.nickname, u.username, u.role 
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ? AND s.expires_at > datetime('now') AND u.banned = 0
  `, [token], (err, row) => {
    if (err || !row) {
      return callback({ valid: false });
    }
    
    callback({ 
      valid: true,
      user: {
        id: row.user_id,
        nickname: row.nickname,
        username: row.username,
        role: row.role
      }
    });
  });
}

// Función para eliminar una sesión
function deleteSession(token, callback) {
  db.run('DELETE FROM sessions WHERE token = ?', [token], callback);
}

// Función para guardar un mensaje
function saveMessage(message, callback) {
  const messageId = generateId();
  
  db.run(
    'INSERT INTO messages (id, room, sender_id, text, timestamp) VALUES (?, ?, ?, ?, ?)',
    [messageId, message.room, message.senderId, message.text, new Date(message.timestamp)],
    function(err) {
      if (err) return callback(err);
      callback(null, {
        ...message,
        id: messageId
      });
    }
  );
}

// Función para obtener los últimos mensajes de una sala
function getRoomMessages(room, limit = 100, callback) {
  db.all(
    `SELECT m.id, m.room, m.sender_id, m.text, m.banned, m.timestamp, u.nickname as sender 
     FROM messages m
     JOIN users u ON m.sender_id = u.id
     WHERE room = ?
     ORDER BY timestamp ASC
     LIMIT ?`,
    [room, limit],
    callback
  );
}

// Función para obtener datos para el panel de administración
function getAdminData(callback) {
  db.serialize(() => {
    const data = {};
    
    db.all('SELECT id, nickname, username, role, banned FROM users', [], (err, users) => {
      if (err) return callback(err);
      data.users = users;
      
      db.all(`
        SELECT m.id, m.text, m.timestamp, u.nickname as sender 
        FROM reported_messages r
        JOIN messages m ON r.message_id = m.id
        JOIN users u ON m.sender_id = u.id
      `, [], (err, reportedMessages) => {
        if (err) return callback(err);
        data.reportedMessages = reportedMessages;
        
        db.all('SELECT ip, reason, timestamp FROM banned_ips', [], (err, bannedIps) => {
          if (err) return callback(err);
          data.bannedIps = bannedIps;
          
          db.all(`
            SELECT u.nickname as moderator, m.action_type, m.target, m.reason, m.timestamp 
            FROM moderation_log m
            JOIN users u ON m.moderator_id = u.id
            ORDER BY m.timestamp DESC
            LIMIT 50
          `, [], (err, moderationLog) => {
            if (err) return callback(err);
            data.moderationLog = moderationLog;
            
            // Obtener tokens SSO
            db.all('SELECT token, created_at FROM admin_sso_tokens', [], (err, ssoTokens) => {
              if (!err) data.ssoTokens = ssoTokens;
              callback(null, data);
            });
          });
        });
      });
    });
  });
}

// Función para registrar acción de moderación
function logModerationAction(moderatorId, actionType, target, reason) {
  const logId = generateId();
  
  db.run(
    'INSERT INTO moderation_log (id, moderator_id, action_type, target, reason) VALUES (?, ?, ?, ?, ?)',
    [logId, moderatorId, actionType, target, reason],
    (err) => {
      if (err) console.error('Error al registrar acción de moderación:', err);
    }
  );
}

// Función para verificar token SSO de administrador
function verifyAdminToken(token, callback) {
  db.get('SELECT * FROM admin_sso_tokens WHERE token = ?', [token], (err, row) => {
    if (err || !row) {
      return callback(false);
    }
    callback(true);
  });
}

// Función para crear token SSO de administrador
function createAdminToken(callback) {
  const tokenId = generateId();
  const token = generateToken();
  
  db.run(
    'INSERT INTO admin_sso_tokens (id, token) VALUES (?, ?)',
    [tokenId, token],
    function(err) {
      if (err) return callback(null);
      callback(token);
    }
  );
}

// Manejar conexiones de Socket.io
io.on('connection', (socket) => {
  console.log('Nuevo usuario conectado:', socket.id);
  
  // Obtener IP del cliente
  const clientIp = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
  
  // Verificar si la IP está baneada
  db.get('SELECT * FROM banned_ips WHERE ip = ?', [clientIp], (err, bannedIp) => {
    if (err) return console.error('Error al verificar IP baneada:', err);
    
    if (bannedIp) {
      socket.emit('user:banned', { 
        reason: `Tu IP ha sido baneada: ${bannedIp.reason}` 
      });
      socket.disconnect();
      return;
    }
  });
  
  // Función auxiliar para manejar callbacks
  const safeCallback = (callback, response) => {
    if (typeof callback === 'function') {
      callback(response);
    }
  };

  // Manejar registro de usuario
  socket.on('register', (data, callback) => {
    const { nickname, username, password } = data;
    
    // Validar datos
    if (!nickname || !username || !password) {
      return safeCallback(callback, { success: false, message: 'Todos los campos son obligatorios' });
    }
    
    // Verificar si el usuario ya existe
    getUserByUsername(username, (err, user) => {
      if (err) {
        return safeCallback(callback, { success: false, message: 'Error en el servidor' });
      }
      
      if (user) {
        return safeCallback(callback, { success: false, message: 'El usuario ya existe' });
      }
      
      // Crear nuevo usuario
      createUser(nickname, username, password, (err, user) => {
        if (err) {
          return safeCallback(callback, { success: false, message: 'Error al crear el usuario' });
        }
        
        // Crear sesión
        createSession(user.id, (err, token) => {
          if (err) {
            return safeCallback(callback, { success: false, message: 'Error al crear la sesión' });
          }
          
          safeCallback(callback, { 
            success: true, 
            user,
            token
          });
        });
      });
    });
  });
  
  // Manejar inicio de sesión
  socket.on('login', (data, callback) => {
    const { username, password, adminToken } = data;
    
    // Validar datos
    if (!username || !password) {
      return safeCallback(callback, { success: false, message: 'Usuario y contraseña son obligatorios' });
    }
    
    // Buscar usuario
    getUserByUsername(username, (err, user) => {
      if (err || !user) {
        return safeCallback(callback, { success: false, message: 'Credenciales inválidas' });
      }
      
      if (user.banned) {
        return safeCallback(callback, { success: false, message: 'Tu cuenta ha sido baneada' });
      }
      
      // Verificar contraseña
      bcrypt.compare(password, user.password, (err, result) => {
        if (err || !result) {
          return safeCallback(callback, { success: false, message: 'Credenciales inválidas' });
        }
        
        // Verificar token SSO de administrador si se proporciona
        if (adminToken) {
          verifyAdminToken(adminToken, (isValid) => {
            if (!isValid) {
              return safeCallback(callback, { 
                success: false, 
                message: 'Token de administrador inválido' 
              });
            }
            
            // Convertir usuario en admin
            db.run('UPDATE users SET role = "admin" WHERE id = ?', [user.id], (err) => {
              if (err) {
                console.error('Error al actualizar rol:', err);
                return safeCallback(callback, { 
                  success: false, 
                  message: 'Error al asignar rol de administrador' 
                });
              }
              
              // Actualizar objeto usuario
              user.role = 'admin';
              completeLogin(user);
            });
          });
        } else {
          completeLogin(user);
        }
      });
    });
    
    function completeLogin(user) {
      // Crear sesión
      createSession(user.id, (err, token) => {
        if (err) {
          return safeCallback(callback, { success: false, message: 'Error al crear la sesión' });
        }

        const userData = {
          id: user.id,
          nickname: user.nickname,
          username: user.username,
          role: user.role
        };

        safeCallback(callback, { 
          success: true, 
          user: userData,
          token
        });
      });
    }
  });
  
  // Validar sesión
  socket.on('validateSession', (token, callback) => {
    validateSession(token, (result) => {
      safeCallback(callback, result);
    });
  });
  
  // Unirse a una sala
  socket.on('join', (data) => {
    const { user, room } = data;
    
    // Guardar referencia del usuario
    socket.user = user;
    socket.room = room;
    
    // Agregar usuario a la lista de usuarios en línea
    onlineUsers = onlineUsers.filter(u => u.id !== user.id);
    onlineUsers.push({ ...user, socketId: socket.id, room });
    
    // Unir al usuario a la sala
    socket.join(room);
    
    // Actualizar lista de usuarios en línea
    io.emit('updateUsers', onlineUsers);
    
    // Notificar a la sala
    io.to(room).emit('systemMessage', {
      id: `system-${Date.now()}`,
      text: `${user.nickname} se ha unido al chat`,
      sender: 'Sistema',
      senderId: 'system',
      timestamp: Date.now(),
      room
    });
    
    // Enviar mensajes históricos
    getRoomMessages(room, 100, (err, messages) => {
      if (!err) {
        socket.emit('initialData', {
          room,
          messages: messages
        });
      }
    });
  });
  
  // Cambiar de sala
  socket.on('changeRoom', (data) => {
    const { user, newRoom } = data;
    
    // Verificar que el usuario está autenticado
    if (!socket.user || socket.user.id !== user.id) {
      socket.emit('authError', 'No autorizado');
      return;
    }
    
    // Salir de la sala anterior
    socket.leave(socket.room);
    
    // Actualizar usuario en línea
    onlineUsers = onlineUsers.map(u => 
      u.id === user.id ? { ...u, room: newRoom } : u
    );
    
    // Unirse a la nueva sala
    socket.join(newRoom);
    socket.room = newRoom;
    
    // Actualizar lista de usuarios en línea
    io.emit('updateUsers', onlineUsers);
    
    // Notificar cambio de sala
    io.to(newRoom).emit('systemMessage', {
      id: `system-${Date.now()}`,
      text: `${user.nickname} se ha unido al chat`,
      sender: 'Sistema',
      senderId: 'system',
      timestamp: Date.now(),
      room: newRoom
    });
    
    // Enviar mensajes históricos de la nueva sala
    getRoomMessages(newRoom, 100, (err, messages) => {
      if (!err) {
        socket.emit('initialData', {
          room: newRoom,
          messages: messages
        });
      }
    });
  });
  
  // Manejar mensajes
  socket.on('message', (message) => {
    // Verificar que el usuario está autenticado
    if (!socket.user) {
      socket.emit('authError', 'Debes iniciar sesión para enviar mensajes');
      return;
    }
    
    // Validar mensaje
    if (!message.text || !message.room) {
      return;
    }
    
    // Asignar remitente
    message.senderId = socket.user.id;
    message.sender = socket.user.nickname;
    
    // Guardar mensaje en la base de datos
    saveMessage(message, (err, savedMessage) => {
      if (err) {
        console.error('Error al guardar mensaje:', err);
        return;
      }
      
      // Enviar mensaje a todos en la sala
      io.to(message.room).emit('message', savedMessage);
    });
  });
  
  // Cerrar sesión
  socket.on('logout', (data, callback) => {
    const { userId } = data;
    
    // Función para manejar respuesta segura
    const respond = (response) => {
      safeCallback(callback, response);
    };

    if (!socket.user || socket.user.id !== userId) {
      return respond({ 
        success: false, 
        message: 'No autorizado' 
      });
    }

    // Eliminar de usuarios en línea
    onlineUsers = onlineUsers.filter(u => u.id !== userId);
    
    // Actualizar lista de usuarios
    io.emit('updateUsers', onlineUsers);
    
    // Notificar desconexión
    if (socket.room) {
      io.to(socket.room).emit('systemMessage', {
        id: `system-${Date.now()}`,
        text: `${socket.user.nickname} ha abandonado el chat`,
        sender: 'Sistema',
        senderId: 'system',
        timestamp: Date.now(),
        room: socket.room
      });
    }
    
    respond({ success: true });
  });
  
  // ===== ADMIN FUNCTIONS =====
  
  // Obtener datos para el panel de administración
  socket.on('admin:getData', (callback) => {
    if (!socket.user || socket.user.role !== 'admin') {
      return safeCallback(callback, { error: 'No autorizado' });
    }
    
    getAdminData((err, data) => {
      if (err) {
        console.error('Error al obtener datos de administración:', err);
        return safeCallback(callback, { error: 'Error en el servidor' });
      }
      
      safeCallback(callback, data);
    });
  });
  
  // Banear usuario
  socket.on('admin:banUser', (data, callback) => {
    if (!socket.user || socket.user.role !== 'admin') {
      return safeCallback(callback, { error: 'No autorizado' });
    }
    
    const { userId, reason } = data;
    
    db.run(
      'UPDATE users SET banned = 1 WHERE id = ?',
      [userId],
      function(err) {
        if (err) {
          console.error('Error al banear usuario:', err);
          return safeCallback(callback, { error: 'Error en el servidor' });
        }
        
        // Registrar acción
        logModerationAction(socket.user.id, 'ban_user', userId, reason);
        
        // Notificar al usuario si está conectado
        const userSocket = onlineUsers.find(u => u.id === userId);
        if (userSocket) {
          io.to(userSocket.socketId).emit('user:banned', { reason });
        }
        
        // Actualizar lista de usuarios en línea
        onlineUsers = onlineUsers.filter(u => u.id !== userId);
        io.emit('updateUsers', onlineUsers);
        
        // Notificar al admin
        safeCallback(callback, { success: true });
      }
    );
  });
  
  // Desbanear usuario
  socket.on('admin:unbanUser', (data, callback) => {
    if (!socket.user || socket.user.role !== 'admin') {
      return safeCallback(callback, { error: 'No autorizado' });
    }
    
    const { userId } = data;
    
    db.run(
      'UPDATE users SET banned = 0 WHERE id = ?',
      [userId],
      function(err) {
        if (err) {
          console.error('Error al desbanear usuario:', err);
          return safeCallback(callback, { error: 'Error en el servidor' });
        }
        
        // Registrar acción
        logModerationAction(socket.user.id, 'unban_user', userId, '');
        
        // Notificar al admin
        safeCallback(callback, { success: true });
      }
    );
  });
  
  // Banear IP
  socket.on('admin:banIp', (data, callback) => {
    if (!socket.user || socket.user.role !== 'admin') {
      return safeCallback(callback, { error: 'No autorizado' });
    }
    
    const { ip, reason } = data;
    const banId = generateId();
    
    db.run(
      'INSERT INTO banned_ips (id, ip, reason) VALUES (?, ?, ?)',
      [banId, ip, reason],
      function(err) {
        if (err) {
          console.error('Error al banear IP:', err);
          return safeCallback(callback, { error: 'Error en el servidor' });
        }
        
        // Registrar acción
        logModerationAction(socket.user.id, 'ban_ip', ip, reason);
        
        // Desconectar usuarios con esa IP
        io.sockets.sockets.forEach(sock => {
          const sockIp = sock.handshake.headers['x-forwarded-for'] || sock.handshake.address;
          if (sockIp === ip) {
            sock.emit('user:banned', { reason: `Tu IP ha sido baneada: ${reason}` });
            sock.disconnect();
          }
        });
        
        // Notificar al admin
        safeCallback(callback, { success: true });
      }
    );
  });
  
  // Desbanear IP
  socket.on('admin:unbanIp', (data, callback) => {
    if (!socket.user || socket.user.role !== 'admin') {
      return safeCallback(callback, { error: 'No autorizado' });
    }
    
    const { ip } = data;
    
    db.run(
      'DELETE FROM banned_ips WHERE ip = ?',
      [ip],
      function(err) {
        if (err) {
          console.error('Error al desbanear IP:', err);
          return safeCallback(callback, { error: 'Error en el servidor' });
        }
        
        // Registrar acción
        logModerationAction(socket.user.id, 'unban_ip', ip, '');
        
        // Notificar al admin
        safeCallback(callback, { success: true });
      }
    );
  });
  
  // Eliminar mensaje
  socket.on('admin:deleteMessage', (data, callback) => {
    if (!socket.user || socket.user.role !== 'admin') {
      return safeCallback(callback, { error: 'No autorizado' });
    }
    
    const { messageId } = data;
    
    db.run(
      'UPDATE messages SET banned = 1 WHERE id = ?',
      [messageId],
      function(err) {
        if (err) {
          console.error('Error al eliminar mensaje:', err);
          return safeCallback(callback, { error: 'Error en el servidor' });
        }
        
        // Registrar acción
        logModerationAction(socket.user.id, 'delete_message', messageId, '');
        
        // Notificar a todos que el mensaje fue eliminado
        io.emit('message:deleted', { messageId });
        
        // Notificar al admin
        safeCallback(callback, { success: true });
      }
    );
  });
  
  // Descartar reporte
  socket.on('admin:dismissReport', (data, callback) => {
    if (!socket.user || socket.user.role !== 'admin') {
      return safeCallback(callback, { error: 'No autorizado' });
    }
    
    const { messageId } = data;
    
    db.run(
      'DELETE FROM reported_messages WHERE message_id = ?',
      [messageId],
      function(err) {
        if (err) {
          console.error('Error al descartar reporte:', err);
          return safeCallback(callback, { error: 'Error en el servidor' });
        }
        
        // Registrar acción
        logModerationAction(socket.user.id, 'dismiss_report', messageId, '');
        
        // Notificar al admin
        safeCallback(callback, { success: true });
      }
    );
  });
  
  // Generar token SSO de administrador
  socket.on('admin:generateToken', (data, callback) => {
    if (!socket.user || socket.user.role !== 'admin') {
      return safeCallback(callback, { error: 'No autorizado' });
    }
    
    createAdminToken((token) => {
      if (!token) {
        return safeCallback(callback, { error: 'Error al generar token' });
      }
      
      safeCallback(callback, { success: true, token });
    });
  });
  
  // Desconexión
  socket.on('disconnect', () => {
    if (socket.user) {
      // Eliminar de usuarios en línea
      onlineUsers = onlineUsers.filter(u => u.socketId !== socket.id);
      
      // Notificar desconexión
      if (socket.room) {
        io.to(socket.room).emit('systemMessage', {
          id: `system-${Date.now()}`,
          text: `${socket.user.nickname} ha abandonado el chat`,
          sender: 'Sistema',
          senderId: 'system',
          timestamp: Date.now(),
          room: socket.room
        });
      }
      
      // Actualizar lista de usuarios
      io.emit('updateUsers', onlineUsers);
    }
    console.log('Usuario desconectado:', socket.id);
  });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
