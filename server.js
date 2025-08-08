const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const history = require('connect-history-api-fallback');
const crypto = require('crypto');
const requestIp = require('request-ip');
const multer = require('multer');
const fs = require('fs');
const sharp = require('sharp');
const { v4: uuidv4 } = require('uuid');
const sanitizeHtml = require('sanitize-html');

// ===== MEJORAS AVANZADAS Y ULTRA AVANZADAS =====

// Configuración de entorno
require('dotenv').config();

// Middleware de seguridad y rendimiento
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const cors = require('cors');

// Cache y optimización
const NodeCache = require('node-cache');
const LRU = require('lru-cache');

// Monitoreo y logging
const winston = require('winston');
const cluster = require('cluster');
const os = require('os');

// Seguridad avanzada
const jwt = require('jsonwebtoken');
const validator = require('validator');

// Utilidades avanzadas
const moment = require('moment');
const lodash = require('lodash');
const axios = require('axios');
const cron = require('node-cron');

// ===== CONFIGURACIÓN AVANZADA DE LOGGING =====
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'chat-app' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Crear directorio de logs si no existe
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// ===== CONFIGURACIÓN DE CACHE AVANZADO =====
const messageCache = new LRU({
  max: 1000, // Máximo 1000 mensajes en cache
  ttl: 1000 * 60 * 5, // 5 minutos
  updateAgeOnGet: true
});

const userCache = new NodeCache({
  stdTTL: 300, // 5 minutos
  checkperiod: 60 // Revisar cada minuto
});

const sessionCache = new NodeCache({
  stdTTL: 3600, // 1 hora
  checkperiod: 300 // Revisar cada 5 minutos
});

// ===== CONFIGURACIÓN DE CACHE LOCAL =====
// En Render, usamos cache local en lugar de Redis para evitar problemas de conectividad
logger.info('Usando cache local para optimización');

// ===== CONFIGURACIÓN DE CLUSTER =====
// En Render, usar servidor único para evitar problemas de conectividad
const useClustering = false; // Deshabilitado para Render
const isMaster = true; // Siempre master en Render

// Código del servidor (Render usa servidor único)
const app = express();
const server = http.createServer(app);

// Inicialización del servidor

// Middleware para obtener IP
app.use(requestIp.mw());
  
// ===== MIDDLEWARE DE SEGURIDAD AVANZADO =====
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "wss:", "ws:"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Rate limiting avanzado
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Máximo 100 requests por IP
  message: {
    error: 'Demasiadas solicitudes desde esta IP',
    retryAfter: '15 minutos'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // No limitar para admins
    return req.headers.authorization && req.headers.authorization.includes('admin');
  }
});

app.use(limiter);

// Rate limiting específico para login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // Máximo 5 intentos de login
  message: {
    error: 'Demasiados intentos de login',
    retryAfter: '15 minutos'
  }
});

// Rate limiting para uploads
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 10, // Máximo 10 uploads por hora
  message: {
    error: 'Demasiados archivos subidos',
    retryAfter: '1 hora'
  }
});

// Middleware anti-spam para mensajes
const messageLimiter = rateLimit({
  windowMs: 10 * 1000, // 10 segundos
  max: 5, // Máximo 5 mensajes cada 10 segundos
  message: { error: 'Estás enviando mensajes demasiado rápido.' }
});
app.use('/mensaje', messageLimiter);

// Compresión
app.use(compression());

// CORS mejorado
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Logging de requests
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.info(message.trim())
  }
}));

// Middleware para solucionar problema de rutas
app.use(history());

// ===== CONFIGURACIÓN AVANZADA DE SOCKET.IO =====
const io = socketIo(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : "*",
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000,
  upgradeTimeout: 10000,
  maxHttpBufferSize: 1e8, // 100MB
  allowRequest: (req, callback) => {
    // Validación de origen para WebSocket
    const origin = req.headers.origin;
    if (!origin || process.env.ALLOWED_ORIGINS === '*') {
      return callback(null, true);
    }
    
    const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['*'];
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    return callback(null, false);
  }
});

// Socket.IO configurado para usar cache local
logger.info('Socket.IO configurado con cache local');

// Middleware de autenticación para Socket.IO
io.use((socket, next) => {
  const token = socket.handshake.auth.token || socket.handshake.headers.authorization;
  
  if (!token) {
    return next(new Error('Token de autenticación requerido'));
  }
  
  validateSession(token, (err, user) => {
    if (err || !user) {
      return next(new Error('Token inválido'));
    }
    
    socket.user = user;
    socket.userId = user.id;
    next();
  });
});

// Configuración de la base de datos
const DB_PATH = process.env.DB_PATH || './chat.db';
const db = new sqlite3.Database(DB_PATH);

// ===== CONFIGURACIÓN AVANZADA DE SEGURIDAD =====
const DEFAULT_ADMIN_TOKEN = process.env.ADMIN_TOKEN || "ANIMIX_ADMIsN_SECRET_2024";
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Configuración de seguridad
const SECURITY_CONFIG = {
  passwordMinLength: 8,
  passwordMaxLength: 128,
  usernameMinLength: 3,
  usernameMaxLength: 20,
  nicknameMinLength: 2,
  nicknameMaxLength: 30,
  maxLoginAttempts: 5,
  lockoutDuration: 15 * 60 * 1000, // 15 minutos
  sessionTimeout: 24 * 60 * 60 * 1000, // 24 horas
  maxConcurrentSessions: 3,
  fileScanEnabled: process.env.FILE_SCAN_ENABLED === 'true',
  antivirusApiKey: process.env.ANTIVIRUS_API_KEY,
  recaptchaEnabled: process.env.RECAPTCHA_ENABLED === 'true',
  recaptchaSecret: process.env.RECAPTCHA_SECRET
};

// ===== FUNCIONES AVANZADAS DE SEGURIDAD =====

// Validación avanzada de contraseñas
function validatePassword(password) {
      const errors = [];
  
  if (password.length < SECURITY_CONFIG.passwordMinLength) {
    errors.push(`La contraseña debe tener al menos ${SECURITY_CONFIG.passwordMinLength} caracteres`);
  }
  
  if (password.length > SECURITY_CONFIG.passwordMaxLength) {
    errors.push(`La contraseña no puede exceder ${SECURITY_CONFIG.passwordMaxLength} caracteres`);
  }
  
  if (!/(?=.*[a-z])/.test(password)) {
    errors.push('La contraseña debe contener al menos una letra minúscula');
  }
  
  if (!/(?=.*[A-Z])/.test(password)) {
    errors.push('La contraseña debe contener al menos una letra mayúscula');
  }
  
  if (!/(?=.*\d)/.test(password)) {
    errors.push('La contraseña debe contener al menos un número');
  }
  
  if (!/(?=.*[@$!%*?&])/.test(password)) {
    errors.push('La contraseña debe contener al menos un carácter especial (@$!%*?&)');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

// Validación avanzada de nombres de usuario
function validateUsername(username) {
      const errors = [];
  
  if (username.length < SECURITY_CONFIG.usernameMinLength) {
    errors.push(`El nombre de usuario debe tener al menos ${SECURITY_CONFIG.usernameMinLength} caracteres`);
  }
  
  if (username.length > SECURITY_CONFIG.usernameMaxLength) {
    errors.push(`El nombre de usuario no puede exceder ${SECURITY_CONFIG.usernameMaxLength} caracteres`);
  }
  
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    errors.push('El nombre de usuario solo puede contener letras, números y guiones bajos');
  }
  
  if (!validator.isAlphanumeric(username.replace(/_/g, ''))) {
    errors.push('El nombre de usuario debe contener al menos una letra o número');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

// Validación de nickname
function validateNickname(nickname) {
      const errors = [];
  
  if (nickname.length < SECURITY_CONFIG.nicknameMinLength) {
    errors.push(`El nickname debe tener al menos ${SECURITY_CONFIG.nicknameMinLength} caracteres`);
  }
  
  if (nickname.length > SECURITY_CONFIG.nicknameMaxLength) {
    errors.push(`El nickname no puede exceder ${SECURITY_CONFIG.nicknameMaxLength} caracteres`);
  }
  
  if (!validator.isLength(nickname, { min: SECURITY_CONFIG.nicknameMinLength, max: SECURITY_CONFIG.nicknameMaxLength })) {
    errors.push('El nickname tiene un formato inválido');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

// Escaneo de archivos con antivirus (si está configurado)
async function scanFile(filePath) {
      if (!SECURITY_CONFIG.fileScanEnabled || !SECURITY_CONFIG.antivirusApiKey) {
    return { isClean: true };
  }
  
  try {
    const formData = new FormData();
    formData.append('file', fs.createReadStream(filePath));
    
    const response = await axios.post('https://api.virustotal.com/v3/files', formData, {
      headers: {
        'x-apikey': SECURITY_CONFIG.antivirusApiKey,
        ...formData.getHeaders()
      }
    });
    
    const result = response.data;
    return {
      isClean: result.data.attributes.last_analysis_stats.malicious === 0,
      scanId: result.data.id,
      stats: result.data.attributes.last_analysis_stats
    };
  } catch (error) {
    logger.error('Error escaneando archivo:', error);
    return { isClean: true, error: 'Error en escaneo' };
  }
}

// Verificación de reCAPTCHA
async function verifyRecaptcha(token, ip) {
      if (!SECURITY_CONFIG.recaptchaEnabled) {
    return { success: true };
  }
  
  try {
    const response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
      params: {
        secret: SECURITY_CONFIG.recaptchaSecret,
        response: token,
        remoteip: ip
      }
    });
    
    return {
      success: response.data.success,
      score: response.data.score,
      action: response.data.action
    };
  } catch (error) {
    logger.error('Error verificando reCAPTCHA:', error);
    return { success: false, error: 'Error en verificación' };
  }
}

// Control de intentos de login
const loginAttempts = new Map();

function checkLoginAttempts(ip) {
      const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  const now = Date.now();
  
  if (now - attempts.lastAttempt > SECURITY_CONFIG.lockoutDuration) {
    attempts.count = 0;
  }
  
  return attempts;
}

function recordLoginAttempt(ip, success) {
      const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  
  if (success) {
    attempts.count = 0;
  } else {
    attempts.count++;
  }
  
  attempts.lastAttempt = Date.now();
  loginAttempts.set(ip, attempts);
  
  // Limpiar intentos antiguos
  setTimeout(() => {
    loginAttempts.delete(ip);
  }, SECURITY_CONFIG.lockoutDuration);
}

// Control de intentos de admin token
const adminTokenAttempts = new Map();

function checkAdminTokenAttempts(ip) {
  const attempts = adminTokenAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  const now = Date.now();
  
  // Reset después de 15 minutos
  if (now - attempts.lastAttempt > 15 * 60 * 1000) {
    attempts.count = 0;
  }
  
  return attempts.count;
}

function recordAdminTokenAttempt(ip, success) {
  const attempts = adminTokenAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  
  if (success) {
    attempts.count = 0;
  } else {
    attempts.count++;
  }
  
  attempts.lastAttempt = Date.now();
  adminTokenAttempts.set(ip, attempts);
  
  // Banear IP si tiene demasiados intentos fallidos (10 o más)
  if (!success && attempts.count >= 10) {
    console.warn(`IP baneada por intentos excesivos de admin token: ${ip}`);
    db.run('INSERT OR REPLACE INTO banned_ips (ip, reason, banned_at) VALUES (?, ?, ?)', 
      [ip, 'Demasiados intentos de acceso admin', new Date().toISOString()], 
      (err) => {
        if (err) {
          console.error('Error al banear IP:', err);
        } else {
          logAuditAction(null, 'IP_BANNED', {
            ip: ip,
            reason: 'Demasiados intentos de acceso admin',
            attempts: attempts.count
          });
        }
      }
    );
  }
  
  // Limpiar intentos antiguos después de 15 minutos
  setTimeout(() => {
    adminTokenAttempts.delete(ip);
  }, 15 * 60 * 1000);
}

// Configuración de archivos
const UPLOAD_DIR = process.env.UPLOAD_DIR || './public/uploads';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024; // 10MB por defecto
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
const ALLOWED_AUDIO_TYPES = ['audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/m4a'];
const ALLOWED_DOCUMENT_TYPES = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];
const ALLOWED_VIDEO_TYPES = ['video/mp4', 'video/webm', 'video/ogg', 'video/avi'];

// Crear directorios de uploads si no existen
const uploadDirs = [
  `${UPLOAD_DIR}/images`,
  `${UPLOAD_DIR}/audios`,
  `${UPLOAD_DIR}/documents`,
  `${UPLOAD_DIR}/videos`,
  `${UPLOAD_DIR}/others`
];

uploadDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Configuración de multer para subida de archivos
const storage = multer.diskStorage({
      destination: function (req, file, cb) {
    let uploadPath = `${UPLOAD_DIR}/others`;
    
    if (ALLOWED_IMAGE_TYPES.includes(file.mimetype)) {
      uploadPath = `${UPLOAD_DIR}/images`;
    } else if (ALLOWED_AUDIO_TYPES.includes(file.mimetype)) {
      uploadPath = `${UPLOAD_DIR}/audios`;
    } else if (ALLOWED_DOCUMENT_TYPES.includes(file.mimetype)) {
      uploadPath = `${UPLOAD_DIR}/documents`;
    } else if (ALLOWED_VIDEO_TYPES.includes(file.mimetype)) {
      uploadPath = `${UPLOAD_DIR}/videos`;
    }
    
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    // Generar nombre único para el archivo
    const uniqueName = `${uuidv4()}-${Date.now()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
      const allowedTypes = [...ALLOWED_IMAGE_TYPES, ...ALLOWED_AUDIO_TYPES, ...ALLOWED_DOCUMENT_TYPES, ...ALLOWED_VIDEO_TYPES];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Tipo de archivo no permitido'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 5 // Máximo 5 archivos por subida
  }
});

// ===== CONFIGURACIÓN AVANZADA DE BASE DE DATOS =====

// Backup automático de la base de datos usando fs.copyFileSync
function backupDatabase() {
      // En Render, el sistema de archivos es efímero, no hacer backups automáticos
  if (process.env.RENDER) {
    logger.info('Backup automático deshabilitado en Render (sistema de archivos efímero)');
    return;
  }
  const dbPath = path.join(__dirname, 'chat.db');
  const backupDir = path.join(__dirname, 'backups');
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
  }
  const backupPath = path.join(backupDir, `chat_backup_${moment().format('YYYY-MM-DD_HH-mm-ss')}.db`);
  try {
    fs.copyFileSync(dbPath, backupPath);
    logger.info(`Backup creado: ${backupPath}`);
    // Limpiar backups antiguos (mantener solo los últimos 7 días)
    cleanupOldBackups();
  } catch (err) {
    logger.error('Error en backup de base de datos:', err);
  }
}

// Limpiar backups antiguos
function cleanupOldBackups() {
      const backupDir = './backups';
  if (!fs.existsSync(backupDir)) return;
  
  const files = fs.readdirSync(backupDir);
  const now = moment();
  
  files.forEach(file => {
    const filePath = path.join(backupDir, file);
    const stats = fs.statSync(filePath);
    const fileAge = moment().diff(moment(stats.mtime), 'days');
    
    if (fileAge > 7) {
      fs.unlinkSync(filePath);
      logger.info(`Backup antiguo eliminado: ${file}`);
    }
  });
}

// Optimización de base de datos
function optimizeDatabase() {
      db.serialize(() => {
    db.run('VACUUM');
    db.run('ANALYZE');
    db.run('REINDEX');
    logger.info('Base de datos optimizada');
  });
}

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
    
      db.run(`
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      original_name TEXT NOT NULL,
      filename TEXT NOT NULL,
      file_path TEXT NOT NULL,
      file_type TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      mime_type TEXT NOT NULL,
      uploaded_by TEXT NOT NULL,
      room TEXT NOT NULL,
      message_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(uploaded_by) REFERENCES users(id),
      FOREIGN KEY(message_id) REFERENCES messages(id)
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
    
      // Tabla para estadísticas y métricas
  db.run(`
    CREATE TABLE IF NOT EXISTS server_stats (
      id TEXT PRIMARY KEY,
      metric_name TEXT NOT NULL,
      metric_value REAL NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
    
      // Tabla para logs de auditoría
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      action TEXT NOT NULL,
      details TEXT,
      ip_address TEXT,
      user_agent TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
    
      // Tabla para configuración del sistema
  db.run(`
    CREATE TABLE IF NOT EXISTS system_config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
    
      // Tabla para rate limiting
  db.run(`
    CREATE TABLE IF NOT EXISTS rate_limits (
      id TEXT PRIMARY KEY,
      ip_address TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      count INTEGER DEFAULT 1,
      first_request DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_request DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
    
      // Índices para optimización
  db.run('CREATE INDEX IF NOT EXISTS idx_messages_room_timestamp ON messages(room, timestamp)');
  db.run('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)');
  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_files_uploaded_by ON files(uploaded_by)');
  db.run('CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)');
  db.run('CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_endpoint ON rate_limits(ip_address, endpoint)');
    
      console.log('Base de datos inicializada con tablas avanzadas');
  
  // Insertar token predefinido al iniciar
  db.run(`
    INSERT OR IGNORE INTO admin_sso_tokens (id, token) 
    VALUES (?, ?)
  `, ['default-admin-token', DEFAULT_ADMIN_TOKEN], (err) => {
    if (err) {
      console.error('Error al insertar token predeterminado:', err);
    } else {
      console.log('Token SSO predeterminado creado');
    }
  });
});

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny', // Bloquear archivos ocultos como .env, .git, etc.
  index: false // No servir index.html automáticamente fuera de rutas explícitas
}));

// Middleware para bloquear acceso directo a archivos sensibles
app.use((req, res, next) => {
      const forbidden = [
    '/.env', '/chat.db', '/package.json', '/package-lock.json', '/render.yaml', '/README.md', '/ADVANCED_FEATURES.md', '/sds.md', '/server.js', '/render-setup.md', '/.git', '/.qodo', '/backups', '/logs'
  ];
  if (forbidden.some(f => req.path.startsWith(f))) {
    return res.status(403).send('Acceso denegado');
  }
  next();
});

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

// Función para obtener el tipo de archivo
function getFileType(mimeType) {
      if (ALLOWED_IMAGE_TYPES.includes(mimeType)) return 'image';
  if (ALLOWED_AUDIO_TYPES.includes(mimeType)) return 'audio';
  if (ALLOWED_DOCUMENT_TYPES.includes(mimeType)) return 'document';
  if (ALLOWED_VIDEO_TYPES.includes(mimeType)) return 'video';
  return 'other';
}

// Función para guardar información de archivo en la base de datos
function saveFileInfo(fileInfo, callback) {
      const fileId = generateId();
  
  db.run(`
    INSERT INTO files (id, original_name, filename, file_path, file_type, file_size, mime_type, uploaded_by, room)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    fileId,
    fileInfo.originalName,
    fileInfo.filename,
    fileInfo.filePath,
    fileInfo.fileType,
    fileInfo.fileSize,
    fileInfo.mimeType,
    fileInfo.uploadedBy,
    fileInfo.room
  ], function(err) {
    if (err) return callback(err);
    callback(null, fileId);
  });
}

// Función para procesar imagen con Sharp (optimización)
async function processImage(inputPath, outputPath) {
      try {
    await sharp(inputPath)
      .resize(1920, 1080, { 
        fit: 'inside',
        withoutEnlargement: true 
      })
      .jpeg({ quality: 85 })
      .toFile(outputPath);
    
    // Reemplazar archivo original con el optimizado
    fs.unlinkSync(inputPath);
    fs.renameSync(outputPath, inputPath);
    
    return true;
  } catch (error) {
    console.error('Error procesando imagen:', error);
    return false;
  }
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
      // Primero verificar en cache
  const cachedSession = getCachedSession(token);
  if (cachedSession) {
    return callback(null, cachedSession);
  }
  
  db.get(`
    SELECT s.user_id, u.nickname, u.username, u.role 
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ? AND s.expires_at > datetime('now') AND u.banned = 0
  `, [token], (err, row) => {
    if (err) {
      return callback(err);
    }
    
    if (!row) {
      return callback(new Error('Sesión no encontrada o expirada'));
    }
    
    const user = {
      id: row.user_id,
      nickname: row.nickname,
      username: row.username,
      role: row.role
    };
    
    // Guardar en cache
    setCachedSession(token, user);
    callback(null, user);
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
function verifyAdminToken(token, callback, clientIp = null) {
  // Validar que el token no esté vacío, null o undefined
  if (!token || typeof token !== 'string' || token.trim() === '') {
    console.warn('Intento de acceso con token vacío o inválido');
    if (clientIp) {
      logAuditAction(null, 'ADMIN_TOKEN_ATTEMPT', {
        ip: clientIp,
        token: 'EMPTY_OR_INVALID',
        success: false,
        reason: 'Token vacío o inválido'
      });
    }
    return callback(false);
  }

  // Sanitizar el token para prevenir inyección
  const sanitizedToken = token.trim();
  
  // Verificar longitud mínima del token
  if (sanitizedToken.length < 10) {
    console.warn('Intento de acceso con token demasiado corto');
    if (clientIp) {
      logAuditAction(null, 'ADMIN_TOKEN_ATTEMPT', {
        ip: clientIp,
        token: 'TOO_SHORT',
        success: false,
        reason: 'Token demasiado corto'
      });
    }
    return callback(false);
  }

  // Verificar contra el token predefinido
  if (sanitizedToken === DEFAULT_ADMIN_TOKEN) {
    console.log('Acceso admin exitoso con token predefinido');
    if (clientIp) {
      logAuditAction(null, 'ADMIN_TOKEN_ATTEMPT', {
        ip: clientIp,
        token: 'DEFAULT_TOKEN',
        success: true
      });
    }
    return callback(true);
  }
  
  // Verificar contra tokens en base de datos
  db.get('SELECT * FROM admin_sso_tokens WHERE token = ?', [sanitizedToken], (err, row) => {
    if (err) {
      console.error('Error al verificar token en base de datos:', err);
      if (clientIp) {
        logAuditAction(null, 'ADMIN_TOKEN_ATTEMPT', {
          ip: clientIp,
          token: 'DB_ERROR',
          success: false,
          reason: 'Error en base de datos'
        });
      }
      return callback(false);
    }
    
    if (!row) {
      console.warn('Intento de acceso con token inválido:', sanitizedToken.substring(0, 8) + '...');
      if (clientIp) {
        logAuditAction(null, 'ADMIN_TOKEN_ATTEMPT', {
          ip: clientIp,
          token: 'INVALID_TOKEN',
          success: false,
          reason: 'Token no encontrado en base de datos'
        });
      }
      return callback(false);
    }
    
    console.log('Acceso admin exitoso con token de base de datos');
    if (clientIp) {
      logAuditAction(null, 'ADMIN_TOKEN_ATTEMPT', {
        ip: clientIp,
        token: 'DB_TOKEN',
        success: true
      });
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
          // Verificar rate limiting para intentos de admin token
          const adminAttempts = checkAdminTokenAttempts(clientIp);
          if (adminAttempts >= 5) {
            console.warn(`Demasiados intentos de admin token desde IP: ${clientIp}`);
            logAuditAction(null, 'ADMIN_TOKEN_RATE_LIMIT', {
              ip: clientIp,
              attempts: adminAttempts
            });
            return safeCallback(callback, { 
              success: false, 
              message: 'Demasiados intentos de acceso admin. Intenta más tarde.' 
            });
          }

          // Registrar intento de admin token
          recordAdminTokenAttempt(clientIp, false);

                    // Agregar delay artificial para prevenir ataques de fuerza bruta
          setTimeout(() => {
            verifyAdminToken(adminToken, (isValid) => {
              if (!isValid) {
                return safeCallback(callback, { 
                  success: false, 
                  message: 'Token de administrador inválido' 
                });
              }
              
              // Registrar intento exitoso
              recordAdminTokenAttempt(clientIp, true);
              
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
            }, clientIp);
          }, 1000); // Delay de 1 segundo para prevenir ataques de fuerza bruta
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
          validateSession(token, (err, user) => {
      if (err || !user) {
        return safeCallback(callback, { valid: false });
      }
      safeCallback(callback, { 
        valid: true,
        user
      });
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
      
      // Sanitizar mensaje
      message.text = cleanMessage(message.text);
      
      // Asignar remitente
      message.senderId = socket.user.id;
      message.sender = socket.user.nickname;
      message.timestamp = Date.now();
      
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

    // --- Señalización WebRTC para canal de voz/video ---
    const callRooms = {};

    // Unirse a canal de llamada
    socket.on('join-call', ({ room }) => {
      socket.join('call-' + room);
      if (!callRooms[room]) callRooms[room] = [];
      callRooms[room].push(socket.id);
      // Notificar a otros usuarios en la llamada
      socket.to('call-' + room).emit('call-user', { from: socket.id });
    });

    // Salir de la llamada
    socket.on('leave-call', ({ room }) => {
      socket.leave('call-' + room);
      if (callRooms[room]) {
        callRooms[room] = callRooms[room].filter(id => id !== socket.id);
        if (callRooms[room].length === 0) delete callRooms[room];
      }
    });

    // Listo para llamada (negociación)
    socket.on('ready-for-call', ({ room }) => {
      socket.to('call-' + room).emit('call-user', { from: socket.id });
    });

    // Oferta WebRTC
    socket.on('call-offer', ({ to, offer }) => {
      io.to(to).emit('call-offer', { from: socket.id, offer });
    });

    // Respuesta WebRTC
    socket.on('call-answer', ({ to, answer }) => {
      io.to(to).emit('call-answer', { from: socket.id, answer });
    });

    // ICE candidates
    socket.on('call-ice-candidate', ({ to, candidate }) => {
      io.to(to).emit('call-ice-candidate', { from: socket.id, candidate });
    });
  });

  // Rutas HTTP para manejo de archivos
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Endpoint para subir archivos
  app.post('/upload', upload.array('file', 5), async (req, res) => {
    try {
      // Verificar que el usuario esté autenticado
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ success: false, error: 'No autorizado' });
      }

      const token = authHeader.replace('Bearer ', '');
      
      // Validar sesión
      validateSession(token, (err, user) => {
        if (err || !user) {
          return res.status(401).json({ success: false, error: 'Sesión inválida' });
        }

        if (!req.files || req.files.length === 0) {
          return res.status(400).json({ success: false, error: 'No se seleccionaron archivos' });
        }

        const uploadedFiles = [];
        let processedCount = 0;

        req.files.forEach(async (file) => {
          try {
            // Procesar imagen si es necesario
            if (ALLOWED_IMAGE_TYPES.includes(file.mimetype)) {
              const tempPath = file.path + '_temp';
              await processImage(file.path, tempPath);
            }

            // Guardar información en la base de datos
            const fileInfo = {
              originalName: file.originalname,
              filename: file.filename,
              filePath: file.path,
              fileType: getFileType(file.mimetype),
              fileSize: file.size,
              mimeType: file.mimetype,
              uploadedBy: user.id,
              room: req.body.room || 'multimedia'
            };

            saveFileInfo(fileInfo, (err, fileId) => {
              if (err) {
                console.error('Error guardando archivo en BD:', err);
                return;
              }

              const fileUrl = `/uploads/${getFileType(file.mimetype)}s/${file.filename}`;
              
              uploadedFiles.push({
                id: fileId,
                name: file.originalname,
                url: fileUrl,
                type: file.mimetype,
                size: file.size
              });

              processedCount++;
              
              // Si todos los archivos han sido procesados, enviar respuesta
              if (processedCount === req.files.length) {
                res.json({
                  success: true,
                  files: uploadedFiles,
                  message: `${uploadedFiles.length} archivo(s) subido(s) exitosamente`
                });
              }
            });

          } catch (error) {
            console.error('Error procesando archivo:', error);
            processedCount++;
            
            if (processedCount === req.files.length) {
              res.status(500).json({
                success: false,
                error: 'Error procesando archivos'
              });
            }
          }
        });

      });

    } catch (error) {
      console.error('Error en endpoint de upload:', error);
      res.status(500).json({
        success: false,
        error: 'Error interno del servidor'
      });
    }
  });

  // Endpoint para obtener información de archivo
  app.get('/file/:fileId', (req, res) => {
    const { fileId } = req.params;
    
    db.get('SELECT * FROM files WHERE id = ?', [fileId], (err, file) => {
      if (err) {
        return res.status(500).json({ success: false, error: 'Error en el servidor' });
      }
      
      if (!file) {
        return res.status(404).json({ success: false, error: 'Archivo no encontrado' });
      }
      
      res.json({
        success: true,
        file: {
          id: file.id,
          name: file.original_name,
          url: `/uploads/${file.file_type}s/${file.filename}`,
          type: file.mime_type,
          size: file.file_size,
          uploadedBy: file.uploaded_by,
          createdAt: file.created_at
        }
      });
    });
  });

  // Endpoint para eliminar archivo (solo admins)
  app.delete('/file/:fileId', (req, res) => {
    const { fileId } = req.params;
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ success: false, error: 'No autorizado' });
    }

    const token = authHeader.replace('Bearer ', '');
    
    validateSession(token, (err, user) => {
      if (err || !user || user.role !== 'admin') {
        return res.status(401).json({ success: false, error: 'No autorizado' });
      }

      db.get('SELECT * FROM files WHERE id = ?', [fileId], (err, file) => {
        if (err) {
          return res.status(500).json({ success: false, error: 'Error en el servidor' });
        }
        
        if (!file) {
          return res.status(404).json({ success: false, error: 'Archivo no encontrado' });
        }

        // Eliminar archivo físico
        fs.unlink(file.file_path, (unlinkErr) => {
          if (unlinkErr) {
            console.error('Error eliminando archivo físico:', unlinkErr);
          }

          // Eliminar registro de la base de datos
          db.run('DELETE FROM files WHERE id = ?', [fileId], (deleteErr) => {
            if (deleteErr) {
              return res.status(500).json({ success: false, error: 'Error eliminando archivo' });
            }

            // Registrar acción de moderación
            logModerationAction(user.id, 'delete_file', fileId, 'Archivo eliminado por admin');

            res.json({ success: true, message: 'Archivo eliminado exitosamente' });
          });
        });
      });
    });
  });

  // Middleware de manejo de errores para multer
  app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
      if (error.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          success: false,
          error: 'El archivo es demasiado grande. Máximo 10MB.'
        });
      }
      if (error.code === 'LIMIT_FILE_COUNT') {
        return res.status(400).json({
          success: false,
          error: 'Demasiados archivos. Máximo 5 archivos por subida.'
        });
      }
      if (error.code === 'LIMIT_UNEXPECTED_FILE') {
        return res.status(400).json({
          success: false,
          error: 'Campo de archivo inesperado.'
        });
      }
    }
    
    if (error.message === 'Tipo de archivo no permitido') {
      return res.status(400).json({
        success: false,
        error: 'Tipo de archivo no permitido.'
      });
    }
    
    console.error('Error en upload:', error);
    res.status(500).json({
      success: false,
      error: 'Error interno del servidor'
    });
  });

  // ===== FUNCIONES AVANZADAS DE CACHE Y OPTIMIZACIÓN =====

  // Cache inteligente para mensajes
  function getCachedMessages(room, limit = 100) {
    const cacheKey = `messages:${room}:${limit}`;
    let messages = messageCache.get(cacheKey);
    
    if (!messages) {
      return null;
    }
    
    return messages;
  }

  function setCachedMessages(room, limit, messages) {
    const cacheKey = `messages:${room}:${limit}`;
    messageCache.set(cacheKey, messages);
  }

  // Cache para usuarios
  function getCachedUser(userId) {
    return userCache.get(userId);
  }

  function setCachedUser(userId, userData) {
    userCache.set(userId, userData);
  }

  // Cache para sesiones
  function getCachedSession(token) {
    return sessionCache.get(token);
  }

  function setCachedSession(token, sessionData) {
    sessionCache.set(token, sessionData);
  }

  // ===== FUNCIONES DE MONITOREO Y MÉTRICAS =====

  // Registrar métricas del servidor
  function recordMetric(metricName, value) {
    const metricId = generateId();
    db.run(`
      INSERT INTO server_stats (id, metric_name, metric_value)
      VALUES (?, ?, ?)
    `, [metricId, metricName, value], (err) => {
      if (err) {
        logger.error('Error registrando métrica:', err);
      }
    });
  }

  // Obtener estadísticas del servidor
  function getServerStats(callback) {
    const stats = {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      connections: io.engine.clientsCount,
      onlineUsers: onlineUsers.length,
      cacheStats: {
        messages: messageCache.size,
        users: userCache.stats.keys,
        sessions: sessionCache.stats.keys
      }
    };
    
    callback(null, stats);
  }

  // ===== FUNCIONES DE AUDITORÍA =====

  // Registrar acción de auditoría
  function logAuditAction(userId, action, details, req) {
    const auditId = generateId();
    const ip = req ? req.ip : 'unknown';
    const userAgent = req ? req.headers['user-agent'] : 'unknown';
    
    db.run(`
      INSERT INTO audit_log (id, user_id, action, details, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [auditId, userId, action, JSON.stringify(details), ip, userAgent], (err) => {
      if (err) {
        logger.error('Error registrando auditoría:', err);
      }
    });
  }

  // ===== TAREAS PROGRAMADAS =====

  // En Render, las tareas programadas pueden no funcionar como esperado
  // Solo ejecutar si no estamos en un entorno serverless
  if (process.env.NODE_ENV === 'production' && !process.env.RENDER) {
    // Backup automático diario
    cron.schedule('0 2 * * *', () => {
      logger.info('Iniciando backup automático de base de datos...');
      backupDatabase();
    });

    // Optimización semanal de base de datos
    cron.schedule('0 3 * * 0', () => {
      logger.info('Iniciando optimización de base de datos...');
      optimizeDatabase();
    });
  }

  // Limpieza de cache cada hora (siempre activa)
  cron.schedule('0 * * * *', () => {
    messageCache.clear();
    userCache.flushAll();
    sessionCache.flushAll();
    logger.info('Cache limpiado');
  });

  // Registro de métricas cada 5 minutos (siempre activo)
  cron.schedule('*/5 * * * *', () => {
    getServerStats((err, stats) => {
      if (!err) {
        recordMetric('memory_usage', stats.memory.heapUsed);
        recordMetric('online_users', stats.onlineUsers);
        recordMetric('active_connections', stats.connections);
      }
    });
  });

  // ===== MANEJO DE ERRORES AVANZADO =====

  // Capturar errores no manejados
  process.on('uncaughtException', (error) => {
    logger.error('Error no manejado:', error);
    process.exit(1);
  });

  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Promesa rechazada no manejada:', reason);
  });

  // Manejo de señales de terminación
  process.on('SIGTERM', () => {
    logger.info('Recibida señal SIGTERM, cerrando servidor...');
    server.close(() => {
      logger.info('Servidor cerrado');
      process.exit(0);
    });
  });

  process.on('SIGINT', () => {
    logger.info('Recibida señal SIGINT, cerrando servidor...');
    server.close(() => {
      logger.info('Servidor cerrado');
      process.exit(0);
    });
  });

  // ===== ENDPOINTS AVANZADOS =====

  // Endpoint de salud del servidor
  app.get('/health', (req, res) => {
    getServerStats((err, stats) => {
      if (err) {
        return res.status(500).json({ status: 'error', error: err.message });
      }
      
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: stats.uptime,
        memory: stats.memory,
        connections: stats.connections,
        onlineUsers: stats.onlineUsers
      });
    });
  });

  // Endpoint de métricas (solo para admins)
  app.get('/metrics', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ error: 'No autorizado' });
    }
    
    const token = authHeader.replace('Bearer ', '');
    
    validateSession(token, (err, user) => {
      if (err || !user || user.role !== 'admin') {
        return res.status(401).json({ error: 'No autorizado' });
      }
      
      getServerStats((err, stats) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        
        res.json({
          server: stats,
          cache: stats.cacheStats,
          timestamp: new Date().toISOString()
        });
      });
    });
  });

  // Endpoint para logs de auditoría (solo para admins)
  app.get('/audit-logs', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ error: 'No autorizado' });
    }
    
    const token = authHeader.replace('Bearer ', '');
    
    validateSession(token, (err, user) => {
      if (err || !user || user.role !== 'admin') {
        return res.status(401).json({ error: 'No autorizado' });
      }
      
      const limit = parseInt(req.query.limit) || 100;
      const offset = parseInt(req.query.offset) || 0;
      
      db.all(`
        SELECT * FROM audit_log 
        ORDER BY timestamp DESC 
        LIMIT ? OFFSET ?
      `, [limit, offset], (err, logs) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        
        res.json({
          logs: logs.map(log => ({
            ...log,
            details: JSON.parse(log.details || '{}')
          })),
          total: logs.length
        });
      });
    });
  });

  // Sanitización de mensajes
  function cleanMessage(text) {
    return sanitizeHtml(text, {
      allowedTags: ['b', 'i', 'em', 'strong', 'a'],
      allowedAttributes: {
        'a': ['href', 'target', 'rel']
      },
      allowedSchemes: ['http', 'https'],
      transformTags: {
        'a': (tagName, attribs) => {
          return {
            tagName: 'a',
            attribs: {
              href: attribs.href,
              target: '_blank',
              rel: 'noopener noreferrer'
            }
          };
        }
      }
    });
  }

  // Sanitización de mensajes en endpoint de mensajes
  app.post('/mensaje', (req, res) => {
    let { texto } = req.body;
    texto = cleanMessage(texto);
    if (texto.length < 1 || texto.length > 500) {
      return res.status(400).json({ error: 'Mensaje inválido.' });
    }
    // ...guardar mensaje...
    res.json({ success: true, message: 'Mensaje sanitizado correctamente' });
  });

  // Iniciar servidor
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => {
    logger.info(`Servidor escuchando en http://localhost:${PORT}`);
    logger.info(`Token SSO predefinido: ${DEFAULT_ADMIN_TOKEN}`);
    logger.info(`Directorio de uploads: ${UPLOAD_DIR}`);
    logger.info(`Modo: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`Servidor único (Render optimizado)`);
    
    // Registrar métricas iniciales
    recordMetric('server_start', Date.now());
  });