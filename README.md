# 🚀 Chat App - Advanced

Aplicación de chat en tiempo real con características avanzadas, seguridad enterprise y escalabilidad.

## 🌐 Despliegue en Render

### Configuración Automática

Este proyecto está configurado para desplegarse automáticamente en Render. Solo necesitas:

1. **Conectar tu repositorio** a Render
2. **Configurar las variables de entorno** (opcional)
3. **¡Listo!** Render se encarga del resto

### Variables de Entorno (Opcionales)

Render generará automáticamente las variables de seguridad, pero puedes configurar las siguientes:

```bash
# Configuración básica
NODE_ENV=production
PORT=10000

# Seguridad (se generan automáticamente)
ADMIN_TOKEN=tu-token-admin
JWT_SECRET=tu-jwt-secret
SESSION_SECRET=tu-session-secret

# Configuración de la aplicación
LOG_LEVEL=info
ALLOWED_ORIGINS=*
RATE_LIMIT_MAX_REQUESTS=100
LOGIN_RATE_LIMIT_MAX=5
UPLOAD_RATE_LIMIT_MAX=10

# Archivos
MAX_FILE_SIZE=10485760
MAX_FILES_PER_UPLOAD=5

# Cache
CACHE_TTL_MESSAGES=300000
CACHE_TTL_USERS=300000
CACHE_TTL_SESSIONS=3600000

# Monitoreo
METRICS_ENABLED=true
AUDIT_LOG_ENABLED=true
COMPRESSION_ENABLED=true
CLUSTER_ENABLED=false

# WebSocket
WS_PING_TIMEOUT=60000
WS_PING_INTERVAL=25000
WS_UPGRADE_TIMEOUT=10000
WS_MAX_HTTP_BUFFER_SIZE=104857600
```

### Características Específicas de Render

✅ **Despliegue automático** desde GitHub
✅ **SSL automático** con certificados Let's Encrypt
✅ **Health checks** automáticos
✅ **Escalado automático** según demanda
✅ **Logs centralizados** en el dashboard de Render
✅ **Variables de entorno** seguras
✅ **Backups automáticos** de la base de datos

### Endpoints Disponibles

- **`/`** - Aplicación principal
- **`/health`** - Estado del servidor
- **`/metrics`** - Métricas (solo admin)
- **`/audit-logs`** - Logs de auditoría (solo admin)

### Monitoreo

Render proporciona:
- **Logs en tiempo real**
- **Métricas de rendimiento**
- **Estado del servicio**
- **Alertas automáticas**

## 🚀 Características Avanzadas

### Seguridad Enterprise
- ✅ Autenticación JWT
- ✅ Rate limiting
- ✅ Validación de entrada
- ✅ Headers de seguridad
- ✅ Escaneo de archivos

### Rendimiento
- ✅ Cache inteligente
- ✅ Compresión automática
- ✅ Optimización de imágenes
- ✅ WebSocket optimizado

### Monitoreo
- ✅ Métricas en tiempo real
- ✅ Logs estructurados
- ✅ Auditoría completa
- ✅ Health checks

### Escalabilidad
- ✅ Arquitectura modular
- ✅ Cache distribuido
- ✅ Base de datos optimizada
- ✅ Manejo de errores robusto

## 📋 Instalación Local

```bash
# Clonar repositorio
git clone https://github.com/yourusername/chat-app.git
cd chat-app

# Instalar dependencias
npm install

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus configuraciones

# Iniciar en desarrollo
npm run dev

# Iniciar en producción
npm start
```

## 🔧 Comandos Disponibles

```bash
npm start          # Iniciar servidor
npm run dev        # Modo desarrollo con nodemon
npm run build      # Build (no requerido)
```

## 📊 Dashboard de Administración

Accede como administrador para ver:
- Métricas del servidor
- Logs de auditoría
- Gestión de usuarios
- Configuración del sistema

## 🔒 Seguridad

- **Autenticación**: JWT tokens seguros
- **Autorización**: Roles de usuario y admin
- **Validación**: Entrada sanitizada
- **Rate Limiting**: Protección contra ataques
- **Headers**: Seguridad automática

## 📈 Monitoreo

- **Uptime**: Tiempo de funcionamiento
- **Memory**: Uso de memoria
- **CPU**: Uso de procesador
- **Connections**: Conexiones activas
- **Users**: Usuarios en línea

## 🛠️ Tecnologías

- **Backend**: Node.js, Express
- **WebSocket**: Socket.IO
- **Base de Datos**: SQLite3
- **Cache**: Node-Cache, LRU-Cache
- **Seguridad**: Helmet, Rate-Limiting
- **Monitoreo**: Winston, Métricas
- **Archivos**: Multer, Sharp

## 📝 Licencia

MIT License - ver [LICENSE](LICENSE) para más detalles.

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push a la rama
5. Abre un Pull Request

## 📞 Soporte

- **Issues**: [GitHub Issues](https://github.com/yourusername/chat-app/issues)
- **Documentación**: [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md)

---

**¡Disfruta tu aplicación de chat avanzada en Render!** 🎉 