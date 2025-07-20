# 🚀 Guía de Despliegue en Render

## 📋 Pasos para Desplegar en Render

### 1. Preparar el Repositorio

Asegúrate de que tu repositorio contenga estos archivos:
- ✅ `server.js` - Servidor principal
- ✅ `package.json` - Dependencias y scripts
- ✅ `render.yaml` - Configuración de Render
- ✅ `public/` - Archivos estáticos
- ✅ `.gitignore` - Archivos a ignorar

### 2. Conectar a Render

1. Ve a [render.com](https://render.com)
2. Crea una cuenta o inicia sesión
3. Haz clic en "New +" → "Web Service"
4. Conecta tu repositorio de GitHub
5. Selecciona el repositorio del chat app

### 3. Configuración Automática

Render detectará automáticamente:
- ✅ **Runtime**: Node.js
- ✅ **Build Command**: `npm install`
- ✅ **Start Command**: `npm start`
- ✅ **Port**: 10000

### 4. Variables de Entorno (Opcional)

Render generará automáticamente las variables de seguridad, pero puedes configurar:

#### Variables Automáticas (no necesitas configurar):
- `ADMIN_TOKEN` - Se genera automáticamente
- `JWT_SECRET` - Se genera automáticamente
- `SESSION_SECRET` - Se genera automáticamente

#### Variables Opcionales (puedes configurar):
```bash
NODE_ENV=production
PORT=10000
LOG_LEVEL=info
ALLOWED_ORIGINS=*
RATE_LIMIT_MAX_REQUESTS=100
LOGIN_RATE_LIMIT_MAX=5
UPLOAD_RATE_LIMIT_MAX=10
MAX_FILE_SIZE=10485760
MAX_FILES_PER_UPLOAD=5
METRICS_ENABLED=true
AUDIT_LOG_ENABLED=true
COMPRESSION_ENABLED=true
CLUSTER_ENABLED=false
```

### 5. Configuración Avanzada

#### Health Check
- **Path**: `/health`
- **Interval**: 30 segundos
- **Timeout**: 10 segundos

#### Auto-Deploy
- ✅ **Enabled**: Sí
- ✅ **Branch**: `main` o `master`

#### Environment
- ✅ **Environment**: Node.js
- ✅ **Region**: El más cercano a tus usuarios

### 6. Despliegue

1. Haz clic en "Create Web Service"
2. Render comenzará el despliegue automáticamente
3. Espera 2-5 minutos para que termine
4. Tu app estará disponible en `https://tu-app.onrender.com`

## 🔧 Configuración Específica de Render

### Características Adaptadas

#### ✅ Sistema de Archivos Efímero
- Los archivos subidos se perderán al reiniciar
- La base de datos se reinicia periódicamente
- No se hacen backups automáticos

#### ✅ Sin Clustering
- Render maneja la escalabilidad automáticamente
- No necesitas configurar workers manualmente

#### ✅ Redis Opcional
- Cache local por defecto
- Redis disponible si lo configuras

#### ✅ Logs Centralizados
- Todos los logs van al dashboard de Render
- No necesitas configurar logging externo

### Optimizaciones para Render

#### Performance
- ✅ Compresión automática
- ✅ Cache optimizado
- ✅ Rate limiting configurado
- ✅ Headers de seguridad

#### Monitoreo
- ✅ Health checks automáticos
- ✅ Métricas en tiempo real
- ✅ Logs estructurados
- ✅ Alertas automáticas

## 📊 Monitoreo en Render

### Dashboard de Render
- **Logs**: En tiempo real
- **Métricas**: CPU, memoria, requests
- **Estado**: Uptime y health checks
- **Despliegues**: Historial de cambios

### Endpoints de Monitoreo
- **`/health`** - Estado del servidor
- **`/metrics`** - Métricas detalladas (admin)
- **`/audit-logs`** - Logs de auditoría (admin)

## 🔒 Seguridad en Render

### Automática
- ✅ SSL/TLS automático
- ✅ Headers de seguridad
- ✅ Rate limiting
- ✅ Validación de entrada

### Configurable
- ✅ Variables de entorno seguras
- ✅ Tokens JWT
- ✅ Autenticación de usuarios
- ✅ Autorización por roles

## 🚀 Escalabilidad

### Automática
- Render escala automáticamente según demanda
- No necesitas configurar nada manualmente

### Límites del Plan Gratuito
- **Uptime**: 15 minutos de inactividad
- **Ancho de banda**: 750 horas/mes
- **Almacenamiento**: 512MB
- **Memoria**: 512MB

### Planes de Pago
- **Starter**: $7/mes - Siempre activo
- **Standard**: $25/mes - Más recursos
- **Pro**: $50/mes - Recursos dedicados

## 🔧 Troubleshooting

### Problemas Comunes

#### 1. Build Fails
```bash
# Verificar package.json
npm install --production

# Verificar Node.js version
node --version
```

#### 2. App No Inicia
```bash
# Verificar logs en Render
# Verificar variables de entorno
# Verificar puerto (debe ser 10000)
```

#### 3. WebSocket No Funciona
```bash
# Verificar CORS
# Verificar SSL
# Verificar firewall
```

#### 4. Base de Datos No Persiste
```bash
# Normal en Render (sistema efímero)
# Considerar base de datos externa
# Usar variables de entorno para configuración
```

### Logs Útiles

```bash
# Ver logs en tiempo real
# En el dashboard de Render

# Verificar health check
curl https://tu-app.onrender.com/health

# Verificar métricas (admin)
curl -H "Authorization: Bearer tu-token" \
     https://tu-app.onrender.com/metrics
```

## 📈 Métricas y Analytics

### Render Dashboard
- **Requests/minuto**
- **Response time**
- **Error rate**
- **Uptime**

### Aplicación
- **Usuarios en línea**
- **Mensajes/minuto**
- **Archivos subidos**
- **Cache hit rate**

## 🎯 Próximos Pasos

1. **Desplegar**: Sigue la guía anterior
2. **Configurar**: Variables de entorno opcionales
3. **Monitorear**: Usar el dashboard de Render
4. **Optimizar**: Según métricas y uso
5. **Escalar**: Si necesitas más recursos

## 📞 Soporte

- **Render Docs**: [docs.render.com](https://docs.render.com)
- **Render Support**: [support.render.com](https://support.render.com)
- **GitHub Issues**: Para problemas específicos del código

---

**¡Tu aplicación de chat estará funcionando en Render en minutos!** 🚀 