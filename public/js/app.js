// URL del servidor WebSocket (cambiar a tu servidor)
const socket = io('https://chat-app-bymp.onrender.com/');

// Variables globales
let currentUser = null;
let currentRoom = 'general';
let onlineUsers = [];
let isAdminPanelOpen = false;

// Elementos DOM
const loginContainer = document.getElementById('login-container');
const registerContainer = document.getElementById('register-container');
const chatContainer = document.getElementById('chat-container');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const showRegister = document.getElementById('show-register');
const showLogin = document.getElementById('show-login');
const currentUserElement = document.getElementById('current-user');
const currentUserIdElement = document.getElementById('current-user-id');
const userAvatar = document.getElementById('user-avatar');
const chatMessages = document.getElementById('chat-messages');
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const onlineUsersList = document.getElementById('online-users');
const currentRoomElement = document.getElementById('current-room');
const logoutButton = document.getElementById('logout-button');
const rememberMe = document.getElementById('remember-me');
const adminButton = document.getElementById('admin-button');
const adminPanel = document.getElementById('admin-panel');
const adminClose = document.getElementById('admin-close');
const adminBadge = document.getElementById('admin-badge');
const adminUserList = document.getElementById('admin-user-list');
const adminMessageList = document.getElementById('admin-message-list');
const bannedIpList = document.getElementById('banned-ip-list');
const moderationLog = document.getElementById('moderation-log');
const banIpButton = document.getElementById('ban-ip-button');
const banIpInput = document.getElementById('ban-ip-input');
const banReasonInput = document.getElementById('ban-reason-input');
const menuToggle = document.getElementById('menu-toggle');
const sidebar = document.getElementById('sidebar');
const sidebarOverlay = document.getElementById('sidebar-overlay');
const adminTokenGroup = document.getElementById('admin-token-group');
const adminLoginCheckbox = document.getElementById('admin-login');
const generateTokenButton = document.getElementById('generate-token-button');
const tokenResult = document.getElementById('token-result');
const generatedToken = document.getElementById('generated-token');
const ssoTokenList = document.getElementById('sso-token-list');

// Toggle sidebar en dispositivos móviles
function toggleSidebar() {
    sidebar.classList.toggle('active');
    sidebarOverlay.classList.toggle('active');
}

// Cerrar sidebar al hacer clic en overlay
sidebarOverlay.addEventListener('click', toggleSidebar);

// Funciones para manejar cookies
function setCookie(name, value, days) {
    const date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
    const expires = "expires=" + date.toUTCString();
    document.cookie = name + "=" + value + ";" + expires + ";path=/";
}

function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for(let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

function deleteCookie(name) {
    document.cookie = name + '=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
}

// Función para mostrar notificaciones
function showNotification(message, type = 'error') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Formatear fecha/hora
function formatDateTime(date) {
    return `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
}

// Añadir mensaje al chat con ID único
function addMessage(message, isCurrentUser = false) {
    // Verificar si el mensaje ya existe
    if (document.querySelector(`[data-message-id="${message.id}"]`)) {
        return;
    }
    
    const messageElement = document.createElement('div');
    messageElement.classList.add('message');
    messageElement.classList.add(isCurrentUser ? 'sent' : 'received');
    
    if (message.banned) {
        messageElement.classList.add('banned-message');
    }
    
    messageElement.setAttribute('data-message-id', message.id);
    
    messageElement.innerHTML = `
        <div class="message-header">
            <span class="message-sender">${isCurrentUser ? 'Tú' : message.sender}</span>
            <span class="user-id">ID: ${message.senderId}</span>
            <span class="message-time">${formatDateTime(new Date(message.timestamp))}</span>
        </div>
        <div class="message-text">${message.banned ? '[MENSAJE ELIMINADO POR ADMINISTRADOR]' : message.text}</div>
        <div class="message-info">
            <span class="message-id">Msg ID: ${message.id}</span>
            ${currentUser?.role === 'admin' ? `
            <button class="admin-action delete-button" data-message-id="${message.id}">
                <i class="fas fa-trash"></i> Eliminar
            </button>
            ` : ''}
        </div>
    `;
    
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    
    // Agregar evento para eliminar mensaje (solo admins)
    if (currentUser?.role === 'admin') {
        const deleteBtn = messageElement.querySelector('.delete-button');
        deleteBtn.addEventListener('click', (e) => {
            const messageId = e.target.closest('.delete-button').dataset.messageId;
            socket.emit('admin:deleteMessage', { messageId });
        });
    }
}

// Actualizar lista de usuarios en línea con IDs únicos
function updateOnlineUsers(users) {
    onlineUsers = users;
    onlineUsersList.innerHTML = '';
    
    users.forEach(user => {
        if (user.id === currentUser?.id) return;
        
        const userItem = document.createElement('li');
        userItem.classList.add('user-item');
        userItem.setAttribute('data-user-id', user.id);
        
        userItem.innerHTML = `
            <div class="user-avatar-sm">${user.nickname.charAt(0)}</div>
            <div>
                <div>${user.nickname}</div>
                <div class="user-id">ID: ${user.id}</div>
            </div>
            ${user.role === 'admin' ? '<div class="admin-indicator">A</div>' : ''}
            ${currentUser?.role === 'admin' ? `
            <button class="admin-action ban-button" data-user-id="${user.id}">
                <i class="fas fa-ban"></i> Banear
            </button>
            ` : ''}
        `;
        
        onlineUsersList.appendChild(userItem);
        
        // Agregar evento para banear usuario (solo admins)
        if (currentUser?.role === 'admin') {
            const banBtn = userItem.querySelector('.ban-button');
            banBtn.addEventListener('click', (e) => {
                const userId = e.target.closest('.ban-button').dataset.userId;
                const reason = prompt('Razón del baneo:');
                if (reason) {
                    socket.emit('admin:banUser', { userId, reason });
                }
            });
        }
    });
}

// Cerrar sesión
function logout() {
    // Eliminar cookies de sesión
    deleteCookie('sessionToken');
    deleteCookie('rememberMe');
    
    // Notificar al servidor
    socket.emit('logout', { userId: currentUser.id });
    
    // Resetear estado
    currentUser = null;
    
    // Mostrar pantalla de login
    chatContainer.classList.add('hidden');
    loginContainer.classList.remove('hidden');
    
    // Desconectar el socket
    socket.disconnect();
}

// Toggle panel de administración
function toggleAdminPanel() {
    isAdminPanelOpen = !isAdminPanelOpen;
    adminPanel.classList.toggle('active', isAdminPanelOpen);
    
    if (isAdminPanelOpen) {
        // Cerrar sidebar si está abierto en móviles
        if (window.innerWidth <= 768) {
            toggleSidebar();
        }
        
        // Cargar datos para el panel de administración
        socket.emit('admin:getData');
    }
}

// Renderizar datos del panel de administración
function renderAdminData(data) {
    // Usuarios
    adminUserList.innerHTML = '';
    data.users.forEach(user => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${user.id}</td>
            <td>${user.nickname}</td>
            <td>${user.username}</td>
            <td>${user.role}</td>
            <td>${user.banned ? 'Baneado' : 'Activo'}</td>
            <td>
                ${user.role !== 'admin' ? `
                <button class="admin-action ban-button" data-user-id="${user.id}">Banear</button>
                ` : ''}
                ${user.banned ? `
                <button class="admin-action" data-user-id="${user.id}" style="background: var(--success-color);">Desbanear</button>
                ` : ''}
            </td>
        `;
        adminUserList.appendChild(tr);
        
        // Agregar eventos a los botones
        const banBtn = tr.querySelector('.ban-button');
        if (banBtn) {
            banBtn.addEventListener('click', () => {
                const reason = prompt('Razón del baneo:');
                if (reason) {
                    socket.emit('admin:banUser', { userId: user.id, reason });
                }
            });
        }
        
        const unbanBtn = tr.querySelector('[style*="var(--success-color)"]');
        if (unbanBtn) {
            unbanBtn.addEventListener('click', () => {
                socket.emit('admin:unbanUser', { userId: user.id });
            });
        }
    });
    
    // Mensajes reportados
    adminMessageList.innerHTML = '';
    data.reportedMessages.forEach(msg => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${msg.id}</td>
            <td>${msg.sender}</td>
            <td>${msg.text}</td>
            <td>${new Date(msg.timestamp).toLocaleString()}</td>
            <td>
                <button class="admin-action delete-button" data-message-id="${msg.id}">Eliminar</button>
                <button class="admin-action" data-message-id="${msg.id}" style="background: var(--success-color);">Descartar</button>
            </td>
        `;
        adminMessageList.appendChild(tr);
        
        // Agregar eventos a los botones
        const deleteBtn = tr.querySelector('.delete-button');
        deleteBtn.addEventListener('click', () => {
            socket.emit('admin:deleteMessage', { messageId: msg.id });
        });
        
        const dismissBtn = tr.querySelector('[style*="var(--success-color)"]');
        dismissBtn.addEventListener('click', () => {
            socket.emit('admin:dismissReport', { messageId: msg.id });
        });
    });
    
    // IPs baneadas
    bannedIpList.innerHTML = '';
    data.bannedIps.forEach(ip => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${ip.ip}</td>
            <td>${ip.reason}</td>
            <td>${new Date(ip.timestamp).toLocaleDateString()}</td>
            <td>
                <button class="admin-action" data-ip="${ip.ip}" style="background: var(--success-color);">Desbanear</button>
            </td>
        `;
        bannedIpList.appendChild(tr);
        
        // Agregar evento al botón
        const unbanBtn = tr.querySelector('button');
        unbanBtn.addEventListener('click', () => {
            socket.emit('admin:unbanIp', { ip: ip.ip });
        });
    });
    
    // Registro de moderación
    moderationLog.innerHTML = '';
    data.moderationLog.forEach(log => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${log.moderator}</td>
            <td>${log.action_type}</td>
            <td>${log.target}</td>
            <td>${new Date(log.timestamp).toLocaleString()}</td>
        `;
        moderationLog.appendChild(tr);
    });
    
    // Tokens SSO
    ssoTokenList.innerHTML = '';
    if (data.ssoTokens && data.ssoTokens.length > 0) {
        data.ssoTokens.forEach(token => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${token.token}</td>
                <td>${new Date(token.created_at).toLocaleString()}</td>
            `;
            ssoTokenList.appendChild(tr);
        });
    } else {
        ssoTokenList.innerHTML = '<tr><td colspan="2">No hay tokens generados</td></tr>';
    }
}

// Cambiar a pantalla de registro
showRegister.addEventListener('click', (e) => {
    e.preventDefault();
    loginContainer.classList.add('hidden');
    registerContainer.classList.remove('hidden');
});

// Cambiar a pantalla de login
showLogin.addEventListener('click', (e) => {
    e.preventDefault();
    registerContainer.classList.add('hidden');
    loginContainer.classList.remove('hidden');
});

// Mostrar/ocultar campo SSO
adminLoginCheckbox.addEventListener('change', function() {
    adminTokenGroup.style.display = this.checked ? 'block' : 'none';
});

// Login
loginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const remember = rememberMe.checked;
    const isAdminLogin = document.getElementById('admin-login').checked;
    const adminToken = isAdminLogin ? document.getElementById('admin-token').value : '';
    
    // Validación básica
    if (!username || !password) {
        showNotification('Por favor completa todos los campos');
        return;
    }
    
    // Autenticación con el servidor
    socket.emit('login', { 
        username, 
        password,
        adminToken
    }, (response) => {
        if (response.success) {
            currentUser = response.user;
            
            // Mostrar elementos de admin si corresponde
            if (currentUser.role === 'admin') {
                adminButton.classList.remove('hidden');
                adminBadge.classList.remove('hidden');
            }
            
            // Guardar sesión en cookie
            if (remember) {
                setCookie('sessionToken', response.token, 30);
                setCookie('rememberMe', 'true', 30);
            } else {
                setCookie('sessionToken', response.token, 1); // Sesión de 1 día
            }
            
            // Actualizar UI
            currentUserElement.textContent = currentUser.nickname;
            currentUserIdElement.textContent = `ID: ${currentUser.id}`;
            userAvatar.textContent = currentUser.nickname.charAt(0).toUpperCase();
            
            // Cambiar a pantalla de chat
            loginContainer.classList.add('hidden');
            chatContainer.classList.remove('hidden');
            
            // Unirse al chat
            socket.emit('join', {
                user: currentUser,
                room: currentRoom
            });
            
            // Mensaje de bienvenida
            addMessage({
                id: 'system-' + Date.now(),
                text: `¡Bienvenido ${currentUser.nickname}! Has entrado al chat.`,
                sender: 'Sistema',
                senderId: 'system',
                timestamp: Date.now()
            });
        } else {
            showNotification(response.message || 'Error en el inicio de sesión');
        }
    });
});

// Registro
registerForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const nickname = document.getElementById('reg-nickname').value;
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;
    const confirm = document.getElementById('reg-confirm').value;
    
    // Validaciones
    if (!nickname || !username || !password || !confirm) {
        showNotification('Por favor completa todos los campos');
        return;
    }
    
    if (password !== confirm) {
        showNotification('Las contraseñas no coinciden');
        return;
    }
    
    if (password.length < 6) {
        showNotification('La contraseña debe tener al menos 6 caracteres');
        return;
    }
    
    // Registro con el servidor
    socket.emit('register', { nickname, username, password }, (response) => {
        if (response.success) {
            currentUser = response.user;
            
            // Guardar sesión en cookie
            setCookie('sessionToken', response.token, 30);
            
            // Actualizar UI
            currentUserElement.textContent = currentUser.nickname;
            currentUserIdElement.textContent = `ID: ${currentUser.id}`;
            userAvatar.textContent = currentUser.nickname.charAt(0).toUpperCase();
            
            // Cambiar a pantalla de chat
            registerContainer.classList.add('hidden');
            chatContainer.classList.remove('hidden');
            
            // Unirse al chat
            socket.emit('join', {
                user: currentUser,
                room: currentRoom
            });
            
            // Mensaje de bienvenida
            addMessage({
                id: 'system-' + Date.now(),
                text: `¡Bienvenido ${currentUser.nickname}! Has entrado al chat.`,
                sender: 'Sistema',
                senderId: 'system',
                timestamp: Date.now()
            });
        } else {
            showNotification(response.message || 'Error en el registro');
        }
    });
});

// Cambiar sala de chat
document.querySelectorAll('.room-item').forEach(item => {
    item.addEventListener('click', function() {
        document.querySelectorAll('.room-item').forEach(i => i.classList.remove('active'));
        this.classList.add('active');
        
        const roomName = this.getAttribute('data-room');
        currentRoom = roomName;
        
        const roomDisplayName = roomName === 'general' ? 'General' : 
                              roomName === 'develop' ? 'Desarrollo' :
                              roomName === 'business' ? 'Negocios' :
                              roomName === 'gaming' ? 'Gaming' : 'Música';
        
        currentRoomElement.textContent = `Sala ${roomDisplayName}`;
        
        // Notificar cambio de sala
        socket.emit('changeRoom', {
            user: currentUser,
            newRoom: roomName
        });
        
        // Limpiar mensajes actuales
        chatMessages.innerHTML = '';
        
        // Mensaje de sistema
        addMessage({
            id: 'system-' + Date.now(),
            text: `Te has unido a la sala ${roomDisplayName}.`,
            sender: 'Sistema',
            senderId: 'system',
            timestamp: Date.now()
        });
        
        // En móviles, cerrar el sidebar después de seleccionar sala
        if (window.innerWidth <= 768) {
            toggleSidebar();
        }
    });
});

// Enviar mensaje
function sendMessage() {
    const text = messageInput.value.trim();
    if (text && currentUser) {
        const message = {
            text: text,
            sender: currentUser.nickname,
            senderId: currentUser.id,
            room: currentRoom,
            timestamp: Date.now()
        };
        
        // Añadir mensaje localmente
        socket.emit('message', message);
        
        // Limpiar input
        messageInput.value = '';
    }
}

sendButton.addEventListener('click', sendMessage);
messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

// Botón de cerrar sesión
logoutButton.addEventListener('click', logout);

// Botones de administración
adminButton.addEventListener('click', toggleAdminPanel);
adminClose.addEventListener('click', toggleAdminPanel);

// Botón de menú para móviles
menuToggle.addEventListener('click', toggleSidebar);

// Banear por IP
banIpButton.addEventListener('click', () => {
    const ip = banIpInput.value.trim();
    const reason = banReasonInput.value.trim();
    
    if (!ip) {
        showNotification('Debes ingresar una dirección IP');
        return;
    }
    
    if (!reason) {
        showNotification('Debes ingresar una razón');
        return;
    }
    
    socket.emit('admin:banIp', { ip, reason });
    banIpInput.value = '';
    banReasonInput.value = '';
});

// Generar token SSO
generateTokenButton.addEventListener('click', () => {
    socket.emit('admin:generateToken', {}, (response) => {
        if (response.success) {
            generatedToken.textContent = response.token;
            tokenResult.style.display = 'block';
            
            // Copiar al portapapeles automáticamente
            navigator.clipboard.writeText(response.token)
                .then(() => {
                    showNotification('Token copiado al portapapeles', 'success');
                })
                .catch(err => {
                    console.error('Error al copiar:', err);
                    showNotification('Error al copiar token', 'error');
                });
        } else {
            showNotification(response.error || 'Error al generar token', 'error');
        }
    });
});

// ===== Eventos de Socket.io =====

// Escuchar mensajes del servidor
socket.on('message', (message) => {
    if (message.room === currentRoom) {
        const isCurrentUser = currentUser && message.senderId === currentUser.id;
        addMessage(message, isCurrentUser);
    }
});

// Escuchar actualizaciones de usuarios
socket.on('updateUsers', (users) => {
    updateOnlineUsers(users);
});

// Escuchar mensajes del sistema
socket.on('systemMessage', (message) => {
    if (message.room === currentRoom) {
        addMessage(message);
    }
});

// Escuchar errores de autenticación
socket.on('authError', (message) => {
    showNotification(message);
});

// Escuchar cuando un usuario se une
socket.on('userJoined', (user) => {
    if (user.room === currentRoom) {
        addMessage({
            id: 'system-' + Date.now(),
            text: `${user.nickname} se ha unido al chat`,
            sender: 'Sistema',
            senderId: 'system',
            timestamp: Date.now()
        });
    }
});

// Escuchar cuando un usuario abandona
socket.on('userLeft', (user) => {
    if (user.room === currentRoom) {
        addMessage({
            id: 'system-' + Date.now(),
            text: `${user.nickname} ha abandonado el chat`,
            sender: 'Sistema',
            senderId: 'system',
            timestamp: Date.now()
        });
    }
});

// Manejar reconexión
socket.on('reconnect', () => {
    if (currentUser) {
        socket.emit('rejoin', {
            user: currentUser,
            room: currentRoom
        });
    }
});

// Cargar mensajes iniciales
socket.on('initialData', (data) => {
    if (data.room === currentRoom) {
        data.messages.forEach(message => {
            const isCurrentUser = currentUser && message.sender_id === currentUser.id;
            addMessage({
                id: message.id,
                text: message.text,
                sender: message.sender,
                senderId: message.sender_id,
                timestamp: new Date(message.timestamp).getTime(),
                banned: message.banned
            }, isCurrentUser);
        });
    }
});

// Validar sesión al cargar la página
window.addEventListener('DOMContentLoaded', () => {
    const sessionToken = getCookie('sessionToken');
    const remember = getCookie('rememberMe') === 'true';
    
    if (sessionToken) {
        // Mostrar recordarme si está activo
        if (remember) {
            rememberMe.checked = true;
        }
        
        // Conectar al servidor
        socket.connect();
        
        // Validar sesión
        socket.emit('validateSession', sessionToken, (response) => {
            if (response.valid) {
                currentUser = response.user;
                
                // Mostrar elementos de admin si corresponde
                if (currentUser.role === 'admin') {
                    adminButton.classList.remove('hidden');
                    adminBadge.classList.remove('hidden');
                }
                
                // Actualizar UI
                currentUserElement.textContent = currentUser.nickname;
                currentUserIdElement.textContent = `ID: ${currentUser.id}`;
                userAvatar.textContent = currentUser.nickname.charAt(0).toUpperCase();
                
                // Cambiar a pantalla de chat
                loginContainer.classList.add('hidden');
                registerContainer.classList.add('hidden');
                chatContainer.classList.remove('hidden');
                
                // Unirse al chat
                socket.emit('join', {
                    user: currentUser,
                    room: currentRoom
                });
            } else {
                // Eliminar cookies inválidas
                deleteCookie('sessionToken');
                deleteCookie('rememberMe');
            }
        });
    }
});

// Recibir datos para el panel de administración
socket.on('admin:data', (data) => {
    renderAdminData(data);
});

// Notificación de acción de administración
socket.on('admin:notification', (message) => {
    showNotification(message, 'success');
    
    // Si el panel está abierto, actualizar datos
    if (isAdminPanelOpen) {
        socket.emit('admin:getData');
    }
});

// Usuario baneado
socket.on('user:banned', (data) => {
    if (currentUser && currentUser.id === data.userId) {
        showNotification('Has sido baneado: ' + data.reason, 'error');
        logout();
    }
});