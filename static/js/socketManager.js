export class SocketManager {
    constructor() {
        this.socket = this.initializeSocket();
    }
    
    initializeSocket() {
        if (window.socket) return window.socket;
        
        const socket = io({ 
            reconnection: true,
            reconnectionAttempts: 5,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            timeout: 20000,
            transports: ['websocket']
        });
        window.socket = socket;
        return socket;
    }
}