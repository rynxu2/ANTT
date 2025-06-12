import { SocketManager } from './socketManager.js';
import { HostManager } from './hostManager.js';
import { FileManager } from './fileManager.js';
import { RequestManager } from './requestManager.js';
import { UIManager } from './uiManager.js';

class RealtimeClient {
    constructor() {
        this.socketManager = new SocketManager();

        this.socketManager.socket.on('connect', () => {
            this.hostManager = new HostManager(this.socketManager.socket);
            this.fileManager = new FileManager(this.socketManager.socket);
            this.requestManager = new RequestManager(this.socketManager.socket);
            this.uiManager = new UIManager();
        });
    }

    static initialize() {
        if (!window.realtimeClient) {
            window.realtimeClient = new RealtimeClient();
        }
        return window.realtimeClient;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    RealtimeClient.initialize();
});

export { RealtimeClient };