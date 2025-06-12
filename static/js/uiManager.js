export class UIManager {
    constructor() {
        this.initializeUIElements();
    }
    
    initializeUIElements() {
        this.createConnectionStatus();
    }
    
    createConnectionStatus() {
        const statusDiv = document.createElement('div');
        statusDiv.id = 'connection-status';
        statusDiv.className = 'connection-status disconnected';
        statusDiv.innerHTML = `
            <span class="status-dot"></span>
            <span class="status-text">Disconnected</span>
        `;
        document.body.appendChild(statusDiv);
    }
    
    showLoading(action) {
        const actionArea = document.querySelector(`[data-action="${action}"]`);
        if (actionArea) {
            actionArea.classList.add('loading');
            const spinner = document.createElement('div');
            spinner.className = 'loading-spinner';
            actionArea.appendChild(spinner);
        }
    }

    hideLoading(action) {
        const actionArea = document.querySelector(`[data-action="${action}"]`);
        if (actionArea) {
            actionArea.classList.remove('loading');
            const spinner = actionArea.querySelector('.loading-spinner');
            if (spinner) spinner.remove();
        }
    }
}