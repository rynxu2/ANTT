class RealtimeClient {
    constructor() {
        if (window.socket) {
            this.socket = window.socket;
        } else {
            this.socket = io({
                reconnection: true,
                reconnectionAttempts: 5,
                reconnectionDelay: 1000,
                reconnectionDelayMax: 5000,
                timeout: 20000,
                transports: ['websocket']
            });
            window.socket = this.socket;
        }
        
        if (window.realtimeClient) {
            return window.realtimeClient;
        }
        window.realtimeClient = this;
        
        this.processedFiles = new Set();
        this.initializeEventHandlers();
        this.initializeUIElements();
    }

    initializeUIElements() {
        const statusDiv = document.createElement('div');
        statusDiv.id = 'connection-status';
        statusDiv.className = 'connection-status disconnected';
        statusDiv.innerHTML = `
            <span class="status-dot"></span>
            <span class="status-text">Disconnected</span>
        `;
        document.body.appendChild(statusDiv);
    }

    initializeEventHandlers() {
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.updateConnectionStatus('connected');
            this.socket.emit('join', { room: this.getClientIP() });
        });

        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
            this.updateConnectionStatus('disconnected');
        });

        this.socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            this.updateConnectionStatus('error');
        });

        this.socket.on('reconnect_attempt', (attemptNumber) => {
            console.log(`Reconnection attempt ${attemptNumber}`);
            this.updateConnectionStatus('reconnecting');
        });

        this.socket.on('new_host', (data) => {
            this.handleNewHost(data);
        });

        this.socket.on('host_deleted', (data) => {
            this.handleHostDeleted(data);
        });

        this.socket.on('status_change', (data) => {
            this.handleStatusChange(data);
        });

        let lastNewFileTimestamp = 0;
        this.socket.on('new_file', (data) => {
            const now = Date.now();
            if (now - lastNewFileTimestamp < 500) {
                console.log('Ignoring duplicate new_file event');
                return;
            }
            lastNewFileTimestamp = now;
            console.log('Processing new_file event:', data);
            this.handleNewFile(data);
        });

        this.socket.on('action_start', (data) => {
            this.showLoading(data.action);
        });

        this.socket.on('action_end', (data) => {
            this.hideLoading(data.action);
        });
    }

    updateConnectionStatus(status) {
        const statusDiv = document.getElementById('connection-status');
        if (!statusDiv) return;

        statusDiv.className = `connection-status ${status}`;
        const statusText = statusDiv.querySelector('.status-text');
        if (statusText) {
            statusText.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        }
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

    handleHostDeleted(data) {
        const isSelectHostPage = document.querySelector('.step.active .step-icon i.fas.fa-server') !== null;
        if (isSelectHostPage) {
            const hostElement = document.querySelector(`.card-body form[action="/select_host/${data.id}"]`)?.closest('.col');
            if (hostElement) {
                hostElement.remove();
                
                const hostContainer = document.querySelector('.row.row-cols-1.row-cols-md-2.row-cols-lg-3.g-4');
                if (hostContainer && !hostContainer.children.length) {
                    const cardBody = hostContainer.parentElement;
                    hostContainer.remove();
                    
                    cardBody.innerHTML = `
                        <div class="text-center">
                            <div class="alert alert-info">
                                <i class="fas fa-info-circle me-2"></i>
                                No hosts are available for file transfer. Ask your intended recipient to register as a host first.
                            </div>
                            <img src="https://www.carolijamora.com/build/images/background/no-results-bg.2d2c6ee3.png" alt="No hosts" class="img-fluid mb-3" style="max-width: 200px;">
                            <p class="text-muted">
                                To send files, you need a recipient who has registered as a host. Once they register, their host will appear here.
                            </p>
                            <a href="/sender_dashboard" class="btn btn-outline-primary">
                                <i class="fas fa-plus me-2"></i>
                                Manage Hosts
                            </a>
                        </div>
                    `;
                }
            }
        }

        const hostsList = document.querySelector('.hosts-list');
        if (hostsList) {
            const hostElement = hostsList.querySelector(`[data-id="${data.id}"]`)?.closest('.col-md-6');
            if (hostElement) {
                hostElement.remove();
            }
        }

        showAlert('info', 'A host has been removed');
    }

    handleNewHost(data) {
        const existingHost = document.querySelector(`[data-host-id="${data.id}"]`);
        if (existingHost) {
            console.log(`Host ${data.id} already exists, skipping addition`);
            return;
        }

        const hostsList = document.querySelector('.hosts-list');
        if (hostsList) {
            const newHostHtml = `
                <div class="col-md-6 col-lg-4 mb-4" data-host-id="${data.id}">
                    <div class="card h-100 border-0 shadow-sm">
                        <div class="card-body">
                            <h5 class="card-title d-flex align-items-center">
                                <i class="fas fa-desktop text-primary me-2"></i>
                                ${data.name}
                            </h5>
                            <p class="card-text">
                                <small class="text-muted">
                                    <i class="fas fa-network-wired me-1"></i> ${data.ip_address}
                                </small>
                                ${data.description ? `<br>${data.description}` : ''}
                            </p>
                            <div class="d-flex justify-content-between align-items-center">
                                <small class="text-muted">Added by ${data.created_by}</small>
                                <button class="btn btn-sm btn-outline-danger delete-recipient" data-id="${data.id}">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            hostsList.insertAdjacentHTML('afterbegin', newHostHtml);

            const newDeleteButton = hostsList.querySelector(`[data-id="${data.id}"]`);
            if (newDeleteButton) {
                newDeleteButton.addEventListener('click', () => {
                    if (confirm('Are you sure you want to delete this recipient?')) {
                        deleteRecipient(data.id);
                    }
                });
            }
        }

        const isSelectHostPage = document.querySelector('.step.active .step-icon i.fas.fa-server') !== null;
        if (!isSelectHostPage) return;

        const hostCard = document.querySelector('.card:not(.mb-4)');
        if (!hostCard) return;

        const cardBody = hostCard.querySelector('.card-body');
        if (!cardBody) return;

        const newHostHtml = `
            <div class="col" data-host-id="${data.id}">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title">${data.name}</h5>
                        <p class="card-text">
                            <small class="text-muted">IP: <code>${data.ip_address}</code></small>
                        </p>
                        ${data.description ? `<p class="card-text">${data.description}</p>` : ''}
                        <div class="mt-3">
                            ${data.public_key ? `
                                <form action="/select_host/${data.id}" method="POST" class="select-host-form">
                                    <input type="hidden" name="csrf_token" value="${document.querySelector('meta[name="csrf-token"]').getAttribute('content')}">
                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="fas fa-check-circle me-2"></i>
                                        Select this Host
                                    </button>
                                </form>
                            ` : `
                                <button class="btn btn-warning w-100" disabled>
                                    <i class="fas fa-exclamation-triangle me-2"></i>
                                    No Public Key Available
                                </button>
                            `}
                        </div>
                    </div>
                </div>
            </div>
        `;

        let hostContainer = cardBody.querySelector('.row.row-cols-1.row-cols-md-2.row-cols-lg-3.g-4');
        const noHostsElements = cardBody.querySelector('.text-center');

        if (!hostContainer) {
            if (noHostsElements) {
                noHostsElements.remove();
            }
            hostContainer = document.createElement('div');
            hostContainer.className = 'row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4';
            cardBody.appendChild(hostContainer);
        }

        hostContainer.insertAdjacentHTML('afterbegin', newHostHtml);
        showAlert('success', `New host "${data.name}" has been added`);
    }    

    handleStatusChange(data) {        
        console.log("Status change received:", data);

        if (data.status === 'verified') {
            const completedStats = document.querySelector('.stat-card-completed');
            if (completedStats) {
                const currentCount = parseInt(completedStats.textContent) || 0;
                completedStats.textContent = (currentCount + 1).toString();
            }
        }

        const fileRow = document.querySelector(`tr[data-session-token="${data.session_token}"]`);
        if (!fileRow) {
            console.warn("Could not find file row for session token:", data.session_token);
            return;
        }
        console.log("Found file row:", fileRow);
        const statusCell = fileRow.querySelector('td:nth-child(5)');
        if (statusCell) {
            console.log("Updating status cell with new status:", data.status);
            let statusHtml = '';
            const statusConfig = {
                'verified': {
                    bg: 'verified',
                    icon: 'check-circle',
                    text: 'Verified'
                },
                'downloaded': {
                    bg: 'downloaded',
                    icon: 'download',
                    text: 'Downloaded'
                },
                'pending': {
                    bg: 'pending',
                    icon: 'clock',
                    text: 'Pending'
                },
                'failed': {
                    bg: 'failed',
                    icon: 'times-circle',
                    text: 'Failed'
                }
            };

            const config = statusConfig[data.status] || statusConfig.pending;
            statusHtml = `
                <span class="status-badge status-${config.bg}">
                    <i class="fas fa-${config.icon} me-1"></i>
                    ${config.text}
                </span>`;
            const oldBadge = statusCell.querySelector('.badge');
            if (oldBadge) {
                oldBadge.classList.add('status-change');
                setTimeout(() => {
                    statusCell.innerHTML = statusHtml;
                    const newBadge = statusCell.querySelector('.badge');
                    if (newBadge) {
                        newBadge.classList.add('status-change');
                        setTimeout(() => newBadge.classList.remove('status-change'), 300);
                    }
                }, 150);
            } else {
                statusCell.innerHTML = statusHtml;
            }
            const notifications = {
                'verified': { 
                    type: 'success', 
                    message: 'File has been verified successfully. Ready for download.',
                    sound: 'success'
                },
                'downloaded': { 
                    type: 'info', 
                    message: 'File has been downloaded by the recipient',
                    sound: 'info'
                },
                'failed': { 
                    type: 'warning', 
                    message: 'File marked as failed',
                    sound: 'error'
                },
                'pending': { 
                    type: 'warning', 
                    message: 'File is pending verification',
                    sound: null
                }
            };

            const notification = notifications[data.status];
            if (notification) {
                const existingAlerts = document.querySelectorAll('.alert');
                let isDuplicate = false;
                
                existingAlerts.forEach(alert => {
                    if (alert.textContent.includes(notification.message)) {
                        isDuplicate = true;
                    }
                });
                
                if (!isDuplicate) {
                    showAlert(notification.type, notification.message);
                    
                    if (notification.sound && window.notificationSounds?.[notification.sound]) {
                        window.notificationSounds[notification.sound].play().catch(e => console.log('Sound play error:', e));
                    }
                }
                
                const notificationList = document.querySelector('.notification-list');
                if (notificationList) {
                    const notificationItem = document.createElement('div');
                    notificationItem.className = `notification-item alert alert-${notification.type} fade show`;
                    notificationItem.innerHTML = `
                        <div class="d-flex justify-content-between align-items-center">
                            <span><i class="fas fa-${this.getStatusIcon(data.status)} me-2"></i>${notification.message}</span>
                            <small class="text-muted">${new Date().toLocaleTimeString()}</small>
                        </div>
                    `;
                    notificationList.insertBefore(notificationItem, notificationList.firstChild);
                    
                    while (notificationList.children.length > 5) {
                        notificationList.removeChild(notificationList.lastChild);
                    }
                }
            }
            
            console.log("Status cell updated with animation");
        }

        if (window.location.pathname.includes('/receiver_files')) {
            const actionCell = fileRow.querySelector('td:last-child');
            if (actionCell) {
                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');            
                if (data.status === 'failed') {
                    actionCell.innerHTML = `
                        <div class="btn-group">
                            <button class="btn btn-sm btn-primary" disabled>
                                <i class="fas fa-download"></i>
                            </button>
                            <button class="btn btn-sm btn-danger" disabled>
                                <i class="fas fa-times-circle me-1"></i>
                            </button>
                        </div>
                    `;
                } else if (data.status === 'verified') {
                    actionCell.innerHTML = `
                        <div class="btn-group">
                            <a href="/download/${data.session_token}" class="btn btn-sm btn-primary" target="_blank">
                                <i class="fas fa-download"></i>
                            </a>
                            <button type="button" class="btn btn-sm btn-danger mark-failed" data-file-id="${fileRow.getAttribute('data-file-id')}">
                                <i class="fas fa-times-circle me-1"></i>Mark as Failed
                            </button>
                        </div>
                    `;
                    
                    const markFailedBtn = actionCell.querySelector('.mark-failed');
                    if (markFailedBtn) {
                        markFailedBtn.addEventListener('click', () => {
                            if (confirm('Are you sure you want to mark this file as failed?')) {
                                fetch('/mark_file_failed/' + markFailedBtn.getAttribute('data-file-id'), {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'X-CSRFToken': csrfToken
                                    }
                                })
                                .then(response => {
                                    if (response.ok) {
                                        return response.json();
                                    }
                                    throw new Error('Failed to update file status');
                                })
                                .then(result => {
                                    const statusCell = fileRow.querySelector('td:nth-child(5)');
                                    if (statusCell) {
                                        statusCell.innerHTML = `
                                            <span class="badge bg-danger">
                                                <i class="fas fa-times-circle me-1"></i>Failed
                                            </span>
                                        `;
                                    }
                                    this.highlightRow(fileRow, 'failed');
                                })
                                .catch(error => {
                                    console.error('Error:', error);
                                    showAlert('danger', error.message);
                                });
                            }
                        });
                    }
                } else if (data.status === 'downloaded') {
                    const badge = statusCell.querySelector('.badge');
                    if (badge) {
                        badge.classList.remove('bg-info');
                        badge.classList.add('bg-success');
                    }
                    showAlert('info', 'File has been downloaded by the recipient');
                }
            }    
        }
        this.highlightRow(fileRow, data.status);
    }

    highlightRow(row, status) {
        row.classList.remove('highlight-success', 'highlight-warning', 'highlight-danger');
        
        const highlightClass = {
            'verified': 'highlight-success',
            'downloaded': 'highlight-success',
            'failed': 'highlight-danger',
            'pending': 'highlight-warning'
        }[status] || 'highlight';
        
        row.classList.add(highlightClass);
        row.classList.add('highlight');
        
        setTimeout(() => {
            row.classList.remove('highlight', highlightClass);
        }, 2000);
    }

    handleNewFile(data) {
        if (window.location.pathname.includes('/receiver_files')) {
            const fileKey = `${data.session_token}-${data.created_at}`;
            if (this.processedFiles.has(fileKey)) {
                console.log('File đã được xử lý trước đó:', fileKey);
                return;
            }

            this.processedFiles.add(fileKey);
            console.log('Xử lý file mới:', fileKey);

            const emptyState = document.querySelector('.empty-state');
            if (emptyState) {
                emptyState.style.display = 'none';
            }

            let tableContainer = document.querySelector('.table-responsive');
            if (!tableContainer) {
                tableContainer = document.createElement('div');
                tableContainer.className = 'table-responsive';
                const cardBody = document.querySelector('.card-body');
                if (cardBody) {
                    if (emptyState) {
                        cardBody.insertBefore(tableContainer, emptyState);
                    } else {
                        cardBody.appendChild(tableContainer);
                    }
                }
            }

            let table = tableContainer.querySelector('.table');
            if (!table) {
                table = this.createFileTable();
                tableContainer.appendChild(table);
            }

            const tbody = table.querySelector('tbody');
            if (tbody) {
                const tr = this.createFileRow(data);
                tbody.insertBefore(tr, tbody.firstChild);
            }

            setTimeout(() => {
                this.processedFiles.delete(fileKey);
            }, 5000);
        }
    }

    createFileTable() {
        const table = document.createElement('table');
        table.className = 'table table-hover align-middle mb-0';
        table.innerHTML = `
            <thead>
                <tr>
                    <th style="width: 35%">File Name</th>
                    <th style="width: 20%">Sender</th>
                    <th style="width: 15%">Size</th>
                    <th style="width: 15%">Status</th>
                    <th style="width: 15%" class="text-end">Actions</th>
                </tr>
            </thead>
            <tbody></tbody>
        `;
        return table;
    }    
    
    createFileRow(data) {
        const tr = document.createElement('tr');
        tr.setAttribute('data-session-token', data.session_token);
        tr.setAttribute('data-file-id', data.id);
        const date = new Date(data.created_at);
        const formattedDate = date.toLocaleString('en-US', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        });

        tr.innerHTML = `
            <td>
                <div class="d-flex align-items-center">
                    <div class="file-icon me-3">
                        <i class="fas fa-file-alt"></i>
                    </div>
                    <div class="file-info">
                        <div class="file-name">${data.filename}</div>
                        <div class="file-date text-muted small">${formattedDate}</div>
                    </div>
                </div>
            </td>
            <td>
                <div class="d-flex align-items-center">
                    <div class="sender-avatar me-2">
                        <i class="fas fa-user"></i>
                    </div>
                    <code class="sender-ip">${data.sender_ip}</code>
                </div>
            </td>
            <td>${this.formatFileSize(data.file_size)}</td>            
            <td>
                <span class="badge bg-warning">
                    <i class="fas fa-clock me-1"></i>
                    Pending
                </span>
            </td>
            <td class="text-end">
                <div style="display: flex; gap: 3px;">
                    <button type="button" class="btn btn-sm btn-success verify-btn" 
                            data-session-token="${data.session_token}"
                            data-bs-toggle="tooltip"
                            data-bs-title="Verify File">
                        <i class="fas fa-check"></i>
                    </button>
                    <button type="button" class="btn btn-sm btn-primary download-btn"
                            disabled
                            data-session-token="${data.session_token}"
                            data-bs-toggle="tooltip"
                            data-bs-title="Download File">
                        <i class="fas fa-download"></i>
                    </button>                    
                    <button type="button" class="btn btn-sm btn-danger mark-failed-btn"
                            data-id="${data.id}"
                            data-bs-toggle="tooltip"
                            data-bs-title="Mark as Failed">
                        <i class="fas fa-times-circle"></i>
                    </button>
                </div>
            </td>
        `;

        const tooltips = tr.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltips.forEach(el => new bootstrap.Tooltip(el));

        this.initializeFileRowButtons(tr);

        return tr;
    }

    initializeFileRowButtons(row) {
        const verifyBtn = row.querySelector('.verify-btn');
        if (verifyBtn) {            
            verifyBtn.addEventListener('click', () => {
                const sessionToken = verifyBtn.dataset.sessionToken;
                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
                fetch(`/verify_file/${sessionToken}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    }
                }).then(response => {
                    if (response.ok) {
                        location.reload();
                    }
                });
            });
        }

        const downloadBtn = row.querySelector('.download-btn');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', async function() {
                if (!this.disabled) {
                    const sessionToken = this.dataset.sessionToken;
                    try {
                        const statusCell = row.querySelector('td:nth-child(4)');
                        if (statusCell) {
                            statusCell.innerHTML = `
                                <span class="status-badge status-downloaded">
                                    <i class="fas fa-download me-1"></i>
                                    Downloaded  
                                </span>
                            `;
                        }
                        window.open(`/download/${sessionToken}`, '_blank');
                    } catch (error) {
                        console.error('Download error:', error);
                        showAlert('danger', 'Error downloading file');
                    }
                }
            });
        }

        const markFailedBtn = row.querySelector('.mark-failed-btn');
        if (markFailedBtn) {
            markFailedBtn.addEventListener('click', () => {
                const fileId = markFailedBtn.dataset.id;
                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
                if (confirm('Are you sure you want to mark this file as failed?')) {                    
                    fetch(`/mark_file_failed/${fileId}`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': csrfToken
                        }
                    }).then(response => {
                        if (response.ok) {
                            console.log('File marked as failed');
                            const statusCell = row.querySelector('td:nth-child(4)');
                            if (statusCell) {
                                statusCell.innerHTML = `
                                    <span class="badge bg-danger">
                                        <i class="fas fa-exclamation-circle me-1"></i>
                                        Failed
                                    </span>
                                `;
                            }
                            const btnGroup = markFailedBtn.closest('.btn-group');
                            if (btnGroup) {
                                btnGroup.innerHTML = `
                                    <button class="btn btn-sm btn-primary" disabled>
                                        <i class="fas fa-download"></i>
                                    </button>
                                    <button class="btn btn-sm btn-danger" disabled>
                                        <i class="fas fa-times-circle me-1"></i>Failed
                                    </button>
                                `;
                            }
                            showAlert('warning', 'File marked as failed');
                        }
                    }).catch(error => {
                        console.error('Error marking file as failed:', error);
                        showAlert('danger', 'Error marking file as failed');
                    });
                }
            });
        }
    }

    getStatusBadgeClass(status) {
        const statusClasses = {
            'pending': 'warning',
            'completed': 'success',
            'failed': 'danger',
            'verified': 'info'
        };
        return statusClasses[status] || 'secondary';
    }

    capitalizeFirstLetter(str) {
        if (!str) return '';
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    getFileActions(file) {
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (file.status === 'Verified') {
            return `
                <a href="/download/${file.session_token}" class="btn btn-sm btn-success" target="_blank">
                    <i class="fas fa-download"></i> Download
                </a>
            `;
        } else {
            return `
                <form class="verify-form d-inline-block" action="/verify/${file.session_token}" method="POST">
                    <input type="hidden" name="csrf_token" value="${csrfToken}">
                    <button type="submit" class="btn btn-sm btn-primary">
                        <i class="fas fa-check-circle"></i> Verify
                    </button>
                </form>
            `;
        }
    }

    formatFileSize(bytes) {
        const units = ['B', 'KB', 'MB', 'GB'];
        let size = bytes;
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        return `${size.toFixed(2)} ${units[unitIndex]}`;
    }

    updateFileStatistics(newFileData) {
        const statsElements = {
            totalFiles: document.querySelector('.card-body .col-md-3:nth-child(1) h3'),
            totalSize: document.querySelector('.card-body .col-md-3:nth-child(2) h3'),
            uniqueSenders: document.querySelector('.card-body .col-md-3:nth-child(3) h3'),
            lastReceived: document.querySelector('.card-body .col-md-3:nth-child(4) h3')
        };

        if (!statsElements.totalFiles?.closest('.card')) {
            const statsCard = `
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-chart-bar me-2"></i>
                            Statistics
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row g-4">
                            <div class="col-md-3">
                                <div class="border rounded p-3 text-center">
                                    <h6 class="text-muted mb-2">Total Files</h6>
                                    <h3>1</h3>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="border rounded p-3 text-center">
                                    <h6 class="text-muted mb-2">Total Size</h6>
                                    <h3>${this.formatFileSize(newFileData.file_size)}</h3>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="border rounded p-3 text-center">
                                    <h6 class="text-muted mb-2">Unique Senders</h6>
                                    <h3>1</h3>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="border rounded p-3 text-center">
                                    <h6 class="text-muted mb-2">Last Received</h6>
                                    <h3>${new Date(newFileData.created_at).toLocaleDateString()}</h3>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            document.querySelector('.col-lg-10').insertAdjacentHTML('beforeend', statsCard);
            return;
        }

        if (statsElements.totalFiles) {
            const currentTotal = parseInt(statsElements.totalFiles.textContent);
            statsElements.totalFiles.textContent = (currentTotal + 1).toString();
        }

        if (statsElements.totalSize) {
            const currentSizeText = statsElements.totalSize.textContent;
            const currentSize = this.parseSizeToBytes(currentSizeText);
            statsElements.totalSize.textContent = this.formatFileSize(currentSize + newFileData.file_size);
        }

        if (statsElements.lastReceived) {
            statsElements.lastReceived.textContent = new Date(newFileData.created_at).toLocaleDateString();
        }
    }

    parseSizeToBytes(sizeStr) {
        const units = {
            'B': 1,
            'KB': 1024,
            'MB': 1024 * 1024,
            'GB': 1024 * 1024 * 1024,
            'TB': 1024 * 1024 * 1024 * 1024
        };
        const matches = sizeStr.match(/^([\d.]+)\s*([KMGT]?B)$/i);
        if (!matches) return 0;
        const [, size, unit] = matches;
        return parseFloat(size) * (units[unit] || 1);
    }

    getClientIP() {
        const ipMetaTag = document.querySelector('meta[name="client-ip"]');
        if (ipMetaTag) {
            return ipMetaTag.getAttribute('content');
        }
        console.warn('Client IP meta tag not found');
        return 'unknown';
    }

    getStatusIcon(status) {
        const icons = {
            'verified': 'check-circle',
            'downloaded': 'download',
            'failed': 'exclamation-circle',
            'pending': 'clock'
        };
        return icons[status] || 'question-circle';
    }
}

const notificationManager = {
    lastNotifications: {},
    debounceTime: 3000,

    canShow(message) {
        const now = Date.now();
        const lastTime = this.lastNotifications[message];
        
        if (!lastTime || (now - lastTime) > this.debounceTime) {
            this.lastNotifications[message] = now;
            return true;
        }
        return false;
    }
};

function showAlert(type, message) {
    if (!notificationManager.canShow(message)) {
        return;
    }

    const alertHtml = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    const container = document.querySelector('.container');
    container.insertAdjacentHTML('afterbegin', alertHtml);
    
    setTimeout(() => {
        const alert = container.querySelector('.alert');
        if (alert) {
            bootstrap.Alert.getOrCreateInstance(alert).close();
        }
    }, 5000);
}

const style = document.createElement('style');
style.textContent = `    .highlight {
        animation: highlight-fade 2s ease-in-out;
    }

    .highlight-success {
        animation: highlight-success-fade 2s ease-in-out;
    }

    .highlight-warning {
        animation: highlight-warning-fade 2s ease-in-out;
    }

    .highlight-danger {
        animation: highlight-danger-fade 2s ease-in-out;
    }
    
    @keyframes highlight-fade {
        0% { background-color: rgba(var(--bs-info-rgb), 0.3); }
        50% { background-color: rgba(var(--bs-info-rgb), 0.1); }
        100% { background-color: transparent; }
    }

    @keyframes highlight-success-fade {
        0% { background-color: rgba(var(--bs-success-rgb), 0.3); }
        50% { background-color: rgba(var(--bs-success-rgb), 0.1); }
        100% { background-color: transparent; }
    }

    @keyframes highlight-warning-fade {
        0% { background-color: rgba(var(--bs-warning-rgb), 0.3); }
        50% { background-color: rgba(var(--bs-warning-rgb), 0.1); }
        100% { background-color: transparent; }
    }

    @keyframes highlight-danger-fade {
        0% { background-color: rgba(var(--bs-danger-rgb), 0.3); }
        50% { background-color: rgba(var(--bs-danger-rgb), 0.1); }
        100% { background-color: transparent; }
    }

    .badge {
        transition: all 0.3s ease-in-out;
    }

    .badge.status-change {
        transform: scale(1.1);
    }
    
    /* Add subtle shadow effect during status change */
    tr.highlight, tr.highlight-success, tr.highlight-warning, tr.highlight-danger {
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
        position: relative;
        z-index: 1;
    }

    .highlight-success {
        background-color: rgba(40, 167, 69, 0.2) !important;
    }

    .highlight-warning {
        background-color: rgba(255, 193, 7, 0.2) !important;
    }

    .highlight-danger {
        background-color: rgba(220, 53, 69, 0.2) !important;
    }
`;
document.head.appendChild(style);

document.addEventListener('DOMContentLoaded', () => {
    window.realtimeClient = new RealtimeClient();
});