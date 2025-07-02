import { formatFileSize } from './utils.js';

export class FileManager {
    constructor(socket) {
        this.socket = socket;
        this.processedFiles = new Set();
        this.setupFileEvents();
    }
    
    setupFileEvents() {
        this.socket.on('new_file', (data) => this.handleNewFile(data));
        this.socket.on('status_change', (data) => this.handleStatusChange(data));
    }

    handleNewFile(data) {
        console.log("New file received:", data);
        if (!window.location.pathname.includes('/receiver_files')) return;

        const fileKey = `${data.session_token}-${data.created_at}`;
        if (this.processedFiles.has(fileKey)) return;

        this.processedFiles.add(fileKey);
        setTimeout(() => this.processedFiles.delete(fileKey), 5000);

        document.querySelector('.empty-state')?.classList.add('d-none');

        let tableContainer = document.querySelector('.table-responsive');
        if (!tableContainer) {
            tableContainer = document.createElement('div');
            tableContainer.className = 'table-responsive';
            document.querySelector('.card-body')?.appendChild(tableContainer);
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

        const stats = document.querySelectorAll('#received-files-container .stat-card .stat-info strong');
        if (stats) {
            stats.forEach((el, index) => {
                let oldValue = parseInt(el.textContent.replace(' Bytes', '')) || 0;
                switch (index) {
                    case 0:
                        el.textContent = (parseInt(el.textContent) || 0) + 1;
                        break;
                    case 1:
                        el.textContent = formatFileSize(this.parseSizeToBytes(oldValue) + data.file_size);
                        break;
                    case 2:
                        break;
                    default:
                        break;
                }
            });
        }
    }

    parseSizeToBytes(sizeStr) {
        const units = {
            b: 1,
            kb: 1024,
            mb: 1024 ** 2,
            gb: 1024 ** 3,
            tb: 1024 ** 4
        };
        
        try {
            const regex = /^([\d.]+)\s*(b|kb|mb|gb|tb)$/i;
            const match = sizeStr.trim().toLowerCase().match(regex);

            if (!match) return sizeStr;
        } catch (e) {
            return sizeStr;
        }

        const value = parseFloat(match[1]);
        const unit = match[2];

        return Math.round(value * units[unit]);
    }

    createFileTable() {
        const table = document.createElement('table');
        table.className = 'table table-hover align-middle mb-0';
        table.id = "table-received-files";
        table.innerHTML = `
            <thead>
                <tr>
                    <th style="width: 35%">Tên file</th>
                    <th style="width: 20%">Người gửi</th>
                    <th style="width: 15%">Dung lượng</th>
                    <th style="width: 20%">Trạng thái</th>
                    <th style="width: 15%" class="text-end">Hành động</th>
                </tr>
            </thead>
            <tbody></tbody>
        `;

        return table;
    }

    createFileRow(data) {
        const tr = document.createElement('tr');
        tr.dataset.sessionToken = data.session_token;
        tr.dataset.fileId = data.id;

        const formattedDate = new Date(data.created_at).toLocaleString('vi-VN', {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit'
        });

        tr.innerHTML = `
            <td>
                <div class="d-flex align-items-center">
                    <div class="file-icon me-3"><i class="fas fa-file-alt"></i></div>
                    <div class="file-info">
                        <div class="file-name">${data.filename}</div>
                        <div class="file-date text-muted small">${formattedDate}</div>
                    </div>
                </div>
            </td>
            <td>
                <div class="d-flex align-items-center">
                    <div class="sender-avatar me-2"><i class="fas fa-user"></i></div>
                    <code class="sender-ip">${data.sender_ip}</code>
                </div>
            </td>
            <td>${formatFileSize(data.file_size)}</td>
            <td>
                <span class="status-badge status-pending">
                    <i class="fas fa-clock me-1"></i> Đang chờ
                </span>
            </td>
            <td class="text-end">
                <div class="action-btn" style="display: flex; gap: 3px; justify-content: center;">
                    <button type="submit" class="btn btn-sm btn-success verify-btn"
                            data-csrf-token="${document.querySelector('meta[name="csrf-token"]')?.content}"
                            data-session-token="${data.session_token}"
                            data-file-id="${data.id}"
                            data-bs-toggle="tooltip"
                            data-bs-title="Xác thực file">
                        <i class="fas fa-check"></i>
                    </button>
                    <button type="button" class="btn btn-sm btn-outline-primary download-btn"
                            data-session-token="${data.session_token}"
                            data-file-id="${data.id}"
                            data-host-id="${data.receiver_ip}"
                            data-status="pending"
                            data-bs-toggle="tooltip"
                            data-bs-title="Tải file mã hóa">
                        <i class="fas fa-lock"></i>
                    </button>
                </div>
            </td>
        `;

        return tr;
    }

    handleStatusChange(data) {
        console.log("Status change received:", data);
        const { session_token, status } = data;

        if (status === 'verified') this.incrementVerifiedCount();

        const fileRow = document.querySelector(`tr[data-session-token="${session_token}"]`);
        if (!fileRow) return;

        this.updateStatusBadge(fileRow, status);

        if (window.location.pathname.includes('/receiver_files')) {
            this.updateActionButtons(fileRow, status);
        }
    }

    incrementVerifiedCount() {
        if (window.location.pathname.includes('/receiver_files')) {
            const el = document.querySelector('#received-files-container .row .col-md-4:last-child strong');
            if (!el) return;
            el.textContent = (parseInt(el.textContent) || 0) + 1;
        };
        if (window.location.pathname.includes('/sender')) {
            const verifiedCountEl = document.querySelector('.stat-card-completed');
            if (verifiedCountEl) {
                verifiedCountEl.textContent = (parseInt(verifiedCountEl.textContent) || 0) + 1;
            }
        };
    }

    updateStatusBadge(fileRow, status) {
        const statusCell = fileRow.querySelector('td:nth-child(4)');
        if (!statusCell) return;

        const config = {
            verified: ['check-circle', 'Đã xác thực'],
            downloaded: ['download', 'Đã tải về'],
            failed: ['times-circle', 'Lỗi'],
            pending: ['clock', 'Đang chờ']
        }[status] || ['question-circle', 'Không xác định']; 

        const [icon, text] = config;

        const html = `
            <span class="status-badge status-${status}">
                <i class="fas fa-${icon} me-1"></i>${text}
            </span>`;

        statusCell.innerHTML = html;
    }

    updateActionButtons(fileRow, status) {
        const actionCell = fileRow.querySelector('td:last-child');
        if (!actionCell) return;

        if (['verified', 'downloaded'].includes(status)) {
            actionCell.innerHTML = `
                <div class="text-center">
                    <button class="btn btn-sm btn-info verify-details-btn"
                            data-session-token="${fileRow.dataset.sessionToken}"
                            data-file-id="${fileRow.dataset.fileId}"
                            data-bs-toggle="tooltip" 
                            data-bs-title="Xem chi tiết xác thực">
                        <i class="fas fa-shield-alt"></i>
                    </button>
                    <button type="button" class="btn btn-sm btn-outline-primary download-btn"
                            data-session-token="${fileRow.dataset.sessionToken}"
                            data-file-id="${fileRow.dataset.fileId}"
                            data-host-id="${fileRow.dataset.hostId}"
                            data-status="${status}"
                            data-bs-toggle="tooltip"
                            data-bs-title="Tải file đã giải mã">
                        <i class="fas fa-download"></i>
                    </button>
                </div>`;
        }
        else if (['failed', 'pending'].includes(status)) {
            actionCell.innerHTML = `
                <div class="text-center">
                    <button class="btn btn-sm btn-danger verify-details-btn"
                            data-session-token="${fileRow.dataset.sessionToken}"
                            data-file-id="${fileRow.dataset.fileId}"
                            data-bs-toggle="tooltip" 
                            data-bs-title="Xem chi tiết xác thực">
                        <i class="fas fa-exclamation-triangle"></i>
                    </button>
                    <button type="button" class="btn btn-sm btn-outline-primary download-btn"
                            data-session-token="${fileRow.dataset.sessionToken}"
                            data-file-id="${fileRow.dataset.fileId}"
                            data-host-id="${fileRow.dataset.hostId}"
                            data-status="${status}"
                            data-bs-toggle="tooltip"
                            data-bs-title="Tải file mã hóa">
                        <i class="fas fa-lock"></i>
                    </button>
                </div>`;
        }
    }
}