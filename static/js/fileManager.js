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
    }

    createFileTable() {
        const table = document.createElement('table');
        table.className = 'table table-hover align-middle mb-0';
        table.id = "table-received-files";
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
        tr.dataset.sessionToken = data.session_token;
        tr.dataset.fileId = data.id;

        const formattedDate = new Date(data.created_at).toLocaleString('en-US', {
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
                    <i class="fas fa-clock me-1"></i> Pending
                </span>
            </td>
            <td class="text-end">
                <div class="action-btn" style="display: flex; gap: 3px; justify-content: center;">
                    <button type="submit" class="btn btn-sm btn-success verify-btn"
                            data-csrf-token="${document.querySelector('meta[name="csrf-token"]')?.content}"
                            data-session-token="${data.session_token}"
                            data-file-id="${data.id}"
                            data-bs-toggle="tooltip"
                            data-bs-title="Verify File">
                        <i class="fas fa-check"></i>
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
            this.bindVerificationModal(fileRow, session_token);
        }
    }

    incrementVerifiedCount() {
        const el = document.querySelector('.stat-card-completed');
        if (!el) return;
        el.textContent = (parseInt(el.textContent) || 0) + 1;
    }

    updateStatusBadge(fileRow, status) {
        const statusCell = fileRow.querySelector('td:nth-child(4)');
        if (!statusCell) return;

        const config = {
            verified: ['check-circle', 'Verified'],
            downloaded: ['download', 'Downloaded'],
            failed: ['times-circle', 'Failed'],
            pending: ['clock', 'Pending']
        }[status] || ['question-circle', 'Unknown'];

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

        if (['verified', 'failed'].includes(status)) {
            actionCell.innerHTML = `
                <div class="text-center">
                    <button class="btn btn-sm btn-info verify-details-btn"
                            data-session-token="${fileRow.dataset.sessionToken}"
                            data-file-id="${fileRow.dataset.fileId}"
                            data-bs-toggle="tooltip" 
                            data-bs-title="View Verification Details">
                        <i class="fas fa-shield-alt"></i>
                    </button>
                </div>`;
        }
    }

    bindVerificationModal(fileRow, sessionToken) {
        const btn = fileRow.querySelector('.verify-details-btn');
        if (!btn) return;

        const modal = new bootstrap.Modal(document.getElementById('verificationModal'));

        btn.addEventListener('click', async () => {
            try {
                const res = await fetch(`/file_metadata/${sessionToken}`);
                const data = await res.json();

                this.showVerificationSteps(data);
                modal.show();
            } catch (e) {
                alert('Error fetching metadata: ' + e.message);
            }
        });
    }

    showVerificationSteps(data) {
        const {
            status,
            fail_step: errorStep = null,
            error_message: errorMessage = ''
        } = data;

        this.showModalContent('verification-process');
        document.getElementById('verification-success')?.classList.remove('d-none');
        document.getElementById('downloadVerifiedBtn')?.classList.remove('d-none');
        document.querySelector('.verification-head')?.classList.add('d-none');
        document.getElementById('proceedVerifyBtn')?.classList.add('d-none');

        document.querySelectorAll('.verification-step').forEach(step => {
            const stepId = step.id;
            const progressBar = step.querySelector('.progress-ring-bar');
            const waitingIcon = step.querySelector('.step-waiting');
            const successIcon = step.querySelector('.step-success');
            const errorIcon = step.querySelector('.step-error');
            const bgIcon = step.querySelector('.step-icon');
            const details = step.querySelector('.step-details');

            step.style.opacity = '1';
            if (stepId === errorStep) {
                step.classList.add('error');
                progressBar.style.strokeDashoffset = '0';
                progressBar.style.stroke = '#dc3545';
                waitingIcon?.classList.add('d-none');
                errorIcon?.classList.remove('d-none');
                bgIcon?.classList.add('bg-danger');
                details.innerHTML = `<small class="text-danger">✗ ${errorMessage}</small>`;
                details.classList.remove('d-none');
            } else {
                step.classList.add('completed');
                progressBar.style.strokeDashoffset = '0';
                progressBar.style.stroke = '#198754';
                waitingIcon?.classList.add('d-none');
                successIcon?.classList.remove('d-none');
                bgIcon?.classList.add('bg-success');
            }
        });
    }

    showModalContent(contentClass) {
        ['verification-info', 'verification-process', 'verification-error'].forEach(cls => {
            document.querySelector(`.${cls}`)?.classList.add('d-none');
        });
        document.querySelector(`.${contentClass}`)?.classList.remove('d-none');
        if (contentClass !== 'verification-process') {
            document.getElementById('verification-success')?.classList.add('d-none');
        }
    }
}