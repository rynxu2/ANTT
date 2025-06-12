import { formatFileSize } from './utils.js';

export class FileManager {
    constructor(socket) {
        this.socket = socket;
        this.processedFiles = new Set();
        this.setupFileEvents();
        this.setupBatchOperations();
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

        // 1. Cập nhật thống kê nếu status là 'verified'
        if (status === 'verified') this.incrementVerifiedCount();

        // 2. Tìm dòng file tương ứng
        const fileRow = document.querySelector(`tr[data-session-token="${session_token}"]`);
        if (!fileRow) return;

        // 3. Cập nhật trạng thái dòng
        this.updateStatusBadge(fileRow, status);

        // 4. Hiển thị thông báo
        this.notifyStatusChange(status);

        // 5. Nếu là trang receiver thì cập nhật action và bind modal
        if (window.location.pathname.includes('/receiver_files')) {
            this.updateActionButtons(fileRow, status);
            this.bindVerificationModal(fileRow, session_token);
        }

        // 6. Highlight dòng
        this.highlightRow(fileRow, status);
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

    notifyStatusChange(status) {
        const map = {
            verified: ['success', 'File has been verified successfully. Ready for download.', 'success'],
            downloaded: ['info', 'File has been downloaded by the recipient', 'info'],
            failed: ['warning', 'File marked as failed', 'error'],
            pending: ['warning', 'File is pending verification', null]
        };

        const [type, msg, sound] = map[status] || ['info', 'Unknown status', null];

        if (notificationManager.canShow(msg)) {
            if (sound && window.notificationSounds?.[sound]) {
                window.notificationSounds[sound].play().catch(console.log);
            }
        }
    }

    updateActionButtons(fileRow, status) {
        const actionCell = fileRow.querySelector('td:last-child');
        if (!actionCell) return;

        const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

        if (['verified', 'failed'].includes(status)) {
            actionCell.innerHTML = `
                <div class="text-center">
                    <button class="btn btn-sm btn-info verify-details-btn"
                            data-session-token="${csrf}"
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

        // 1. Hiện phần nội dung chính của modal
        this.showModalContent('verification-process');
        document.getElementById('verification-success')?.classList.remove('d-none');
        document.getElementById('downloadVerifiedBtn')?.classList.remove('d-none');
        document.getElementById('uploadDriveBtn')?.classList.remove('d-none');
        document.querySelector('.verification-head')?.classList.add('d-none');
        document.getElementById('proceedVerifyBtn')?.classList.add('d-none');

        // 2. Lặp qua các bước xác minh
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
                progressBar.style.stroke = '#dc3545'; // đỏ
                waitingIcon?.classList.add('d-none');
                errorIcon?.classList.remove('d-none');
                bgIcon?.classList.add('bg-danger');
                details.innerHTML = `<small class="text-danger">✗ ${errorMessage}</small>`;
                details.classList.remove('d-none');
            } else {
                step.classList.add('completed');
                progressBar.style.strokeDashoffset = '0';
                progressBar.style.stroke = '#198754'; // xanh lá
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

    setupBatchOperations() {
        // Select all checkbox
        const selectAllCheckbox = document.getElementById('select-all-files');
        if (selectAllCheckbox) {
            selectAllCheckbox.addEventListener('change', (e) => {
                document.querySelectorAll('.file-checkbox').forEach(checkbox => {
                    checkbox.checked = e.target.checked;
                });
                this.updateBatchButtons();
            });
        }

        // Individual checkboxes
        document.addEventListener('change', (e) => {
            if (e.target.classList.contains('file-checkbox')) {
                this.updateBatchButtons();
            }
        });

        // Batch operation buttons
        document.getElementById('batch-verify-btn')?.addEventListener('click', () => this.batchVerify());
        document.getElementById('batch-download-btn')?.addEventListener('click', () => this.batchDownload());
        document.getElementById('batch-drive-btn')?.addEventListener('click', () => this.batchUploadToDrive());
    }

    updateBatchButtons() {
        const selectedCheckboxes = document.querySelectorAll('.file-checkbox:checked');
        const selectedCount = selectedCheckboxes.length;
        const allCheckboxes = document.querySelectorAll('.file-checkbox');

        // Update select all checkbox state
        const selectAllCheckbox = document.getElementById('select-all-files');
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = selectedCount > 0 && selectedCount === allCheckboxes.length;
            selectAllCheckbox.indeterminate = selectedCount > 0 && selectedCount < allCheckboxes.length;
        }

        // Update batch action buttons
        const verifyBtn = document.getElementById('batch-verify-btn');
        const downloadBtn = document.getElementById('batch-download-btn');
        const driveBtn = document.getElementById('batch-drive-btn');

        const hasPendingFiles = Array.from(selectedCheckboxes).some(cb => cb.dataset.status === 'pending');
        const hasVerifiedFiles = Array.from(selectedCheckboxes).some(cb => cb.dataset.status === 'verified');

        if (verifyBtn) verifyBtn.disabled = !hasPendingFiles;
        if (downloadBtn) downloadBtn.disabled = !hasVerifiedFiles;
        if (driveBtn) driveBtn.disabled = !hasVerifiedFiles;
    }

    async batchVerify() {
        const pendingFiles = Array.from(document.querySelectorAll('.file-checkbox:checked'))
            .filter(cb => cb.dataset.status === 'pending')
            .map(cb => cb.dataset.sessionToken);

        if (!pendingFiles.length) return;

        try {
            for (const sessionToken of pendingFiles) {
                const response = await fetch(`/verify_file/${sessionToken}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
                    }
                });

                if (!response.ok) {
                    throw new Error(`Failed to verify file ${sessionToken}`);
                }
            }
            showAlert('success', `Successfully verified ${pendingFiles.length} files`);
        } catch (error) {
            console.error('Batch verification error:', error);
            showAlert('danger', 'Error during batch verification');
        }
    }

    batchDownload() {
        const verifiedFiles = Array.from(document.querySelectorAll('.file-checkbox:checked'))
            .filter(cb => cb.dataset.status === 'verified')
            .map(cb => cb.dataset.sessionToken);

        if (!verifiedFiles.length) return;

        verifiedFiles.forEach(sessionToken => {
            window.open(`/download/${sessionToken}`, '_blank');
        });
        
        showAlert('info', `Downloading ${verifiedFiles.length} files`);
    }

    async batchUploadToDrive() {
        const verifiedFiles = Array.from(document.querySelectorAll('.file-checkbox:checked'))
            .filter(cb => cb.dataset.status === 'verified')
            .map(cb => cb.dataset.fileId);

        if (!verifiedFiles.length) return;

        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

        try {
            for (const fileId of verifiedFiles) {
                const res = await fetch('/drive/upload', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-CSRFToken': csrfToken
                    },
                    body: `file_id=${fileId}`
                });

                if (!res.ok) {
                    throw new Error(`Failed to upload file ${fileId} to Drive`);
                }
            }
            showAlert('success', `Successfully uploaded ${verifiedFiles.length} files to Drive`);
        } catch (error) {
            console.error('Batch Drive upload error:', error);
            showAlert('danger', 'Error during batch upload to Drive');
        }
    }
}