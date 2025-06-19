export class RequestManager {
    constructor(socket) {
        this.socket = socket;
        this.setupRequestEvents();
    }
    
    setupRequestEvents() {
        this.socket.on('new_join_request', (data) => this.handleNewJoinRequest(data));
        this.socket.on('request_approved', (data) => this.handleRequestApproved(data));
        this.socket.on('request_rejected', (data) => this.handleRequestRejected(data));
        this.socket.on('access_revoked', (data) => this.handleAccessRevoked(data));
    }

    handleNewJoinRequest(data) {
        console.log('New join request received:', data);

        const cardBody = document.querySelector('.pending-requests.card-body');
        if (!cardBody) return;

        // Xóa thông báo rỗng nếu có
        const emptyMsg = cardBody.querySelector('.text-center');
        if (emptyMsg) emptyMsg.remove();

        // Đảm bảo container tồn tại
        let requestsList = cardBody.querySelector('.join-requests');
        if (!requestsList) {
            requestsList = document.createElement('div');
            requestsList.className = 'list-group join-requests gap-1';
            cardBody.appendChild(requestsList);
        }

        // Tạo HTML cho yêu cầu mới
        const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
        const newRequestHtml = this.getJoinRequestHtml(data, csrf);
        requestsList.insertAdjacentHTML('afterbegin', newRequestHtml);

        // Cập nhật badge đếm số lượng
        this.incrementPendingCount();

        // Gán sự kiện cho yêu cầu mới
        const newItem = requestsList.querySelector(`[data-request-id="${data.request_id}"]`);
        if (newItem) this.initializeRequestButtons(newItem);
    };

    getJoinRequestHtml(data, csrf) {
        return `
            <div class="list-group-item" data-request-id="${data.request_id}">
                <div class="d-flex align-items-center gap-3">
                    <div class="flex-shrink-0">
                        <i class="fas fa-user text-secondary"></i>
                    </div>
                    <div class="flex-grow-1">
                        <div class="d-flex justify-content-between align-items-center mb-1">
                            <div>
                                <span class="fw-medium">${data.sender_ip}</span>
                                <small class="text-muted ms-2">${data.created_at}</small>
                            </div>
                            <div class="d-flex gap-2">
                                <form action="/host/request/${data.request_id}/approve" method="POST" class="approve-form">
                                    <input type="hidden" name="csrf_token" value="${csrf}">
                                    <input type="hidden" name="message" value="Đồng ý!">
                                    <button type="submit" class="btn btn-sm btn-light text-success px-3" title="Duyệt">
                                        <i class="fas fa-check"></i>
                                    </button>
                                </form>
                                <form action="/host/request/${data.request_id}/reject" method="POST" class="reject-form">
                                    <input type="hidden" name="csrf_token" value="${csrf}">
                                    <button type="submit" class="btn btn-sm btn-light text-danger px-3" title="Từ chối">
                                        <i class="fas fa-times"></i>
                                    </button>
                                </form>
                            </div>
                        </div>
                        <div class="bg-light rounded px-3 py-2">
                            <code>${data.message}</code>
                        </div>
                    </div>
                </div>
            </div>
        `;
    };

    incrementPendingCount() {
        const pendingCount = document.querySelector('.pending-count');
        if (!pendingCount) return;

        const current = parseInt(pendingCount.textContent.match(/\d+/)?.[0] || '0');
        pendingCount.innerHTML = `
            <i class="fas fa-clock me-1"></i>
            ${current + 1} Đang chờ
        `;
    }

    initializeRequestButtons(requestElement) { 
        const approveBtn = requestElement.querySelector('.approve-request');
        const rejectBtn = requestElement.querySelector('.reject-request');
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

        if (approveBtn) {
            approveBtn.addEventListener('click', async () => {
                try {
                    const response = await fetch(`/host/request/${approveBtn.dataset.requestId}/approve`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': csrfToken
                        }
                    });

                    if (response.ok) {
                        requestElement.remove();
                        this.updatePendingCount(-1);
                    }
                } catch (error) {
                    console.error('Error approving request:', error);
                }
            });
        }

        if (rejectBtn) {
            rejectBtn.addEventListener('click', async () => {
                try {
                    const response = await fetch(`/host/request/${rejectBtn.dataset.requestId}/reject`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': csrfToken
                        }
                    });

                    if (response.ok) {
                        requestElement.remove();
                        this.updatePendingCount(-1);
                    }
                } catch (error) {
                    console.error('Error rejecting request:', error);
                }
            });
        }
    }

    updateHostStatus(hostId, html) {
        const hostCard = document.querySelector(`[data-host-id="${hostId}"]`);
        if (!hostCard) return;

        const statusArea = hostCard.querySelector('.status-area');
        if (statusArea) {
            statusArea.innerHTML = html;
        }
    }

    handleRequestApproved(data) {
        const html = `
            <div class="mb-2">
                <span class="badge bg-success d-block p-2 mb-2">
                    <i class="fas fa-check-circle me-1"></i>
                    Đã duyệt ${data.approved_at}
                </span>
                <form action="/select_host/${data.host_id}" method="POST" class="select-host-form">
                    <input type="hidden" name="csrf_token" value="${this.getCsrfToken()}">
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="fas fa-upload me-2"></i>
                        Chọn Host này
                    </button>
                </form>
            </div>
        `;
        this.updateHostStatus(data.host_id, html);
    }

    handleRequestRejected(data) {
        const now = new Date();
        const html = `
            <div class="alert alert-danger mb-2">
                <div class="d-flex align-items-center mb-2">
                    <i class="fas fa-times-circle text-danger me-2"></i>
                    <strong>Yêu cầu bị từ chối</strong>
                </div>
                <small class="d-block text-muted mb-2">
                    Đã từ chối: ${now.toLocaleDateString()} ${now.toLocaleTimeString()}
                </small>
            </div>
            <form action="/host/${data.host_id}/request_join" method="POST" class="join-host-form">
                <input type="hidden" name="csrf_token" value="${this.getCsrfToken()}">
                <button type="submit" class="btn btn-outline-primary w-100">
                    <i class="fas fa-redo me-1"></i>
                    Gửi lại yêu cầu
                </button>
            </form>
        `;
        this.updateHostStatus(data.host_id, html);
    }

    handleAccessRevoked(data) {
        const now = new Date();
        const html = `
            <div class="alert alert-secondary mb-2">
                <div class="d-flex align-items-center mb-2">
                    <i class="fas fa-ban text-secondary me-2"></i>
                    <strong>Đã thu hồi quyền truy cập</strong>
                </div>
                <small class="d-block text-muted mb-2">
                    Đã thu hồi: ${now.toLocaleDateString()} ${now.toLocaleTimeString()}
                </small>
            </div>
            <form action="/host/${data.host_id}/request_join" method="POST" class="join-host-form">
                <input type="hidden" name="csrf_token" value="${this.getCsrfToken()}">
                <button type="submit" class="btn btn-outline-primary w-100">
                    <i class="fas fa-redo me-1"></i>
                    Gửi lại yêu cầu
                </button>
            </form>
        `;
        this.updateHostStatus(data.host_id, html);
    }

    getCsrfToken() {
        return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    }
}