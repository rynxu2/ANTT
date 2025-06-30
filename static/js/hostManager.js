export class HostManager {
    constructor(socket) {
        this.socket = socket;
        this.setupHostEvents();
    }
    
    setupHostEvents() {
        this.socket.on('new_host', this.handleNewHost);
        this.socket.on('host_deleted', this.handleHostDeleted);
    }

    handleNewHost = (data) => {
        console.log('New host received:', data);
        if (document.querySelector(`[data-host-id="${data.id}"]`)) {
            console.log(`Host ${data.id} already exists`);
            return;
        }

        this.renderHostInListView(data);
        this.renderHostInSelectView(data);
    };

    renderHostInListView = (data) => {
        const hostsList = document.querySelector('.hosts-list');
        if (!hostsList) return;

        const hostHtml = `
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
                            <small class="text-muted">Thêm bởi ${data.created_by}</small>
                            <button class="btn btn-sm btn-outline-danger delete-recipient" data-id="${data.id}">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        hostsList.insertAdjacentHTML('afterbegin', hostHtml);

        const deleteBtn = hostsList.querySelector(`[data-id="${data.id}"]`);
        if (deleteBtn) {
            deleteBtn.addEventListener('click', () => {
                if (confirm('Bạn có chắc muốn xóa người nhận này?')) {
                    deleteRecipient(data.id);
                }
            });
        }
    }

    renderHostInSelectView = (data) => {
        const isSelectHostPage = window.location.pathname.endsWith('/sender_select_host');
        if (!isSelectHostPage) return;

        const cardBody = document.querySelector('.card:not(.mb-4) .card-body');
        if (!cardBody) return;

        const hostHtml = `
            <div class="col" data-host-id="${data.id}">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title">${data.name}</h5>
                        <p class="card-text">
                            <small class="text-muted">IP: <code>${data.ip_address}</code></small>
                        </p>
                        ${data.description ? `<p class="card-text">${data.description}</p>` : ''}
                        <div class="mt-3">
                            ${data.has_keys ? `
                                <form action="/host/${data.id}/request_join" method="POST" class="join-host-form">
                                    <input type="hidden" name="csrf_token" value="${document.querySelector('meta[name="csrf-token"]')?.content}">
                                    <input type="hidden" name="message" value="Hello! ${this.getClientIP()}">
                                    <button type="submit" class="btn btn-outline-primary w-100">
                                        <i class="fas fa-paper-plane me-1"></i>
                                        Gửi yêu cầu truy cập
                                    </button>
                                </form>
                            ` : `
                                <button class="btn btn-warning w-100" disabled>
                                    <i class="fas fa-exclamation-triangle me-2"></i>
                                    Chưa có Public Key
                                </button>
                            `}
                        </div>
                    </div>
                </div>
            </div>
        `;

        let hostContainer = cardBody.querySelector('.row.row-cols-1.row-cols-md-2.row-cols-lg-3.g-4');
        const emptyState = cardBody.querySelector('.text-center');

        if (!hostContainer) {
            if (emptyState) emptyState.remove();
            hostContainer = document.createElement('div');
            hostContainer.className = 'row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4';
            cardBody.appendChild(hostContainer);
        }

        hostContainer.insertAdjacentHTML('afterbegin', hostHtml);
    }

    handleHostDeleted = (data) => {
        const isSelectHostPage = !!window.location.pathname.endsWith('/sender_select_host');

        if (isSelectHostPage) {
            const form = document.querySelector(`div.col[data-host-id="${data.id}"]`);
            if (form) form.remove();

            const hostGrid = document.querySelector('.row.row-cols-1.row-cols-md-2.row-cols-lg-3.g-4');

            if (hostGrid && hostGrid.children.length === 0) {
                const cardBody = hostGrid.parentElement;
                hostGrid.remove();

                const emptyHTML = `
                    <div class="text-center">
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            Không có host nào sẵn sàng để gửi file. Hãy yêu cầu người nhận đăng ký làm host trước.
                        </div>
                        <img src="{{ url_for('static', filename='images/empty-hosts.svg') }}" alt="No hosts" class="img-fluid mb-3" style="max-width: 200px;">
                        <p class="text-muted">
                            Để gửi file, bạn cần người nhận đã đăng ký làm host. Khi họ đăng ký, host của họ sẽ xuất hiện tại đây.
                        </p>
                    </div>
                `;

                cardBody.innerHTML = emptyHTML;
            }
        }

        const hostsList = document.querySelector('.hosts-list');
        if (hostsList) {
            const hostCol = hostsList.querySelector(`[data-id="${data.id}"]`)?.closest('.col-md-6');
            if (hostCol) hostCol.remove();
        }
    }

    getClientIP() {
        const ipMetaTag = document.querySelector('meta[name="client-ip"]');
        if (ipMetaTag) {
            return ipMetaTag.getAttribute('content');
        }
        console.warn('Client IP meta tag not found');
        return 'unknown';
    }
}