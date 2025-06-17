class SecureUploadClient {
    constructor() {
        const data = window.serverData || {};
        this.clientIP = data.clientIP || '';
        this.hasKeys = data.hasKeys || false;
        this.serverPublicKey = data.publicKey || null;
        this.selectedHost = data.selectedHost || null;

        this.initEvents();
    }

    initEvents() {
        document.getElementById('generateKeysBtn')?.addEventListener('click', () => this.generateKeys());
        document.getElementById('uploadForm')?.addEventListener('submit', (e) => this.handleFileUpload(e));
    }

    async generateKeys() {
        const btn = document.getElementById('generateKeysBtn');
        const originalText = btn.innerHTML;

        try {
            btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Generating...';
            btn.disabled = true;

            const res = await fetch('/generate_keys', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
            const result = await res.json();

            if (result.success) setTimeout(() => location.reload(), 1000);

        } catch (error) {
            console.error('Key generation failed:', error);
        } finally {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    }

    async handleFileUpload(e) {
        e.preventDefault();
        const uploadBtn = document.querySelector('#uploadBtn');
        const fileInput = document.getElementById('fileInput');
        const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
        const fileSource = document.querySelector('input[name="fileSource"]:checked')?.value;

        const loadingOverlay = document.getElementById('loading-overlay');
        loadingOverlay?.classList.remove('d-none');

        const originalText = uploadBtn.innerHTML;
        uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Uploading...';
        uploadBtn.disabled = true;

        try {
            if (fileSource === 'local' && !this.hasKeys) {
                const file = fileInput?.files[0];
                if (!file) return;

                const allowedTypes = [
                    'application/pdf',
                    'application/msword',
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                ];
                const allowedExts = ['.pdf', '.doc', '.docx'];
                const fileName = file.name.toLowerCase();
                const isValidType = allowedTypes.includes(file.type);
                const isValidExt = allowedExts.some(ext => fileName.endsWith(ext));
                if (!isValidType && !isValidExt) {
                    alert('Only PDF, DOC, DOCX files are allowed.');
                    uploadBtn.innerHTML = originalText;
                    uploadBtn.disabled = false;
                    loadingOverlay?.classList.add('d-none');
                    return;
                }

                const formData = new FormData();
                formData.append('file', file);

                const res = await fetch('/upload', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken },
                    body: formData
                });

                const result = await res.json();
                if (res.ok) {
                    this.showUploadSuccess(result);
                    fileInput.value = '';
                } else {
                    const msg = result.error || 'Upload failed';
                }
            }
        } catch (err) {
            console.error('Upload error:', err);
        } finally {
            loadingOverlay?.classList.add('d-none');
            uploadBtn.innerHTML = originalText;
            uploadBtn.disabled = false;
        }
    }

    showUploadSuccess(result) {
        const setText = (id, value) => document.getElementById(id).textContent = value;
        setText('sessionToken', result.session_token);
        setText('fileHash', result.file_hash);
        setText('iv', result.metadata.iv);
        setText('publicKey', result.metadata.public_key);
        setText('hashType', result.metadata.hash_type);

        document.querySelector('.step.active')?.classList.replace('active', 'completed');
        document.querySelector('.step:last-child')?.classList.add('active');
        document.getElementById('uploadForm').style.display = 'none';
        document.getElementById('successInfo').classList.remove('d-none');
        document.querySelector('#headerbar .col:last-child .step')?.classList.add('completed');
    }

    generateRandomKey(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    }

    readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(new Uint8Array(reader.result));
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }

    simulateAESEncryption(data, key, iv) { return Promise.resolve(data); }
    simulateSignature(data) { return Promise.resolve(this.generateRandomKey(128)); }
    simulateRSAEncryption(data) { return Promise.resolve(this.generateRandomKey(128)); }

    async calculateSHA512(data) {
        try {
            return CryptoJS.SHA512(CryptoJS.lib.WordArray.create(data)).toString(CryptoJS.enc.Hex);
        } catch (e) {
            throw e;
        }
    }

    arrayBufferToBase64(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }

    showProgress(percentage, text) {
        const container = document.getElementById('uploadProgress');
        container.style.display = 'block';
        document.getElementById('progressBar').style.width = `${percentage}%`;
        document.getElementById('progressBar').setAttribute('aria-valuenow', percentage);
        document.getElementById('progressText').textContent = text;
        if (percentage === 100) setTimeout(() => container.style.display = 'none', 2000);
    }

    showUploadResult(type, result) {
        const container = document.getElementById('uploadResult');
        const isSuccess = type === 'success';
        const alertClass = isSuccess ? 'alert-success' : 'alert-danger';
        const icon = isSuccess ? 'fa-check-circle' : 'fa-exclamation-circle';

        container.innerHTML = `
            <div class="alert ${alertClass}">
                <i class="fas ${icon} me-2"></i>
                <strong>${isSuccess ? 'Success!' : 'Error!'}</strong>
                <p class="mb-0">${result.message}</p>
                ${isSuccess ? `
                    <hr>
                    <small>
                        <strong>Session Token:</strong> <code>${result.session_token}</code><br>
                        <strong>Filename:</strong> ${result.filename}<br>
                        <strong>Decrypted Size:</strong> ${result.file_size} bytes
                    </small>` : ''}
            </div>
        `;
        container.style.display = 'block';
        container.scrollIntoView({ behavior: 'smooth' });
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => console.log('Copied to clipboard')).catch(console.error);
}

async function addRecipient(ip, name) {
    try {
        const res = await fetch('/add_recipient', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, name })
        });
        const result = await res.json();
        if (result.success) location.reload();
        else alert('Error: ' + result.message);
    } catch (e) {
        console.error('Add error:', e);
        alert('Failed to add recipient');
    }
}

async function deleteRecipient(id) {
    try {
        const res = await fetch(`/delete_recipient/${id}`, { method: 'DELETE' });
        const result = await res.json();
        if (result.success) location.reload();
        else alert('Error: ' + result.message);
    } catch (e) {
        console.error('Delete error:', e);
        alert('Failed to delete recipient');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new SecureUploadClient();

    const form = document.getElementById('addRecipientForm');
    form?.addEventListener('submit', e => {
        e.preventDefault();
        const ip = document.getElementById('recipientIp').value;
        const name = document.getElementById('recipientName').value;
        addRecipient(ip, name);
    });

    document.querySelectorAll('.delete-recipient').forEach(button => {
        button.addEventListener('click', () => {
            const id = button.dataset.id;
            if (confirm('Are you sure you want to delete this recipient?')) {
                deleteRecipient(id);
            }
        });
    });
});