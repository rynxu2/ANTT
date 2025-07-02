class SecureUploadClient {
    constructor() {
        const data = window.serverData || {};
        this.clientIP = data.clientIP || '';
        this.hasKeys = data.hasKeys || false;
        this.selectedHost = data.selectedHost || null;

        this.initEvents();
    }

    initEvents() {
        document.getElementById('generateKeysBtn')?.addEventListener('click', () => this.generateKeys());
        document.getElementById('uploadForm')?.addEventListener('submit', (e) => this.handleFileUpload(e));
    }

    async handleFileUpload(e) {
        e.preventDefault();
        const uploadBtn = document.querySelector('#uploadBtn');
        const fileInput = document.getElementById('fileInput');
        const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
        const fileSource = document.querySelector('input[name="fileSource"]:checked')?.value;
        const host_name = document.querySelector('input[name="host_name"]')?.value;
        const loadingOverlay = document.getElementById('loading-overlay');

        loadingOverlay?.classList.remove('d-none');
        const originalText = uploadBtn.innerHTML;
        uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Uploading...';
        uploadBtn.disabled = true;
        try {
            if (fileSource === 'local') {
                const file = fileInput?.files[0];
                if (!file) return;
                // Validate file type
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
                // 1. Read file as ArrayBuffer
                const fileBuffer = await this.readFileAsArrayBuffer(file);
                // 2. Generate AES-CBC key and IV
                const aesKey = await window.crypto.subtle.generateKey(
                    { name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']
                );
                const iv = window.crypto.getRandomValues(new Uint8Array(16));
                // 3. Encrypt file (AES-CBC)
                const encryptedContent = await window.crypto.subtle.encrypt(
                    { name: 'AES-CBC', iv }, aesKey, fileBuffer
                );
                // 4. Export and encrypt AES key with recipient's public key (RSA-OAEP + SHA-512)
                const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
                const recipientPublicKeyPem = this.getHostPublicKey();
                if (!recipientPublicKeyPem) {
                    console.error('Recipient public key is missing or invalid.');
                    throw new Error('Recipient public key is missing or invalid.');
                }
                const recipientPublicKey = await this.importRsaPublicKey(recipientPublicKeyPem, 'SHA-512');
                const encryptedSessionKey = await window.crypto.subtle.encrypt(
                    { name: 'RSA-OAEP' }, recipientPublicKey, exportedAesKey
                );
                // 5. Hash file (SHA-512(IV || ciphertext))
                const ivAndCipher = new Uint8Array(iv.length + encryptedContent.byteLength);
                ivAndCipher.set(iv, 0);
                ivAndCipher.set(new Uint8Array(encryptedContent), iv.length);
                const fileHash = await this.calculateSHA512(ivAndCipher.buffer);
                // 6. Metadata: filename, timestamp, sender_ip
                const senderIp = await this.get_ip();
                const metadata = {
                    filename: file.name,
                    timestamp: new Date().toISOString(),
                    sender_ip: senderIp,
                };
                // 7. Ký số metadata bằng private key RSA/SHA-512
                const privateKeyPem = localStorage.getItem('rsa_sender_private_key_pem');
                if (!privateKeyPem) {
                    alert('Không tìm thấy private key trên trình duyệt.');
                    return;
                }
                const privateKey = await this.importRsaPrivateKey(privateKeyPem, 'SHA-512');
                const metadataString = JSON.stringify(metadata);
                const encoder = new TextEncoder();
                const metadataBytes = encoder.encode(metadataString);
                const signature = await window.crypto.subtle.sign(
                    { name: 'RSASSA-PKCS1-v1_5' },
                    privateKey,
                    metadataBytes
                );
                // 8. Prepare FormData (gói tin đúng yêu cầu)
                const formData = new FormData();
                formData.append('iv', this.arrayBufferToBase64(iv));
                formData.append('hash', fileHash);
                formData.append('sig', this.arrayBufferToBase64(signature));
                formData.append('encrypted_session_key', this.arrayBufferToBase64(encryptedSessionKey));
                formData.append('metadata', metadataString);
                formData.append('file', new Blob([encryptedContent]), file.name);
                // 9. Send to server
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
                    alert(msg);
                }
            }
        } catch (err) {
            console.error('Upload error:', err);
            alert('Upload error: ' + err.message);
        } finally {
            loadingOverlay?.classList.add('d-none');
            uploadBtn.innerHTML = originalText;
            uploadBtn.disabled = false;
        }
    }

    async get_ip() {
        try {
            const responsive = await fetch('/get_ip');
            if (!responsive.ok) {
                throw new Error('Failed to fetch IP address');
            } 
            const data = await responsive.json();
            return data.ip_address || '';
        } catch (error) {
            console.error('Error fetching IP address:', error);
            return '';
        }
    }

    getHostPublicKey() {
        const publicKeyInput = document.querySelector(`input[name="host_public_key"]`);
        const publicKeyPem = publicKeyInput ? publicKeyInput.value : null;
        return publicKeyPem;
    }

    showUploadSuccess(result) {
        const setText = (id, value) => document.getElementById(id).textContent = value;
        setText('sessionToken', result.session_token);
        setText('fileHash', result.file_hash);
        setText('iv', result.metadata.iv);
        setText('signature', result.metadata.metadata_signature);

        document.querySelector('.step.active')?.classList.replace('active', 'completed');
        document.querySelector('.step:last-child')?.classList.add('active');
        document.getElementById('uploadForm').style.display = 'none';
        document.getElementById('successInfo').classList.remove('d-none');
        document.querySelector('#headerbar .col:last-child .step')?.classList.add('completed');
    }

    async importRsaPublicKey(pem, hashAlg = 'SHA-512') {
        if (!pem) {
            throw new Error('Public key PEM is null or undefined.');
        }
        // Remove header/footer and newlines
        const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
        const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        return window.crypto.subtle.importKey(
            'spki', der.buffer, { name: 'RSA-OAEP', hash: { name: hashAlg } }, true, ['encrypt']
        );
    }

    async importRsaPrivateKey(pem, hashAlg = 'SHA-512') {
        if (!pem) {
            throw new Error('Private key PEM is null or undefined.');
        }
        // Remove header/footer and newlines
        const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
        const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        return window.crypto.subtle.importKey(
            'pkcs8', der.buffer, { name: 'RSASSA-PKCS1-v1_5', hash: { name: hashAlg } }, true, ['sign']
        );
    }

    async calculateSHA512(buffer) {
        const hashBuffer = await window.crypto.subtle.digest('SHA-512', buffer);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
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

    readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => console.log('Copied to clipboard')).catch(console.error);
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