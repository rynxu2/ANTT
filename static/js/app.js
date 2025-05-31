class SecureUploadClient {
    constructor() {
        this.clientIP = window.serverData?.clientIP || '';
        this.hasKeys = window.serverData?.hasKeys || false;
        this.serverPublicKey = window.serverData?.publicKey || null;
        this.selectedHost = window.serverData?.selectedHost || null;
        
        this.initializeEventListeners();
    }
    
    initializeEventListeners() {
        const generateKeysBtn = document.getElementById('generateKeysBtn');
        if (generateKeysBtn) {
            generateKeysBtn.addEventListener('click', () => this.generateKeys());
        }
        
        const uploadForm = document.getElementById('uploadForm');
        if (uploadForm) {
            uploadForm.addEventListener('submit', (e) => this.handleFileUpload(e));
        }
    }
    
    async generateKeys() {
        const btn = document.getElementById('generateKeysBtn');
        const originalText = btn.innerHTML;
        
        try {
            btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Generating...';
            btn.disabled = true;
            
            const response = await fetch('/generate_keys', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showAlert('success', result.message);
                setTimeout(() => location.reload(), 1000);
            } else {
                this.showAlert('danger', result.message);
            }
            
        } catch (error) {
            console.error('Error generating keys:', error);
            this.showAlert('danger', 'Failed to generate keys. Please try again.');
        } finally {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    }
    
    async handleFileUpload(event) {
        event.preventDefault();
        
        const fileInput = document.getElementById('fileInput');
        const file = fileInput.files[0];
        
        if (!file) {
            this.showAlert('warning', 'Please select a file to upload');
            return;
        }
        
        const uploadBtn = document.querySelector('#uploadBtn');
        const originalText = uploadBtn.innerHTML;
        
        document.getElementById('loading-overlay').classList.remove('d-none');
        
        try {
            uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Uploading...';
            uploadBtn.disabled = true;
            
            const formData = new FormData();
            formData.append('file', file);
            
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            
            const response = await fetch('/upload', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': csrfToken
                },
                body: formData
            });
            
            const result = await response.json();
            
            if (response.ok) {
                this.showAlert('success', 'File uploaded successfully! Redirecting to verification...');
                
                document.getElementById('sessionToken').textContent = result.session_token;
                document.getElementById('fileHash').textContent = result.file_hash;
                document.getElementById('iv').textContent = result.metadata.iv;
                document.getElementById('publicKey').textContent = result.metadata.public_key;
                document.getElementById('hashType').textContent = result.metadata.hash_type;
                
                const uploadStep = document.querySelector('.step.active');
                const verificationStep = document.querySelector('.step:last-child');
                
                uploadStep.classList.remove('active');
                uploadStep.classList.add('completed');
                verificationStep.classList.add('active');
                
                document.getElementById('uploadForm').style.display = 'none';
                document.getElementById('successInfo').classList.remove('d-none');
                document.querySelector('#headerbar .col:last-child .step').classList.add('completed');
                
                fileInput.value = '';
            } else {
                if (result.error && result.error.includes('pending file')) {
                    this.showAlert('warning', result.error + ' You can go to your dashboard to manage existing files.');
                } else {
                    this.showAlert('danger', result.error || 'Upload failed');
                }
            }
        } catch (error) {
            console.error('Upload error:', error);
            this.showAlert('danger', 'Upload failed: ' + error.message);
        } finally {
            document.getElementById('loading-overlay').classList.add('d-none');
            uploadBtn.innerHTML = originalText;
            uploadBtn.disabled = false;
        }
    }
    
    async downloadFile(sessionToken) {
        try {
            const response = await fetch(`/download/${sessionToken}`);
            
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                
                const contentDisposition = response.headers.get('content-disposition');
                const filenameMatch = contentDisposition && contentDisposition.match(/filename="?([^"]+)"?/);
                a.download = filenameMatch ? filenameMatch[1] : 'downloaded-file';
                
                document.body.appendChild(a);
                a.click();
                
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
                
                this.showAlert('success', 'File downloaded successfully!');
            } else {
                const error = await response.json();
                this.showAlert('danger', error.error || 'Download failed');
            }
        } catch (error) {
            console.error('Download error:', error);
            this.showAlert('danger', 'Download failed: ' + error.message);
        }
    }
    
    generateRandomKey(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    }
    
    async readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(new Uint8Array(reader.result));
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }
    
    async simulateAESEncryption(data, key, iv) {
        return data;
    }
    
    async simulateSignature(data) {
        const encoder = new TextEncoder();
        const dataArray = encoder.encode(data);
        return this.generateRandomKey(128);
    }
    
    async simulateRSAEncryption(data) {
        return this.generateRandomKey(128);
    }
    
    async calculateSHA512(data) {
        try {
            const wordArray = CryptoJS.lib.WordArray.create(data);
    
            const hash = CryptoJS.SHA512(wordArray).toString(CryptoJS.enc.Hex);
    
            return hash;
        } catch (error) {
            this.showAlert('danger', 'Hashing failed: ' + error.message);
            throw error;
        }
    }
    
    
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    showProgress(percentage, text) {
        const progressContainer = document.getElementById('uploadProgress');
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        
        progressContainer.style.display = 'block';
        progressBar.style.width = percentage + '%';
        progressBar.setAttribute('aria-valuenow', percentage);
        progressText.textContent = text;
        
        if (percentage === 100) {
            setTimeout(() => {
                progressContainer.style.display = 'none';
            }, 2000);
        }
    }
    
    showUploadResult(type, result) {
        const resultContainer = document.getElementById('uploadResult');
        
        let alertClass = type === 'success' ? 'alert-success' : 'alert-danger';
        let icon = type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle';
        
        let content = `
            <div class="alert ${alertClass}">
                <i class="fas ${icon} me-2"></i>
                <strong>${type === 'success' ? 'Success!' : 'Error!'}</strong>
                <p class="mb-0">${result.message}</p>
        `;
        
        if (type === 'success' && result.session_token) {
            content += `
                <hr>
                <small>
                    <strong>Session Token:</strong> <code>${result.session_token}</code><br>
                    <strong>Filename:</strong> ${result.filename}<br>
                    <strong>Decrypted Size:</strong> ${result.file_size} bytes
                </small>
            `;
        }
        
        content += '</div>';
        
        resultContainer.innerHTML = content;
        resultContainer.style.display = 'block';
        
        resultContainer.scrollIntoView({ behavior: 'smooth' });
    }
    
    showAlert(type, message) {
        const alertHtml = `
            <div class="alert alert-${type} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        const container = document.querySelector('.container');
        const existingContent = container.innerHTML;
        container.innerHTML = alertHtml + existingContent;
        
        setTimeout(() => {
            const alert = container.querySelector('.alert');
            if (alert) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        }, 5000);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new SecureUploadClient();
});

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        console.log('Copied to clipboard');
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}

window.SecureUploadClient = SecureUploadClient;

async function addRecipient(ip, name) {
    try {
        const response = await fetch('/add_recipient', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip, name })
        });
        
        const result = await response.json();
        
        if (result.success) {
            location.reload();
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (error) {
        console.error('Error adding recipient:', error);
        alert('Failed to add recipient');
    }
}

async function deleteRecipient(id) {
    try {
        const response = await fetch(`/delete_recipient/${id}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (result.success) {
            location.reload();
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (error) {
        console.error('Error deleting recipient:', error);
        alert('Failed to delete recipient');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const addRecipientForm = document.getElementById('addRecipientForm');
    if (addRecipientForm) {
        addRecipientForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const ip = document.getElementById('recipientIp').value;
            const name = document.getElementById('recipientName').value;
            addRecipient(ip, name);
        });
    }
    
    const deleteButtons = document.querySelectorAll('.delete-recipient');
    deleteButtons.forEach(button => {
        button.addEventListener('click', () => {
            const id = button.getAttribute('data-id');
            if (confirm('Are you sure you want to delete this recipient?')) {
                deleteRecipient(id);
            }
        });
    });
});
