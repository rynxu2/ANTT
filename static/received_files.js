document.addEventListener('DOMContentLoaded', function() {
    // Handle verify form submissions
    const verifyForms = document.querySelectorAll('.verify-form');
    verifyForms.forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            
            try {
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                submitBtn.disabled = true;
                
                const response = await fetch(form.action, {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                    }
                });
                
                const result = await response.json();
                  if (response.ok) {
                    // Không hiển thị thông báo ở đây vì sẽ nhận qua Socket.IO
                    // Cập nhật giao diện với dữ liệu từ response
                    const {status, session_token} = result;
                    const fileRow = form.closest('tr');
                    if (fileRow && status === 'verified') {
                        const statusCell = fileRow.querySelector('td:nth-child(5)');
                        const actionCell = fileRow.querySelector('td:last-child');
                        
                        if (statusCell) {
                            statusCell.innerHTML = `
                                <span class="badge bg-success">
                                    <i class="fas fa-check-circle me-1"></i>
                                    Verified
                                </span>
                            `;
                        }
                        
                        // Update actions
                        if (actionCell) {
                            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
                            actionCell.innerHTML = `
                                <div class="btn-group">                                    <a href="/download/${session_token}" class="btn btn-sm btn-primary" target="_blank">
                                        <i class="fas fa-download"></i>
                                    </a>
                                    <button type="button" class="btn btn-sm btn-danger mark-failed" data-file-id="${fileRow.getAttribute('data-file-id')}">
                                        <i class="fas fa-times-circle me-1"></i>Mark as Failed
                                    </button>
                                </div>
                            `;
                        }
                    }
                } else {
                    showAlert('danger', result.error || 'Verification failed');
                }
            } catch (error) {
                console.error('Verification error:', error);
                showAlert('danger', 'Verification failed: ' + error.message);
            } finally {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            }
        });
    });
    
    // Handle mark as failed buttons
    function initMarkFailedButtons() {
        const markFailedButtons = document.querySelectorAll('.mark-failed');
        markFailedButtons.forEach(button => {
            button.addEventListener('click', async () => {
                if (confirm('Are you sure you want to mark this file as failed?')) {
                    const fileId = button.getAttribute('data-file-id');
                    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

                    try {
                        const response = await fetch('/mark_file_failed/' + fileId, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRFToken': csrfToken
                            }
                        });

                        if (response.ok) {
                            // Update the status cell
                            const fileRow = button.closest('tr');
                            const statusCell = fileRow.querySelector('td:nth-child(5)');
                            if (statusCell) {
                                statusCell.innerHTML = `
                                    <span class="badge bg-danger">
                                        <i class="fas fa-times-circle me-1"></i>Failed
                                    </span>
                                `;
                            }
                            showAlert('success', 'File has been marked as failed');
                            
                            // Add highlight animation
                            fileRow.classList.add('highlight-danger');
                            setTimeout(() => {
                                fileRow.classList.remove('highlight-danger');
                            }, 2000);
                        } else {
                            const error = await response.json();
                            showAlert('danger', error.message || 'Failed to update file status');
                        }
                    } catch (error) {
                        console.error('Error:', error);
                        showAlert('danger', 'An error occurred while updating the file status');
                    }
                }
            });
        });
    }

    // Initialize mark as failed buttons
    initMarkFailedButtons();

    // Reinitialize mark as failed buttons when file status changes
    document.addEventListener('fileStatusChanged', function() {
        initMarkFailedButtons();
    });

    function showAlert(type, message) {
        const alertHtml = `
            <div class="alert alert-${type} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        // Insert at the top of the container
        const container = document.querySelector('.container');
        container.insertAdjacentHTML('afterbegin', alertHtml);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            const alert = container.querySelector('.alert');
            if (alert) {
                bootstrap.Alert.getOrCreateInstance(alert).close();
            }
        }, 5000);
    }
});
