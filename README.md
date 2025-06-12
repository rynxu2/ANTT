# ANTT - Secure File Transfer System

A secure file transfer system supporting both local and cloud storage (Google Drive) with end-to-end encryption, digital signatures, and real-time verification.

## Features

### Security
- 🔐 RSA-based key pair generation for each user/IP (2048-bit keys)
- 🔒 AES-256-CBC encryption for file contents
- 📝 Digital signatures using RSA/SHA-512
- 🔍 Real-time file integrity verification
- ⚡ Session key management for secure transfers
- 🛡️ Secure key exchange using OAEP padding
- 🔐 PSS padding for digital signatures

### File Transfer
- 📤 Local file uploads with drag & drop support
- ☁️ Google Drive integration with automatic folder management
- 📥 Secure file downloads with integrity checks
- 🔄 File status tracking and real-time updates
- 📊 Transfer progress monitoring
- 📁 Automatic host-specific folder creation in Drive

### Host Management
- 👥 Multiple host support with isolated storage
- 🔑 Host-specific key management and storage
- 📋 Join request system with verification
- 🚫 Access control with approval/rejection
- ⏳ Request status tracking
- 🏷️ Host-based file organization

### Real-Time Features
- 📲 Real-time status updates via WebSocket
- 🔔 Event notifications for file transfers
- 💫 Live progress tracking
- 🔄 Automatic UI updates
- 🚦 Transfer state management

## Security Architecture

### Key Management
1. **RSA Key Pairs**
   - 2048-bit RSA keys generated per host/IP
   - Private keys never leave the generating system
   - Public keys exchanged during host registration

2. **Session Keys**
   - Random 256-bit AES keys per file transfer
   - Encrypted with recipient's RSA public key
   - Unique IV (Initialization Vector) per encryption

3. **Digital Signatures**
   - RSA-PSS signatures with SHA-512
   - File integrity verification
   - Sender authentication

### Encryption Process
1. **File Upload**
   - Generate random AES session key
   - Encrypt file with AES-256-CBC
   - Encrypt session key with recipient's public key
   - Sign the encrypted data
   - Store encrypted file and metadata

2. **File Download**
   - Verify file integrity with stored hash
   - Decrypt session key with private key
   - Verify digital signature
   - Decrypt file data with AES
   - Perform final integrity check

## Technology Stack

### Backend
- **Framework**: Flask (Python)
- **Database**: SQLAlchemy ORM
- **Cryptography**: 
  - cryptography.hazmat library
  - RSA for asymmetric encryption
  - AES for symmetric encryption
- **Real-time**: Socket.IO
- **Cloud Storage**: Google Drive API v3

### Frontend
- **Core**: HTML5/CSS3
- **JavaScript**: ES6+
- **UI Framework**: Bootstrap 5
- **Icons**: Font Awesome
- **WebSocket**: Socket.IO client

### Security Libraries
- RSA encryption (2048-bit keys)
- AES-256-CBC encryption
- SHA-512 hashing
- OAEP/PSS padding schemes

### Storage
- Local file system (encrypted storage)
- Google Drive integration
- Secure temporary file handling

## Setup Instructions

### Prerequisites
1. **System Requirements**
   - Python 3.9+
   - pip package manager
   - Node.js (for frontend development)
   - Git

2. **Google Cloud Setup**
   - Google Cloud account
   - Project with Drive API enabled
   - OAuth 2.0 credentials
   - Download client secrets file

### Installation

1. Clone the repository:
```powershell
git clone <repository-url>
cd ANTT
```

2. Create and activate virtual environment:
```powershell
python -m venv venv
.\venv\Scripts\Activate
```

3. Install dependencies:
```powershell
pip install -r requirements.txt
```

4. Set up Google Drive API:
   - Create project in Google Cloud Console
   - Enable Drive API
   - Create OAuth 2.0 credentials
   - Download client secrets file as `client_secret_*.json`
   - Place in project root directory

5. Initialize the database:
```powershell
python
>>> from app import db
>>> db.create_all()
>>> exit()
```

6. Start the server:
```powershell
python app.py
```

## Usage Guide

### First Time Setup

1. **Host Registration**
   - Start the application
   - Generate host keys (automatic)
   - Complete registration form
   - Store credentials securely

2. **Connecting to Other Hosts**
   - Send join request
   - Exchange public keys
   - Wait for approval
   - Establish secure connection

### File Transfer

1. **Local Transfer**
   - Select file(s)
   - Choose recipient host
   - Initiate transfer
   - Monitor progress
   - Verify completion

2. **Drive Transfer**
   - Select file(s)
   - Choose cloud storage option
   - Select recipient
   - Monitor upload
   - Share Drive link

### Security Best Practices

1. **Key Management**
   - Store private keys securely
   - Never share private keys
   - Rotate keys periodically
   - Backup keys safely

2. **File Handling**
   - Verify file integrity
   - Check recipient details
   - Monitor transfer status
   - Clear temporary files

## Development

### Project Structure
```
ANTT/
├── app.py              # Application entry point
├── routes.py           # API endpoints
├── models.py           # Database models
├── crypto_utils.py     # Cryptography functions
├── drive_utils.py      # Google Drive integration
├── storage_utils.py    # File storage handlers
├── events.py          # WebSocket events
├── static/            # Frontend assets
│   ├── js/
│   └── css/
└── templates/         # HTML templates
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Submit pull request
5. Follow coding standards

## License

[Insert License Information]

## Acknowledgments

- Cryptography library contributors
- Google Drive API team
- Flask and Socket.IO communities