import os
import pickle
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from flask import session

SCOPES = [
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/drive.metadata.readonly'
]

class DriveManager:
    def initialize_service(self, host_id):
        """Initialize service for a specific host"""
        token_path = f'tokens/token_{host_id}.pickle'
        os.makedirs('tokens', exist_ok=True)

        credentials = None
        if os.path.exists(token_path):
            with open(token_path, 'rb') as token:
                credentials = pickle.load(token)

        if not credentials or not credentials.valid:
            if credentials and credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
            else:
                session['authenticating_host_id'] = host_id
                flow = InstalledAppFlow.from_client_secrets_file(
                    'client_secret_326222266772-n102mfh5tjuq7305d5m0jlr7fcn9if4q.apps.googleusercontent.com.json', 
                    SCOPES
                )
                credentials = flow.run_local_server(port=8080)

            with open(token_path, 'wb') as token:
                pickle.dump(credentials, token)

        self.service = build('drive', 'v3', credentials=credentials)
        return True

    def save_credentials(self, credentials, host_id):
        """Save credentials for a specific host"""
        token_path = f'tokens/token_{host_id}.pickle'
        os.makedirs('tokens', exist_ok=True)
        with open(token_path, 'wb') as token:
            pickle.dump(credentials, token)

    def has_valid_credentials(self, host_id):
        """Check if host has valid credentials"""
        token_path = f'tokens/token_{host_id}.pickle'
        if not os.path.exists(token_path):
            return False
        try:
            with open(token_path, 'rb') as token:
                credentials = pickle.load(token)
                return credentials and credentials.valid
        except:
            return False

    def get_service(self, host_id):
        self.initialize_service(host_id)
        return self.service

    def download_file(self, host_id, file_id, destination_path):
        try:
            service = self.get_service(host_id)
            request = service.files().get_media(fileId=file_id)
            with open(destination_path, 'wb') as f:
                downloader = MediaIoBaseDownload(f, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                    if status:
                        print(f'Download {int(status.progress() * 100)}%')
            return True
        except HttpError as error:
            print(f'An error occurred: {error}')
            return False

    def get_file_link(self, host_id, file_id):
        try:
            service = self.get_service(host_id)
            file = service.files().get(
                fileId=file_id,
                fields='webViewLink'
            ).execute()
            return file.get('webViewLink')
        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def get_or_create_host_folder(self, host_id, host_name):
        try:
            service = self.get_service(host_id)
            query = f"name='{host_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            results = service.files().list(
                q=query,
                spaces='drive',
                fields='files(id, name)'
            ).execute()
            items = results.get('files', [])

            if items:
                return items[0]['id']
            else:
                folder_id = self.create_folder(host_id, host_name)
                if folder_id:
                    self.make_file_public(host_id, folder_id)
                return folder_id

        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def upload_file(self, file_path, host_id, host_name):
        """Upload file to a specific host's Drive"""
        if not self.initialize_service(host_id):
            return None
        try:
            folder_id = self.get_or_create_host_folder(host_id, host_name)
            if not folder_id:
                return None
            file_metadata = {
                'name': os.path.basename(file_path),
                'parents': [folder_id]
            }
            media = MediaFileUpload(
                file_path, 
                resumable=True,
                chunksize=1024*1024
            )
            service = self.get_service(host_id)
            file = service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, webViewLink'
            ).execute()
            self.make_file_public(host_id, file.get('id'))
            return {
                'file_id': file.get('id'),
                'web_link': file.get('webViewLink')
            }
        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

drive_manager = DriveManager()