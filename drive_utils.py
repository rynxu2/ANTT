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
    def __init__(self):
        self.credentials = None
        self.service = None

    def initialize_service(self, user_ip):
        """Initialize service for a specific user"""
        token_path = f'tokens/token_{user_ip}.pickle'
        os.makedirs('tokens', exist_ok=True)

        if os.path.exists(token_path):
            with open(token_path, 'rb') as token:
                self.credentials = pickle.load(token)

        if not self.credentials or not self.credentials.valid:
            if self.credentials and self.credentials.expired and self.credentials.refresh_token:
                self.credentials.refresh(Request())
            else:
                # Store the user_ip in session for oauth callback
                session['authenticating_user_ip'] = user_ip
                flow = InstalledAppFlow.from_client_secrets_file(
                    'client_secret_326222266772-gj08e0ofpf0ulk5lkjibn5vgto6bvtfo.apps.googleusercontent.com.json', 
                    SCOPES
                )
                self.credentials = flow.run_local_server(port=8080)

            with open(token_path, 'wb') as token:
                pickle.dump(self.credentials, token)

        self.service = build('drive', 'v3', credentials=self.credentials)
        return True

    def save_credentials(self, credentials, user_ip):
        """Save credentials for a specific user"""
        token_path = f'tokens/token_{user_ip}.pickle'
        os.makedirs('tokens', exist_ok=True)
        with open(token_path, 'wb') as token:
            pickle.dump(credentials, token)

    def has_valid_credentials(self, user_ip):
        """Check if user has valid credentials"""
        token_path = f'tokens/token_{user_ip}.pickle'
        if not os.path.exists(token_path):
            return False

        try:
            with open(token_path, 'rb') as token:
                credentials = pickle.load(token)
                return credentials and credentials.valid
        except:
            return False

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

    def create_folder(self, host_id, folder_name, parent_folder_id=None):
        try:
            service = self.get_service(host_id)
            file_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            if parent_folder_id:
                file_metadata['parents'] = [parent_folder_id]

            folder = service.files().create(
                body=file_metadata,
                fields='id'
            ).execute()
            return folder.get('id')
        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

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

    def make_file_public(self, host_id, file_id):
        try:
            service = self.get_service(host_id)
            permission = {
                'type': 'anyone',
                'role': 'reader'
            }
            service.permissions().create(
                fileId=file_id,
                body=permission
            ).execute()
            return True
        except HttpError as error:
            print(f'An error occurred: {error}')
            return False

    def get_or_create_host_folder(self, host_id, host_name):
        try:
            query = f"name='{host_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            results = self.service.files().list(
                q=query,
                spaces='drive',
                fields='files(id, name)'
            ).execute()
            items = results.get('files', [])

            if items:
                return items[0]['id']
            else:
                folder_id = self.create_folder(host_name)
                if folder_id:
                    self.make_file_public(folder_id)
                return folder_id

        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def upload_file(self, file_path, host_name, user_ip):
        """Upload file to a specific user's Drive"""
        if not self.initialize_service(user_ip):
            return None

        try:
            folder_id = self.get_or_create_host_folder(host_name)
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

            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, webViewLink'
            ).execute()

            self.make_file_public(file.get('id'))

            return {
                'file_id': file.get('id'),
                'web_link': file.get('webViewLink')
            }

        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

drive_manager = DriveManager()
