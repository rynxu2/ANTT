import os
import pickle
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

SCOPES = [
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/drive.metadata.readonly'
]

class DriveManager:
    def __init__(self):
        self.credentials = None
        self.service = None
        self.initialize_service()

    def initialize_service(self):
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                self.credentials = pickle.load(token)

        if not self.credentials or not self.credentials.valid:
            if self.credentials and self.credentials.expired and self.credentials.refresh_token:
                self.credentials.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'client_secret_326222266772-gj08e0ofpf0ulk5lkjibn5vgto6bvtfo.apps.googleusercontent.com.json', SCOPES)
                self.credentials = flow.run_local_server(port=0)

            with open('token.pickle', 'wb') as token:
                pickle.dump(self.credentials, token)

        self.service = build('drive', 'v3', credentials=self.credentials)

    def upload_file(self, file_path, folder_id=None):
        try:
            file_metadata = {
                'name': os.path.basename(file_path)
            }
            if folder_id:
                file_metadata['parents'] = [folder_id]

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

            return {
                'file_id': file.get('id'),
                'web_link': file.get('webViewLink')
            }

        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def download_file(self, file_id, destination_path):
        try:
            request = self.service.files().get_media(fileId=file_id)
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

    def create_folder(self, folder_name, parent_folder_id=None):
        try:
            file_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            if parent_folder_id:
                file_metadata['parents'] = [parent_folder_id]

            folder = self.service.files().create(
                body=file_metadata,
                fields='id'
            ).execute()
            return folder.get('id')
        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def get_file_link(self, file_id):
        try:
            file = self.service.files().get(
                fileId=file_id,
                fields='webViewLink'
            ).execute()
            return file.get('webViewLink')
        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

drive_manager = DriveManager()
