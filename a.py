# troubleshoot_drive.py
import os
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

# Configuration - MODIFY THESE VALUES
SERVICE_ACCOUNT_FILE = os.getenv("SERVICE_ACCOUNT_FILE", "sr-counselling-ebook-a6992e3809e3.json")
EBOOK_FILE_ID = os.getenv("EBOOK_FILE_ID", "1x1OBfXej4YyNIJvn2jQqWbWtbgINlqg1")  # Extracted from your Drive link
DRIVE_SCOPES = ['https://www.googleapis.com/auth/drive']
TEST_EMAIL = "ananyap1524@gmail.com"
def test_drive_access():
    """Test if we can grant permissions to a Google Drive file."""
    print(f"Testing Drive API access using service account: {SERVICE_ACCOUNT_FILE}")
    print(f"Testing with file ID: {EBOOK_FILE_ID}")
    print(f"Will attempt to grant access to: {TEST_EMAIL}")

    try:
        # Step 1: Check if the service account file exists
        if not os.path.exists(SERVICE_ACCOUNT_FILE):
            print(f"ERROR: Service account file not found at {SERVICE_ACCOUNT_FILE}")
            return False
        print("✓ Service account file exists")

        # Step 2: Authenticate using the service account
        credentials = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=['https://www.googleapis.com/auth/drive'])
        print("✓ Created credentials from service account file")

        # Step 3: Create a Drive service
        service = build('drive', 'v3', credentials=credentials)
        print("✓ Built Drive API service")

        # Step 4: Verify the file exists and check permissions
        try:
            file = service.files().get(fileId=EBOOK_FILE_ID).execute()
            print(f"✓ File exists: '{file.get('name')}' ({file.get('mimeType')})")
        except HttpError as error:
            print(f"ERROR: Could not access file with ID {EBOOK_FILE_ID}")
            print(f"Error details: {error}")
            return False

        # Step 5: Try to grant permission
        user_permission = {
            'type': 'user',
            'role': 'reader',
            'emailAddress': TEST_EMAIL
        }

        try:
            result = service.permissions().create(
                fileId=EBOOK_FILE_ID,
                body=user_permission,
                fields='id',
                sendNotificationEmail=False
            ).execute()
            print(f"✓ Successfully granted access to {TEST_EMAIL}")
            print(f"Permission ID: {result.get('id')}")
            return True
        except HttpError as error:
            print(f"ERROR: Could not grant permission to {TEST_EMAIL}")
            print(f"Error details: {error}")
            return False

    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_drive_access()
    if success:
        print("\n✅ All tests passed! You should be able to grant Drive access.")
    else:
        print("\n❌ Test failed. See errors above for details.")