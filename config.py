import os
import json
from datetime import timedelta
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, db
from supabase import create_client, Client

load_dotenv()

# --- Configurations ---
FIREBASE_URL = os.getenv("FIREBASE_URL") or os.getenv("firebase_url")
FIREBASE_CRED_ENV = (
    os.getenv("FIREBASE_CREDENTIALS") or 
    os.getenv("firebase_credentials") or 
    os.getenv("FIREBASE_CREDENTIAL_PATH") or 
    os.getenv("firebase_credential")
)

SUPABASE_URL = os.getenv("SUPABASE_URL") or os.getenv("supabase_url")
SUPABASE_SECRET_KEY = (
    os.getenv("SUPABASE_SECRET_KEY") or 
    os.getenv("supabase_secert_key") or 
    os.getenv("SUPABASE_KEY") or 
    os.getenv("SUPABASE_ANON_KEY")
)
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "portfolio-images")
SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or os.getenv("SECRET_KEY", os.urandom(32).hex())

# Security & Upload Constraints (OWASP Standards)
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
ALLOWED_MIME_TYPES = {'image/png', 'image/jpeg', 'application/pdf'}

# --- Firebase Initialization ---
if FIREBASE_CRED_ENV and not firebase_admin._apps:
    try:
        if FIREBASE_CRED_ENV.strip().startswith("{"):
            cred_dict = json.loads(FIREBASE_CRED_ENV)
            if "private_key" in cred_dict and "\\n" in cred_dict["private_key"]:
                cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")
            cred = credentials.Certificate(cred_dict)
        elif os.path.exists(FIREBASE_CRED_ENV):
            cred = credentials.Certificate(FIREBASE_CRED_ENV)
        else:
            cred = None

        if cred:
            firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_URL})
    except Exception as e:
        print(f"⚠️ Firebase Initialization Warning: {e}")

# --- Safe Supabase Initialization (Prevents Vercel Import Crash) ---
supabase: Client = None
if SUPABASE_URL and SUPABASE_SECRET_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)
    except Exception as e:
        print(f"⚠️ Supabase Init Warning (Invalid Key or Connection Failure): {e}")
        supabase = None
else:
    print("⚠️ Supabase credentials missing in environment variables.")