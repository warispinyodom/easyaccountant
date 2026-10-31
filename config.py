import os
import json
from datetime import timedelta
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, db
from supabase import create_client, Client

load_dotenv()

# อ่านค่า Environment Variables (รองรับทั้ง FIREBASE_CREDENTIALS และตัวแปรเดิม)
FIREBASE_URL = os.getenv("FIREBASE_URL") or os.getenv("firebase_url")
FIREBASE_CRED_ENV = (
    os.getenv("FIREBASE_CREDENTIALS") or 
    os.getenv("firebase_credentials") or 
    os.getenv("FIREBASE_CREDENTIAL_PATH") or 
    os.getenv("firebase_credential")
)
SUPABASE_URL = os.getenv("SUPABASE_URL") or os.getenv("supabase_url")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY") or os.getenv("supabase_secert_key")
SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or os.getenv("SECRET_KEY", os.urandom(32).hex())

# Security & Upload Configurations (OWASP Standards)
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # จำกัดขนาดไฟล์อัปโหลดไม่เกิน 5 MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
ALLOWED_MIME_TYPES = {'image/png', 'image/jpeg', 'application/pdf'}

if not FIREBASE_CRED_ENV:
    raise RuntimeError("❌ ไม่พบตัวแปร 'FIREBASE_CREDENTIALS' ในไฟล์ .env กรุณาตรวจสอบ")

# แปลง JSON String เป็น Python Dictionary เพื่อส่งให้ Firebase Credentials
try:
    if FIREBASE_CRED_ENV.strip().startswith("{"):
        cred_dict = json.loads(FIREBASE_CRED_ENV)
        
        # จัดการ \n ใน private_key ให้ถูกต้อง (กรณี dotenv ทำการ escape String)
        if "private_key" in cred_dict and "\\n" in cred_dict["private_key"]:
            cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")
            
        cred = credentials.Certificate(cred_dict)
    elif os.path.exists(FIREBASE_CRED_ENV):
        cred = credentials.Certificate(FIREBASE_CRED_ENV)
    else:
        raise FileNotFoundError(f"ไม่พบไฟล์หรือข้อมูล JSON ของ Credential: '{FIREBASE_CRED_ENV}'")
except Exception as e:
    raise ValueError(f"❌ การโหลด Firebase Credentials ล้มเหลว: {e}")

# Initialize Firebase Realtime Database
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, {
        'databaseURL': FIREBASE_URL
    })

# Initialize Supabase Storage Client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)