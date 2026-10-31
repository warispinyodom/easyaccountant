import uuid
import filetype
from werkzeug.utils import secure_filename
from config import supabase, ALLOWED_EXTENSIONS, ALLOWED_MIME_TYPES

BUCKET_NAME = "accounting-docs"

def upload_document(file):
    try:
        # 1. ตรวจสอบชื่อไฟล์และนามสกุล
        filename = secure_filename(file.filename)
        if '.' not in filename:
            return None, "นามสกุลไฟล์ไม่ถูกต้อง"
            
        ext = filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return None, f"อนุญาตเฉพาะไฟล์ประเภท: {', '.join(ALLOWED_EXTENSIONS)}"

        # 2. อ่านไบต์และตรวจสอบ Magic Bytes (File Signature)
        file_bytes = file.read()
        file.seek(0)  # Reset pointer
        
        kind = filetype.guess(file_bytes)
        if kind is None or kind.mime not in ALLOWED_MIME_TYPES:
            return None, "ประเภทไฟล์ไม่ถูกต้องตามมาตรฐานความปลอดภัย (Invalid Magic Bytes)"

        # 3. สุ่มชื่อไฟล์ใหม่ด้วย UUID4 ป้องกัน Direct Path Traversal
        unique_name = f"{uuid.uuid4().hex}.{ext}"
        
        # 4. อัปโหลดไป Supabase Storage
        supabase.storage.from_(BUCKET_NAME).upload(
            path=unique_name,
            file=file_bytes,
            file_options={"content-type": kind.mime}
        )
        
        public_url = supabase.storage.from_(BUCKET_NAME).get_public_url(unique_name)
        return public_url, None

    except Exception as e:
        print(f"Supabase Upload Secure Error: {e}")
        return None, "เกิดข้อผิดพลาดในการอัปโหลดไฟล์"