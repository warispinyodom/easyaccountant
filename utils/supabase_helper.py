import uuid
import filetype
from werkzeug.utils import secure_filename
from config import supabase, ALLOWED_EXTENSIONS, ALLOWED_MIME_TYPES, SUPABASE_BUCKET

def upload_document(file):
    if supabase is None:
        return None, "ระบบจัดเก็บไฟล์ยังไม่ได้เชื่อมต่อ (กรุณาตรวจสอบ Supabase API Key ใน Vercel Settings)"

    try:
        # 1. ตรวจสอบชื่อและนามสกุลไฟล์
        filename = secure_filename(file.filename)
        if '.' not in filename:
            return None, "นามสกุลไฟล์ไม่ถูกต้อง"
            
        ext = filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return None, f"อนุญาตเฉพาะไฟล์ประเภท: {', '.join(ALLOWED_EXTENSIONS)}"

        # 2. อ่านไบต์และตรวจสอบ Magic Bytes
        file_bytes = file.read()
        file.seek(0)
        
        kind = filetype.guess(file_bytes)
        if kind is None or kind.mime not in ALLOWED_MIME_TYPES:
            return None, "ประเภทไฟล์ไม่ถูกต้องตามมาตรฐานความปลอดภัย (Invalid Magic Bytes)"

        # 3. สุ่มชื่อไฟล์ใหม่ด้วย UUID4
        unique_name = f"{uuid.uuid4().hex}.{ext}"
        
        # 4. อัปโหลดไปยัง Supabase Storage
        supabase.storage.from_(SUPABASE_BUCKET).upload(
            path=unique_name,
            file=file_bytes,
            file_options={"content-type": kind.mime}
        )
        
        public_url = supabase.storage.from_(SUPABASE_BUCKET).get_public_url(unique_name)
        return public_url, None

    except Exception as e:
        print(f"Supabase Upload Secure Error: {e}")
        return None, "เกิดข้อผิดพลาดในการอัปโหลดไฟล์"