# EasyAccountant

โครงสร้างเริ่มต้น Flask สำหรับระบบบัญชี เชื่อม Firebase Realtime Database และ Supabase Storage

## เริ่มต้นใช้งาน
1. ติดตั้ง Python 3.10+
2. สร้าง virtual environment แล้วติดตั้ง `pip install -r requirements.txt`
3. แก้ `.env` ด้วยค่า Firebase และ Supabase จริง
4. วาง Firebase service account JSON ในเครื่อง และกำหนด `FIREBASE_SERVICE_ACCOUNT_PATH`
5. สร้าง bucket ใน Supabase ให้ตรงกับ `SUPABASE_BUCKET`
6. สร้าง Admin: `python create_admin.py`
7. รัน: `python app.py` แล้วเปิด http://127.0.0.1:5000

## หมายเหตุด้านความปลอดภัย
- ไฟล์ `.env` ใน ZIP เป็นค่า placeholder ไม่ใช่ Credentials จริงของคุณ
- ห้ามเผยแพร่ `.env`, Firebase service account JSON หรือ Supabase service-role key
- ตั้ง `FLASK_DEBUG=false` และใช้ secret key ที่สุ่มยาวเมื่อ deploy
- ตัวอย่างนี้เป็น starter scaffold; ควรเพิ่ม CSRF protection, rate limiting, audit log, policy การเข้าถึงไฟล์ และทดสอบก่อนใช้งานจริง
- ตัวเลขรายรับ/รายจ่ายยังเป็น placeholder ไม่ได้คำนวณจากข้อมูลจริง
