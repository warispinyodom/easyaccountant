import werkzeug.security
from config import db
from utils.firebase_helper import get_user_by_username, log_event
from utils.security import validate_password_strength, sanitize_input

def create_initial_admin():
    print("=== EasyAccountant Admin Setup ===")
    username = sanitize_input(input("กำหนด Username Admin: ")).strip()
    
    if get_user_by_username(username):
        print("❌ Username นี้มีอยู่ในระบบแล้ว!")
        return

    password = input("กำหนด Password: ").strip()
    is_valid, msg = validate_password_strength(password)
    if not is_valid:
        print(f"❌ รหัสผ่านไม่ผ่านเกณฑ์ความปลอดภัย: {msg}")
        return

    name = sanitize_input(input("ชื่อ-นามสกุล Admin: ")).strip()
    hashed_pw = werkzeug.security.generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    ref = db.reference('users')
    new_admin = ref.push({
        'username': username,
        'password': hashed_pw,
        'name': name,
        'role': 'ADMIN',
        'created_at': {".sv": "timestamp"}
    })
    
    # บันทึก Audit Log เมื่อสร้าง Admin สำเร็จ
    log_event('AUDIT', 'ADMIN_INITIAL_SETUP', f"สร้างบัญชี Admin คนแรกผ่าน CLI: '{username}'", 
              new_admin.key, username, "CLI_LOCAL", "SYSTEM_SCRIPT")
    
    print(f"✅ สร้าง Admin สำเร็จแล้ว! User ID: {new_admin.key}")

if __name__ == "__main__":
    create_initial_admin()