import re
from functools import wraps
from flask import session, redirect, url_for, flash, abort

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or not session.get('user', {}).get('uid'):
            flash('กรุณาเข้าสู่ระบบก่อนใช้งาน', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return redirect(url_for('login'))
            user_role = session['user'].get('role')
            if user_role not in allowed_roles:
                flash('คุณไม่มีสิทธิ์เข้าถึงหน้านี้ (Unauthorized)', 'danger')
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_password_strength(password):
    """
    OWASP Password Requirement:
    - ยาวอย่างน้อย 8 ตัวอักษร
    - มีอักษรตัวพิมพ์ใหญ่ พิมพ์เล็ก ตัวเลข และอักขระพิเศษ
    """
    if len(password) < 8:
        return False, "รหัสผ่านต้องมีความยาวอย่างน้อย 8 ตัวอักษร"
    if not re.search(r"[A-Z]", password):
        return False, "รหัสผ่านต้องมีอักษรภาษาอังกฤษตัวพิมพ์ใหญ่อย่างน้อย 1 ตัว"
    if not re.search(r"[a-z]", password):
        return False, "รหัสผ่านต้องมีอักษรภาษาอังกฤษตัวพิมพ์เล็กอย่างน้อย 1 ตัว"
    if not re.search(r"[0-9]", password):
        return False, "รหัสผ่านต้องมีตัวเลขอย่างน้อย 1 ตัว"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "รหัสผ่านต้องมีอักขระพิเศษอย่างน้อย 1 ตัว (!@#$%^&*)"
    return True, ""

def sanitize_input(text):
    if not isinstance(text, str):
        return text
    # ป้องกัน Control Characters และตัด space หัวท้าย
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text).strip()