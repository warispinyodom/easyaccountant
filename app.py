import os
import time
from functools import wraps
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import SECRET_KEY, MAX_CONTENT_LENGTH
from utils.security import login_required, role_required, validate_password_strength, sanitize_input
from utils.firebase_helper import (
    get_user_by_username, 
    create_user, 
    save_transaction, 
    get_user_transactions,
    update_transaction,
    delete_transaction,
    log_event,
    get_audit_logs
)
from utils.supabase_helper import upload_document
import werkzeug.security

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# --- OWASP A02 & A07: Session Cookie Security ---
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# --- OWASP A03 & A04: CSRF Protection & Rate Limiting ---
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

def get_client_ua():
    return request.headers.get('User-Agent', '')

# --- OWASP Double-Submit Guard ---
def prevent_double_submit(cooldown_seconds=1.5):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == 'POST':
                current_time = time.time()
                session_key = f"_last_post_{request.path}"
                last_time = session.get(session_key, 0)
                
                if current_time - last_time < cooldown_seconds:
                    flash('ระบบกำลังประมวลผลคำขอก่อนหน้า กรุณารอสักครู่แล้วลองใหม่อีกครั้ง', 'warning')
                    log_event('SECURITY', 'DUPLICATE_REQUEST_BLOCKED', 
                              f"บล็อกการส่ง Request ซ้ำภายใน {cooldown_seconds} วินาที: {request.path}", 
                              session.get('user', {}).get('uid', 'ANONYMOUS'), 
                              session.get('user', {}).get('username', 'GUEST'), 
                              get_client_ip(), get_client_ua())
                    target = request.referrer or url_for('dashboard')
                    return redirect(target)
                
                session[session_key] = current_time
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- OWASP A05: Security HTTP Headers ---
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://kit.fontawesome.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:;"
    )
    return response

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@prevent_double_submit(cooldown_seconds=1.5)
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        
        try:
            user = get_user_by_username(username)
            if user and werkzeug.security.check_password_hash(user['password'], password):
                session.clear()
                session.permanent = True
                session['user'] = {
                    'uid': user['uid'],
                    'username': user['username'],
                    'name': user['name'],
                    'role': user['role']
                }
                log_event('AUDIT', 'LOGIN_SUCCESS', f"ผู้ใช้เข้าสู่ระบบสำเร็จ (Role: {user['role']})", 
                          user['uid'], user['username'], get_client_ip(), get_client_ua())
                flash(f'ยินดีต้อนรับคุณ {user["name"]}', 'success')
                return redirect(url_for('dashboard'))
            else:
                log_event('SECURITY', 'LOGIN_FAILED', f"พยายามเข้าสู่ระบบล้มเหลวด้วย Username: '{username}'", 
                          "ANONYMOUS", username, get_client_ip(), get_client_ua())
                flash('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 'danger')
        except Exception as err:
            print(f"⚠️ Login Error Exception: {err}")
            log_event('SECURITY', 'DATABASE_ERROR', f"เกิดข้อผิดพลาดในการยืนยันตัวตน: {str(err)}", 
                      "ANONYMOUS", username, get_client_ip(), get_client_ua())
            flash('เกิดข้อผิดพลาดในการเชื่อมต่อฐานข้อมูล (กรุณาซิงค์เวลาเครื่องหรือตรวจสอบ Firebase Key)', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user' in session:
        log_event('AUDIT', 'LOGOUT', "ผู้ใช้ออกจากระบบ", 
                  session['user']['uid'], session['user']['username'], get_client_ip(), get_client_ua())
    session.clear()
    flash('คุณได้ออกจากระบบเรียบร้อยแล้ว', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = session['user']
    try:
        if user['role'] == 'ADMIN':
            logs = get_audit_logs(limit=5)
            return render_template('dashboard_admin.html', user=user, recent_logs=logs)
        else:
            txs = get_user_transactions(user['uid'])
            total_income = sum(t['amount'] for t in txs if t['type'] == 'INCOME')
            total_expense = sum(t['amount'] for t in txs if t['type'] == 'EXPENSE')
            net_profit = total_income - total_expense
            
            return render_template('dashboard_owner.html', 
                                   user=user, 
                                   transactions=txs[:5], 
                                   income=total_income, 
                                   expense=total_expense, 
                                   profit=net_profit)
    except Exception as err:
        print(f"⚠️ Dashboard Exception: {err}")
        flash('เกิดข้อผิดพลาดในการดึงข้อมูลแดชบอร์ด', 'danger')
        return render_template('dashboard_owner.html', user=user, transactions=[], income=0, expense=0, profit=0)

@app.route('/invoices', methods=['GET', 'POST'])
@login_required
@prevent_double_submit(cooldown_seconds=1.5)
def invoices():
    user = session['user']
    if request.method == 'POST':
        tx_type = request.form.get('type')
        amount = request.form.get('amount')
        category = request.form.get('category')
        description = request.form.get('description')
        file = request.files.get('document')
        
        doc_url = None
        if file and file.filename != '':
            doc_url, error = upload_document(file)
            if error:
                log_event('SECURITY', 'FILE_UPLOAD_FAILED', f"อัปโหลดไฟล์ล้มเหลว: {error}", 
                          user['uid'], user['username'], get_client_ip(), get_client_ua())
                flash(error, 'danger')
                return redirect(url_for('invoices'))
            
        try:
            save_transaction(user['uid'], tx_type, amount, category, description, doc_url)
            log_event('AUDIT', 'TRANSACTION_CREATE', f"บันทึกรายการ {tx_type} จำนวน {amount} บาท", 
                      user['uid'], user['username'], get_client_ip(), get_client_ua())
            flash('บันทึกรายการบัญชีเรียบร้อยแล้ว', 'success')
        except (ValueError, Exception) as ve:
            flash(str(ve) if isinstance(ve, ValueError) else 'เกิดข้อผิดพลาดในการบันทึกรายการ', 'danger')
            
        return redirect(url_for('invoices'))

    try:
        txs = get_user_transactions(user['uid'])
    except Exception as err:
        print(f"⚠️ Invoices Exception: {err}")
        txs = []
        flash('เกิดข้อผิดพลาดในการดึงประวัติรายการบัญชี', 'danger')

    return render_template('invoices.html', user=user, transactions=txs)

@app.route('/invoices/edit/<tx_id>', methods=['POST'])
@login_required
@prevent_double_submit(cooldown_seconds=1.5)
def edit_invoice(tx_id):
    user = session['user']
    tx_type = request.form.get('type')
    amount = request.form.get('amount')
    category = request.form.get('category')
    description = request.form.get('description')
    file = request.files.get('document')

    doc_url = None
    if file and file.filename != '':
        doc_url, error = upload_document(file)
        if error:
            log_event('SECURITY', 'FILE_UPLOAD_FAILED', f"อัปโหลดไฟล์ล้มเหลวขณะแก้ไข: {error}", 
                      user['uid'], user['username'], get_client_ip(), get_client_ua())
            flash(error, 'danger')
            return redirect(url_for('invoices'))

    try:
        update_transaction(tx_id, user['uid'], user['role'], tx_type, amount, category, description, doc_url)
        log_event('AUDIT', 'TRANSACTION_UPDATE', f"แก้ไขรายการ ID: {tx_id} ({tx_type} จำนวน {amount} บาท)", 
                  user['uid'], user['username'], get_client_ip(), get_client_ua())
        flash('แก้ไขรายการบัญชีเรียบร้อยแล้ว', 'success')
    except (ValueError, PermissionError) as err:
        flash(str(err), 'danger')
    except Exception as err:
        print(f"⚠️ Transaction Update Error: {err}")
        flash('เกิดข้อผิดพลาดในการอัปเดตรายการ', 'danger')

    return redirect(url_for('invoices'))

@app.route('/invoices/delete/<tx_id>', methods=['POST'])
@login_required
@prevent_double_submit(cooldown_seconds=1.5)
def delete_invoice(tx_id):
    user = session['user']
    try:
        delete_transaction(tx_id, user['uid'], user['role'])
        log_event('AUDIT', 'TRANSACTION_DELETE', f"ลบรายการบัญชี ID: {tx_id}", 
                  user['uid'], user['username'], get_client_ip(), get_client_ua())
        flash('ลบรายการบัญชีเรียบร้อยแล้ว', 'success')
    except (ValueError, PermissionError) as err:
        flash(str(err), 'danger')
    except Exception as err:
        print(f"⚠️ Transaction Delete Error: {err}")
        flash('เกิดข้อผิดพลาดในการลบรายการ', 'danger')

    return redirect(url_for('invoices'))

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN')
@prevent_double_submit(cooldown_seconds=1.5)
def manage_users():
    admin_user = session['user']
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        role = request.form.get('role')
        
        is_valid, msg = validate_password_strength(password)
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('manage_users'))
            
        try:
            if get_user_by_username(username):
                flash('Username นี้ถูกใช้งานแล้ว', 'danger')
                return redirect(url_for('manage_users'))

            new_uid = create_user(username, password, name, role)
            log_event('AUDIT', 'USER_CREATE', f"Admin สร้างบัญชีผู้ใช้ใหม่: Username '{username}' (Role: {role})", 
                      admin_user['uid'], admin_user['username'], get_client_ip(), get_client_ua())
            flash('เพิ่มบัญชีผู้ใช้งานใหม่เรียบร้อยแล้ว', 'success')
        except ValueError as ve:
            flash(str(ve), 'danger')
        except Exception as err:
            print(f"⚠️ Create User Exception: {err}")
            flash('เกิดข้อผิดพลาดในการสร้างบัญชีผู้ใช้', 'danger')
            
        return redirect(url_for('manage_users'))

    return render_template('users_manage.html', user=admin_user)

@app.route('/admin/logs')
@login_required
@role_required('ADMIN')
def view_logs():
    admin_user = session['user']
    try:
        logs = get_audit_logs(limit=200)
    except Exception as err:
        print(f"⚠️ View Logs Exception: {err}")
        logs = []
        flash('เกิดข้อผิดพลาดในการดึงข้อมูลบันทึกความปลอดภัย', 'danger')
    return render_template('audit_logs.html', user=admin_user, logs=logs)

# --- Error Handlers ---
@app.errorhandler(403)
def forbidden(e):
    user_id = session.get('user', {}).get('uid', 'ANONYMOUS')
    username = session.get('user', {}).get('username', 'GUEST')
    log_event('SECURITY', 'UNAUTHORIZED_ACCESS', f"พยายามเข้าถึงหน้าเพจที่ไม่ได้รับสิทธิ์ (403 Forbidden): {request.path}", 
              user_id, username, get_client_ip(), get_client_ua())
    flash('คุณไม่มีสิทธิ์เข้าถึงหน้านี้ (403 Forbidden)', 'danger')
    return render_template('login.html'), 403

@app.errorhandler(429)
def ratelimit_handler(e):
    user_id = session.get('user', {}).get('uid', 'ANONYMOUS')
    username = session.get('user', {}).get('username', 'GUEST')
    log_event('SECURITY', 'RATE_LIMIT_EXCEEDED', f"ทำรายการเกินขีดจำกัดความถี่ (429 Rate Limit): {request.path}", 
              user_id, username, get_client_ip(), get_client_ua())
    flash('คุณทำรายการถี่เกินไป กรุณารอ 1 นาทีแล้วลองใหม่', 'warning')
    return redirect(url_for('login'))

@app.errorhandler(400)
def bad_request(e):
    flash('คำขอไม่ถูกต้อง (400 Bad Request)', 'danger')
    return render_template('login.html'), 400

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('dashboard'))

@app.errorhandler(413)
def request_entity_too_large(e):
    flash('ขนาดไฟล์ใหญ่เกินขีดจำกัด (สูงสุด 5MB)', 'danger')
    return redirect(url_for('invoices'))

@app.errorhandler(500)
def internal_server_error(e):
    flash('เกิดข้อผิดพลาดภายในระบบเซิร์ฟเวอร์ (500 Internal Server Error)', 'danger')
    return render_template('login.html'), 500

if __name__ == '__main__':
    is_debug = os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1']
    app.run(debug=is_debug, host='0.0.0.0', port=5000)