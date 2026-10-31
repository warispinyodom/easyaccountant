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

# Helper ดึงข้อมูล IP และ User Agent
def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

def get_client_ua():
    return request.headers.get('User-Agent', '')

# --- OWASP Double-Submit Guard Decorator ---
def prevent_double_submit(cooldown_seconds=3):
    """
    บล็อกการส่ง Form POST ซ้ำภายในเวลาที่กำหนด เพื่อป้องกัน Request Limit Exceeded
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == 'POST':
                current_time = time.time()
                last_time = session.get('_last_post_time', 0)
                if current_time - last_time < cooldown_seconds:
                    flash('ระบบกำลังประมวลผลคำขอก่อนหน้า กรุณารอสักครู่แล้วลองใหม่อีกครั้ง', 'warning')
                    log_event('SECURITY', 'DUPLICATE_REQUEST_BLOCKED', 
                              f"บล็อกการส่ง Request ซ้ำภายใน {cooldown_seconds} วินาที: {request.path}", 
                              session.get('user', {}).get('uid', 'ANONYMOUS'), 
                              session.get('user', {}).get('username', 'GUEST'), 
                              get_client_ip(), get_client_ua())
                    return redirect(request.url)
                session['_last_post_time'] = current_time
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
        "script-src 'self' 'unsafe-inline' https://kit.fontawesome.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
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
@prevent_double_submit(cooldown_seconds=3)
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        
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
            return redirect(url_for('dashboard'))
        else:
            log_event('SECURITY', 'LOGIN_FAILED', f"พยายามเข้าสู่ระบบล้มเหลวด้วย Username: '{username}'", 
                      "ANONYMOUS", username, get_client_ip(), get_client_ua())
            flash('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user' in session:
        log_event('AUDIT', 'LOGOUT', "ผู้ใช้ออกจากระบบ", 
                  session['user']['uid'], session['user']['username'], get_client_ip(), get_client_ua())
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = session['user']
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

@app.route('/invoices', methods=['GET', 'POST'])
@login_required
@prevent_double_submit(cooldown_seconds=3)
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
        except ValueError as ve:
            flash(str(ve), 'danger')
            
        return redirect(url_for('invoices'))

    txs = get_user_transactions(user['uid'])
    return render_template('invoices.html', user=user, transactions=txs)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN')
@prevent_double_submit(cooldown_seconds=3)
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
            
        if get_user_by_username(username):
            flash('Username นี้ถูกใช้งานแล้ว', 'danger')
            return redirect(url_for('manage_users'))

        try:
            new_uid = create_user(username, password, name, role)
            log_event('AUDIT', 'USER_CREATE', f"Admin สร้างบัญชีผู้ใช้ใหม่: Username '{username}' (Role: {role})", 
                      admin_user['uid'], admin_user['username'], get_client_ip(), get_client_ua())
            flash('เพิ่มบัญชีผู้ใช้งานใหม่เรียบร้อยแล้ว', 'success')
        except ValueError as ve:
            flash(str(ve), 'danger')
            
        return redirect(url_for('manage_users'))

    return render_template('users_manage.html', user=admin_user)

@app.route('/admin/logs')
@login_required
@role_required('ADMIN')
def view_logs():
    admin_user = session['user']
    logs = get_audit_logs(limit=200)
    return render_template('audit_logs.html', user=admin_user, logs=logs)

# --- Error Handlers & Security Incident Logging ---
@app.errorhandler(403)
def forbidden(e):
    user_id = session.get('user', {}).get('uid', 'ANONYMOUS')
    username = session.get('user', {}).get('username', 'GUEST')
    log_event('SECURITY', 'UNAUTHORIZED_ACCESS', f"พยายามเข้าถึงหน้าเพจที่ไม่ได้รับสิทธิ์ (403 Forbidden): {request.path}", 
              user_id, username, get_client_ip(), get_client_ua())
    return render_template('login.html'), 403

@app.errorhandler(429)
def ratelimit_handler(e):
    user_id = session.get('user', {}).get('uid', 'ANONYMOUS')
    username = session.get('user', {}).get('username', 'GUEST')
    log_event('SECURITY', 'RATE_LIMIT_EXCEEDED', f"ทำรายการเกินขีดจำกัดความถี่ (429 Rate Limit): {request.path}", 
              user_id, username, get_client_ip(), get_client_ua())
    flash('คุณทำรายการถี่เกินไป กรุณารอ 1 นาทีแล้วลองใหม่', 'danger')
    return redirect(url_for('login'))

@app.errorhandler(400)
def bad_request(e):
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
    return render_template('login.html'), 500

if __name__ == '__main__':
    is_debug = os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1']
    app.run(debug=is_debug, host='0.0.0.0', port=5000)