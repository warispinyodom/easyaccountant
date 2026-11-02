import time
from datetime import datetime
from firebase_admin import db
import werkzeug.security

try:
    from utils.security import sanitize_input
except ModuleNotFoundError:
    from security import sanitize_input

def get_user_by_username(username):
    username = sanitize_input(username)
    ref = db.reference('users')
    
    try:
        users = ref.order_by_child('username').equal_to(username).get()
    except Exception:
        users = ref.get()
        if isinstance(users, dict):
            for uid, user_data in users.items():
                if isinstance(user_data, dict) and user_data.get('username') == username:
                    user_data['uid'] = uid
                    return user_data
            return None
        return None

    if users and isinstance(users, dict):
        for uid, user_data in users.items():
            user_data['uid'] = uid
            return user_data
    return None

def create_user(username, password, name, role='OWNER'):
    username = sanitize_input(username)
    name = sanitize_input(name)
    role = sanitize_input(role).upper()
    
    if role not in ['ADMIN', 'ACCOUNTANT', 'OWNER']:
        raise ValueError("สิทธิ์การใช้งานไม่ถูกต้อง")

    hashed_pw = werkzeug.security.generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    ref = db.reference('users')
    new_user_ref = ref.push({
        'username': username,
        'password': hashed_pw,
        'name': name,
        'role': role,
        'created_at': {".sv": "timestamp"}
    })
    return new_user_ref.key

def save_transaction(user_id, tx_type, amount, category, description, doc_url=None):
    tx_type = sanitize_input(tx_type).upper()
    category = sanitize_input(category)
    description = sanitize_input(description)
    
    if tx_type not in ['INCOME', 'EXPENSE']:
        raise ValueError("ประเภทรายการไม่ถูกต้อง")
        
    try:
        val_amount = float(amount)
        if val_amount <= 0 or val_amount > 1_000_000_000:
            raise ValueError()
    except ValueError:
        raise ValueError("จำนวนเงินต้องเป็นตัวเลขที่ถูกต้องและมากกว่า 0")

    ref = db.reference('transactions')
    ref.push({
        'user_id': user_id,
        'type': tx_type,
        'amount': val_amount,
        'category': category,
        'description': description,
        'doc_url': doc_url,
        'created_at': {".sv": "timestamp"}
    })

def get_transaction_by_id(tx_id):
    """ ดึงข้อมูลรายการตาม Transaction Key """
    ref = db.reference(f'transactions/{tx_id}')
    tx = ref.get()
    if isinstance(tx, dict):
        tx['id'] = tx_id
        return tx
    return None

def update_transaction(tx_id, user_id, user_role, tx_type, amount, category, description, doc_url=None):
    """ แก้ไขรายการบัญชีพร้อมตรวจสอบสิทธิ์การใช้งาน """
    tx = get_transaction_by_id(tx_id)
    if not tx:
        raise ValueError("ไม่พบรายการที่ต้องการแก้ไข")
    
    # 🔒 Security Check: เจ้าของรายการ หรือ Admin/Accountant เท่านั้นที่มีสิทธิ์แก้ไข
    if tx.get('user_id') != user_id and user_role not in ['ADMIN', 'ACCOUNTANT']:
        raise PermissionError("คุณไม่มีสิทธิ์แก้ไขรายการนี้")

    tx_type = sanitize_input(tx_type).upper()
    category = sanitize_input(category)
    description = sanitize_input(description)

    if tx_type not in ['INCOME', 'EXPENSE']:
        raise ValueError("ประเภทรายการไม่ถูกต้อง")

    try:
        val_amount = float(amount)
        if val_amount <= 0 or val_amount > 1_000_000_000:
            raise ValueError()
    except ValueError:
        raise ValueError("จำนวนเงินต้องเป็นตัวเลขที่ถูกต้องและมากกว่า 0")

    update_data = {
        'type': tx_type,
        'amount': val_amount,
        'category': category,
        'description': description,
        'updated_at': {".sv": "timestamp"}
    }
    if doc_url:
        update_data['doc_url'] = doc_url

    ref = db.reference(f'transactions/{tx_id}')
    ref.update(update_data)
    return True

def delete_transaction(tx_id, user_id, user_role):
    """ ลบรายการบัญชีพร้อมตรวจสอบสิทธิ์การใช้งาน """
    tx = get_transaction_by_id(tx_id)
    if not tx:
        raise ValueError("ไม่พบรายการที่ต้องการลบ")
    
    # 🔒 Security Check: เจ้าของรายการ หรือ Admin/Accountant เท่านั้นที่มีสิทธิ์ลบ
    if tx.get('user_id') != user_id and user_role not in ['ADMIN', 'ACCOUNTANT']:
        raise PermissionError("คุณไม่มีสิทธิ์ลบรายการนี้")

    ref = db.reference(f'transactions/{tx_id}')
    ref.delete()
    return True

def get_user_transactions(user_id):
    ref = db.reference('transactions')
    try:
        txs = ref.order_by_child('user_id').equal_to(user_id).get()
    except Exception:
        all_txs = ref.get()
        if isinstance(all_txs, dict):
            txs = {k: v for k, v in all_txs.items() if isinstance(v, dict) and v.get('user_id') == user_id}
        else:
            txs = None
            
    tx_list = []
    if txs and isinstance(txs, dict):
        for key, val in txs.items():
            if isinstance(val, dict):
                val['id'] = key
                tx_list.append(val)
                
    tx_list.sort(key=lambda x: x.get('created_at', 0) if isinstance(x.get('created_at'), (int, float)) else 0, reverse=True)
    return tx_list

def log_event(category, action, details, user_id="ANONYMOUS", username="GUEST", ip_address="", user_agent=""):
    ref = db.reference('audit_logs')
    ref.push({
        'category': category,
        'action': action,
        'details': details,
        'user_id': user_id,
        'username': username,
        'ip_address': ip_address,
        'user_agent': user_agent[:150],
        'timestamp': {".sv": "timestamp"}
    })

def cleanup_old_audit_logs(days=90):
    ref = db.reference('audit_logs')
    cutoff_time = (time.time() - (days * 24 * 60 * 60)) * 1000
    
    try:
        old_logs = ref.order_by_child('timestamp').end_at(cutoff_time).get()
        if isinstance(old_logs, dict) and old_logs:
            updates = {key: None for key in old_logs.keys()}
            ref.update(updates)
    except Exception:
        all_logs = ref.get()
        if isinstance(all_logs, dict):
            updates = {}
            for key, val in all_logs.items():
                if isinstance(val, dict):
                    ts = val.get('timestamp')
                    if isinstance(ts, (int, float)) and ts <= cutoff_time:
                        updates[key] = None
            if updates:
                ref.update(updates)

def get_audit_logs(limit=150):
    cleanup_old_audit_logs(days=90)
    ref = db.reference('audit_logs')
    try:
        logs = ref.order_by_child('timestamp').limit_to_last(limit).get()
    except Exception:
        logs = ref.get()

    if not logs or not isinstance(logs, dict):
        return []
    
    log_list = []
    for key, val in logs.items():
        if isinstance(val, dict):
            val['id'] = key
            ts = val.get('timestamp')
            if isinstance(ts, (int, float)):
                dt = datetime.fromtimestamp(ts / 1000.0)
                val['formatted_time'] = dt.strftime('%d/%m/%Y %H:%M:%S')
            else:
                val['formatted_time'] = '-'
            log_list.append(val)
        
    log_list.sort(key=lambda x: x.get('timestamp', 0) if isinstance(x.get('timestamp'), (int, float)) else 0, reverse=True)
    return log_list[:limit]