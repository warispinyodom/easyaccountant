// ==========================================
// 0. SweetAlert2 Flash Notification Handler
// ==========================================
function triggerSweetAlertFlash() {
    const flashEl = document.getElementById('flash-messages-data');
    if (!flashEl) return;

    try {
        const rawJson = flashEl.textContent ? flashEl.textContent.trim() : '';
        if (!rawJson) return;

        const messages = JSON.parse(rawJson);
        if (!Array.isArray(messages) || messages.length === 0) return;

        // หาก SweetAlert2 พร้อมทำงาน ให้ซ่อนกล่อง HTML Alert ป้องกันการแสดงผลซ้ำ
        if (typeof Swal !== 'undefined') {
            const htmlAlertBox = document.getElementById('html-alert-box');
            if (htmlAlertBox) {
                htmlAlertBox.style.display = 'none';
            }

            messages.forEach(([category, msg]) => {
                let iconType = 'info';
                let titleText = 'แจ้งเตือนระบบ';

                if (category === 'success') {
                    iconType = 'success';
                    titleText = 'ทำรายการสำเร็จ';
                } else if (category === 'warning') {
                    iconType = 'warning';
                    titleText = 'คำเตือนจากระบบ';
                } else if (category === 'danger' || category === 'error') {
                    iconType = 'error';
                    titleText = 'เกิดข้อผิดพลาด';
                }

                Swal.fire({
                    icon: iconType,
                    title: titleText,
                    text: msg,
                    confirmButtonColor: iconType === 'error' ? '#ef4444' : '#0f766e',
                    confirmButtonText: 'ตกลง',
                    timer: category === 'success' ? 3500 : undefined,
                    timerProgressBar: category === 'success'
                });
            });
        }
    } catch (err) {
        console.error('SweetAlert Flash Parse Error:', err);
    }
}

// ตรวจสอบการสั่งทำงานทันทีที่ DOM หรือ Window พร้อม
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

function initApp() {
    triggerSweetAlertFlash();

    // 1. Mobile Navigation Toggle
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const sidebar = document.getElementById('sidebar');

    if (mobileMenuBtn && sidebar) {
        mobileMenuBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            sidebar.classList.toggle('active');
        });

        document.addEventListener('click', (e) => {
            if (!sidebar.contains(e.target) && !mobileMenuBtn.contains(e.target)) {
                sidebar.classList.remove('active');
            }
        });
    }

    // 2. Client-side File Upload Validation Guard
    const fileInputs = document.querySelectorAll('input[type="file"]');
    const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
    const ALLOWED_EXT = ['png', 'jpg', 'jpeg', 'pdf'];

    fileInputs.forEach(fileInput => {
        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const ext = file.name.split('.').pop().toLowerCase();
            
            if (!ALLOWED_EXT.includes(ext)) {
                if (typeof Swal !== 'undefined') {
                    Swal.fire({
                        icon: 'error',
                        title: 'ประเภทไฟล์ไม่ถูกต้อง',
                        text: `อนุญาตเฉพาะไฟล์นามสกุล: ${ALLOWED_EXT.join(', ').toUpperCase()}`,
                        confirmButtonColor: '#ef4444',
                        confirmButtonText: 'ตกลง'
                    });
                } else {
                    alert(`❌ ไฟล์ไม่ถูกต้อง! อนุญาตเฉพาะไฟล์นามสกุล: ${ALLOWED_EXT.join(', ')}`);
                }
                fileInput.value = '';
                return;
            }

            if (file.size > MAX_FILE_SIZE) {
                if (typeof Swal !== 'undefined') {
                    Swal.fire({
                        icon: 'error',
                        title: 'ไฟล์มีขนาดใหญ่เกินไป',
                        text: 'ขนาดไฟล์สูงสุดไม่เกิน 5 MB กรุณาเลือกไฟล์ใหม่',
                        confirmButtonColor: '#ef4444',
                        confirmButtonText: 'ตกลง'
                    });
                } else {
                    alert(`❌ ขนาดไฟล์ใหญ่เกินขีดจำกัด! (ขนาดสูงสุดไม่เกิน 5 MB)`);
                }
                fileInput.value = '';
                return;
            }
        });
    });

    // 3. Realtime Password Policy Checker
    const passwordInput = document.getElementById('password');
    const userForm = document.getElementById('userForm');

    if (passwordInput) {
        const rules = {
            length: document.getElementById('rule-length'),
            upper: document.getElementById('rule-upper'),
            lower: document.getElementById('rule-lower'),
            number: document.getElementById('rule-number'),
            special: document.getElementById('rule-special')
        };

        passwordInput.addEventListener('input', (e) => {
            const val = e.target.value;

            updateRule(rules.length, val.length >= 8);
            updateRule(rules.upper, /[A-Z]/.test(val));
            updateRule(rules.lower, /[a-z]/.test(val));
            updateRule(rules.number, /[0-9]/.test(val));
            updateRule(rules.special, /[!@#$%^&*(),.?":{}|<>]/.test(val));
        });

        function updateRule(element, isValid) {
            if (!element) return;
            const icon = element.querySelector('i');
            if (isValid) {
                element.classList.add('valid');
                if (icon) icon.className = 'fa-solid fa-circle-check';
            } else {
                element.classList.remove('valid');
                if (icon) icon.className = 'fa-solid fa-circle-xmark';
            }
        }
    }

    if (userForm && passwordInput) {
        userForm.addEventListener('submit', (e) => {
            const val = passwordInput.value;
            const isValid = val.length >= 8 && /[A-Z]/.test(val) && /[a-z]/.test(val) && /[0-9]/.test(val) && /[!@#$%^&*(),.?":{}|<>]/.test(val);
            
            if (!isValid) {
                e.preventDefault();
                userForm.dataset.submitting = 'false';
                const submitBtn = userForm.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.classList.remove('disabled-loading');
                    submitBtn.innerHTML = `<i class="fa-solid fa-check"></i> ยืนยันสร้างบัญชี`;
                }

                if (typeof Swal !== 'undefined') {
                    Swal.fire({
                        icon: 'warning',
                        title: 'รหัสผ่านไม่ผ่านเกณฑ์ความปลอดภัย',
                        text: 'กรุณากำหนดรหัสผ่านให้ครบ 8 ตัวอักษร, พิมพ์ใหญ่, พิมพ์เล็ก, ตัวเลข และอักขระพิเศษ',
                        confirmButtonColor: '#0f766e',
                        confirmButtonText: 'ตกลง'
                    });
                } else {
                    alert('กรุณากำหนดรหัสผ่านให้ครบถ้วนตามเกณฑ์ความปลอดภัย');
                }
            }
        });
    }

    // 4. UX Guard: Double-Submit Protection
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function (e) {
            if (form.dataset.awaitingConfirm === 'true') {
                return;
            }

            if (form.dataset.submitting === 'true') {
                e.preventDefault();
                return false;
            }

            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                form.dataset.submitting = 'true';
                submitBtn.disabled = true;
                submitBtn.classList.add('disabled-loading');
                submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> กำลังดำเนินการ...`;
            }
        });
    });

    // 5. Global Modal Backdrop & ESC Key Handler
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        });
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            modals.forEach(modal => modal.style.display = 'none');
        }
    });
}

// 6. Global SweetAlert2 Delete Confirmation
function confirmDelete(event, form) {
    event.preventDefault();
    form.dataset.awaitingConfirm = 'true';

    if (typeof Swal !== 'undefined') {
        Swal.fire({
            title: 'ยืนยันการลบรายการ?',
            text: "เมื่อลบแล้ว รายการนี้จะไม่สามารถกู้คืนได้อีก!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#ef4444',
            cancelButtonColor: '#64748b',
            confirmButtonText: '<i class="fa-solid fa-trash-can"></i> ใช่, ลบรายการ',
            cancelButtonText: 'ยกเลิก',
            reverseButtons: true
        }).then((result) => {
            if (result.isConfirmed) {
                form.dataset.awaitingConfirm = 'false';
                const submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.classList.add('disabled-loading');
                    submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> กำลังลบ...`;
                }
                form.submit();
            } else {
                form.dataset.awaitingConfirm = 'false';
            }
        });
    } else {
        if (confirm('คุณแน่ใจหรือไม่ว่าต้องการลบรายการนี้?')) {
            form.dataset.awaitingConfirm = 'false';
            form.submit();
        } else {
            form.dataset.awaitingConfirm = 'false';
        }
    }
    return false;
}