document.addEventListener('DOMContentLoaded', () => {
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

    // 2. Client-side File Upload Validation (Max 5MB & Extension Check)
    const fileInput = document.getElementById('document');
    if (fileInput) {
        const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
        const ALLOWED_EXT = ['png', 'jpg', 'jpeg', 'pdf'];

        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const ext = file.name.split('.').pop().toLowerCase();
            
            // ตรวจสอบนามสกุล
            if (!ALLOWED_EXT.includes(ext)) {
                alert(`❌ ไฟล์ไม่ถูกต้อง! อนุญาตเฉพาะไฟล์นามสกุล: ${ALLOWED_EXT.join(', ')}`);
                fileInput.value = '';
                return;
            }

            // ตรวจสอบขนาดไฟล์
            if (file.size > MAX_FILE_SIZE) {
                alert(`❌ ขนาดไฟล์ใหญ่เกินขีดจำกัด! (ขนาดสูงสุดไม่เกิน 5 MB)`);
                fileInput.value = '';
                return;
            }
        });
    }

    // 3. Realtime Password Policy Checker (หน้าเพิ่มผู้ใช้งาน)
    const passwordInput = document.getElementById('password');
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
            if (isValid) {
                element.classList.add('valid');
                element.querySelector('i').className = 'fa-solid fa-circle-check';
            } else {
                element.classList.remove('valid');
                element.querySelector('i').className = 'fa-solid fa-circle-xmark';
            }
        }
    }

    // 4. UX Guard: Prevent Double-Submit & Disable Button with Loading Spinner
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function (e) {
            if (form.dataset.submitting === 'true') {
                e.preventDefault();
                return false;
            }

            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                form.dataset.submitting = 'true';
                submitBtn.disabled = true;
                submitBtn.classList.add('disabled-loading');
                
                // แสดง Spinner และข้อความกำลังดำเนินการ
                submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> กำลังดำเนินการ...`;
            }
        });
    });
});