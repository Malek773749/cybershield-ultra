// CyberSecurityPro - معالجة النماذج المحسنة
// تم التحديث لتحسين التوافق مع محركات البحث وإعلانات جوجل

// كائن لتخزين حالة النماذج
const FormsManager = {
    forms: {},
    isSubmitting: {},
    validationRules: {},
    init: function() {
        this.setupEventListeners();
        this.initForms();
        this.setupAdSenseCompatibility();
    }
};

document.addEventListener('DOMContentLoaded', function() {
    // تهيئة مدير النماذج
    FormsManager.init();
});

/**
 * إعداد مستمعي الأحداث العامة
 */
FormsManager.setupEventListeners = function() {
    // منع الإرسال المزدوج لجميع النماذج
    document.addEventListener('submit', function(e) {
        const form = e.target;
        if (form.tagName === 'FORM') {
            FormsManager.handleFormSubmit(form, e);
        }
    });

    // تحسين الوصول لوحة المفاتيح
    document.addEventListener('keydown', function(e) {
        // Ctrl+Enter لإرسال النموذج النشط
        if (e.ctrlKey && e.key === 'Enter') {
            const activeForm = document.activeElement.closest('form');
            if (activeForm) {
                FormsManager.submitForm(activeForm);
            }
        }
    });

    // إعادة تعيين النماذج عند إغلاق المودال
    document.addEventListener('hidden.bs.modal', function(e) {
        const modal = e.target;
        const forms = modal.querySelectorAll('form');
        forms.forEach(form => {
            form.reset();
            FormsManager.clearFormValidation(form);
        });
    });
};

/**
 * تهيئة جميع النماذج
 */
FormsManager.initForms = function() {
    // إعداد نماذج محددة
    this.setupIPForm();
    this.setupLinkForm();
    this.setupEmailForm();
    this.setupPasswordForm();
    this.setupWhoisForm();
    this.setupLoginForm();
    this.setupRegisterForm();
    this.setupContactForm();
    this.setupSearchForm();

    // معالجة عامة للنماذج
    this.setupGeneralForms();

    // تسجيل حدث التهيئة
    this.logEvent('forms_initialized', {
        formsCount: Object.keys(this.forms).length,
        timestamp: new Date().toISOString()
    });
};

/**
 * إعداد نموذج فحص IP
 */
FormsManager.setupIPForm = function() {
    const ipForm = document.getElementById('ipForm');
    if (!ipForm) return;

    const ipInput = document.getElementById('ipInput');
    const scanButton = ipForm.querySelector('[type="submit"]');

    // تخزين مرجع النموذج
    this.forms.ipForm = ipForm;

    // التحقق من عنوان IP في الوقت الحقيقي مع debounce
    if (ipInput) {
        ipInput.addEventListener('input', this.debounce(function() {
            const ip = this.value.trim();
            FormsManager.validateIPField(this, ip);
        }, 300));

        // التحقق عند فقدان التركيز
        ipInput.addEventListener('blur', function() {
            FormsManager.validateIPField(this, this.value.trim());
        });

        // إضافة IP الحالي تلقائياً إذا كان متاحاً
        this.prefillCurrentIP(ipInput);
    }

    // إضافة ARIA labels
    if (scanButton && !scanButton.getAttribute('aria-label')) {
        scanButton.setAttribute('aria-label', 'فحص عنوان IP');
    }

    // تسجيل الحدث
    this.logEvent('ip_form_initialized');
};

/**
 * التحقق من حقل IP
 */
FormsManager.validateIPField = function(field, ip) {
    if (!ip) {
        this.clearFieldValidation(field);
        return false;
    }

    // التحقق من صيغة IP (IPv4 و IPv6)
    let isValid = false;
    
    // IPv4
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    
    // IPv6 (تبسيط)
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$/;
    
    if (ipv4Regex.test(ip) || ipv6Regex.test(ip)) {
        isValid = true;
    }

    if (isValid) {
        this.markFieldAsValid(field, 'عنوان IP صالح');
    } else {
        this.markFieldAsInvalid(field, 'عنوان IP غير صالح');
    }

    return isValid;
};

/**
 * تعبئة IP الحالي تلقائياً
 */
FormsManager.prefillCurrentIP = function(field) {
    // استخدام خدمة خارجية للحصول على IP العميل
    if (!field.value && !sessionStorage.getItem('user_ip_fetched')) {
        field.placeholder = 'جاري الحصول على عنوان IP...';
        
        fetch('https://api.ipify.org?format=json')
            .then(response => response.json())
            .then(data => {
                field.placeholder = `مثال: ${data.ip}`;
                field.setAttribute('data-example-ip', data.ip);
                sessionStorage.setItem('user_ip_fetched', 'true');
                sessionStorage.setItem('user_ip', data.ip);
            })
            .catch(error => {
                console.error('فشل في الحصول على IP:', error);
                field.placeholder = 'مثال: 8.8.8.8';
            });
    } else if (sessionStorage.getItem('user_ip')) {
        field.placeholder = `مثال: ${sessionStorage.getItem('user_ip')}`;
    }
};

/**
 * إعداد نموذج فحص الروابط
 */
FormsManager.setupLinkForm = function() {
    const linkForm = document.getElementById('linkForm');
    if (!linkForm) return;

    const linkInput = document.getElementById('linkInput');
    const scanButton = linkForm.querySelector('[type="submit"]');

    // تخزين مرجع النموذج
    this.forms.linkForm = linkForm;

    // التحقق من الرابط في الوقت الحقيقي
    if (linkInput) {
        linkInput.addEventListener('input', this.debounce(function() {
            const url = this.value.trim();
            FormsManager.validateURLField(this, url);
        }, 300));

        linkInput.addEventListener('blur', function() {
            FormsManager.validateURLField(this, this.value.trim());
        });

        // إضافة مثال لرابط
        if (!linkInput.placeholder) {
            linkInput.placeholder = 'https://example.com';
        }
    }

    // إضافة ARIA labels
    if (scanButton && !scanButton.getAttribute('aria-label')) {
        scanButton.setAttribute('aria-label', 'فحص الرابط');
    }

    // تسجيل الحدث
    this.logEvent('link_form_initialized');
};

/**
 * التحقق من حقل الرابط
 */
FormsManager.validateURLField = function(field, url) {
    if (!url) {
        this.clearFieldValidation(field);
        return false;
    }

    let isValid = false;
    let processedUrl = url;

    // إضافة البروتوكول إذا لم يكن موجوداً
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        processedUrl = 'https://' + url;
    }

    // التحقق من صحة الرابط
    try {
        new URL(processedUrl);
        
        // التحقق من أن الرابط يحتوي على نطاق
        const domain = new URL(processedUrl).hostname;
        if (domain && domain.includes('.')) {
            isValid = true;
        }
    } catch (e) {
        isValid = false;
    }

    if (isValid) {
        this.markFieldAsValid(field, 'رابط صالح');
        // تحديث القيمة إذا أضفنا البروتوكول
        if (url !== processedUrl) {
            field.value = processedUrl;
        }
    } else {
        this.markFieldAsInvalid(field, 'رابط غير صالح');
    }

    return isValid;
};

/**
 * إعداد نموذج فحص البريد
 */
FormsManager.setupEmailForm = function() {
    const emailForm = document.getElementById('emailForm');
    if (!emailForm) return;

    const emailInput = document.getElementById('emailInput');
    const scanButton = emailForm.querySelector('[type="submit"]');

    // تخزين مرجع النموذج
    this.forms.emailForm = emailForm;

    // التحقق من البريد في الوقت الحقيقي
    if (emailInput) {
        emailInput.addEventListener('input', this.debounce(function() {
            const email = this.value.trim();
            FormsManager.validateEmailField(this, email);
        }, 300));

        emailInput.addEventListener('blur', function() {
            FormsManager.validateEmailField(this, this.value.trim());
        });

        // تعيين نوع المدخلات للأجهزة المحمولة
        emailInput.type = 'email';
        emailInput.autocomplete = 'email';
    }

    // إضافة ARIA labels
    if (scanButton && !scanButton.getAttribute('aria-label')) {
        scanButton.setAttribute('aria-label', 'فحص البريد الإلكتروني');
    }

    // تسجيل الحدث
    this.logEvent('email_form_initialized');
};

/**
 * التحقق من حقل البريد الإلكتروني
 */
FormsManager.validateEmailField = function(field, email) {
    if (!email) {
        this.clearFieldValidation(field);
        return false;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const isValid = emailRegex.test(email);

    if (isValid) {
        this.markFieldAsValid(field, 'بريد إلكتروني صالح');
        
        // التحقق من النطاقات الشائعة
        const domain = email.split('@')[1];
        const commonDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'];
        if (commonDomains.includes(domain.toLowerCase())) {
            this.showFieldInfo(field, 'نطاق بريد معروف');
        }
    } else {
        this.markFieldAsInvalid(field, 'بريد إلكتروني غير صالح');
    }

    return isValid;
};

/**
 * إعداد نموذج فحص كلمة المرور
 */
FormsManager.setupPasswordForm = function() {
    const passwordForm = document.getElementById('passwordForm');
    if (!passwordForm) return;

    const passwordInput = document.getElementById('passwordInput');
    const checkButton = passwordForm.querySelector('[type="submit"]');
    const toggleButton = document.getElementById('togglePassword');
    const eyeIcon = toggleButton?.querySelector('i');

    // تخزين مرجع النموذج
    this.forms.passwordForm = passwordForm;

    // إعداد زر إظهار/إخفاء كلمة المرور
    if (toggleButton && passwordInput) {
        toggleButton.type = 'button';
        toggleButton.setAttribute('aria-label', 'إظهار/إخفاء كلمة المرور');
        toggleButton.setAttribute('role', 'button');
        toggleButton.tabIndex = 0;

        toggleButton.addEventListener('click', function() {
            FormsManager.togglePasswordVisibility(passwordInput, eyeIcon);
        });

        // تفعيل بالضغط على Enter أو Space
        toggleButton.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                FormsManager.togglePasswordVisibility(passwordInput, eyeIcon);
            }
        });
    }

    // تحليل قوة كلمة المرور في الوقت الحقيقي
    if (passwordInput) {
        passwordInput.addEventListener('input', this.debounce(function() {
            const password = this.value;
            FormsManager.updatePasswordStrength(password);
            
            // تسجيل طول كلمة المرور (للاستخدام التحليلي فقط)
            if (password.length > 0) {
                FormsManager.logEvent('password_typed', {
                    length: password.length,
                    hasSpecialChars: /[!@#$%^&*(),.?":{}|<>]/.test(password),
                    timestamp: new Date().toISOString()
                });
            }
        }, 200));

        // تعيين سمات الوصول
        passwordInput.autocomplete = 'current-password';
        passwordInput.setAttribute('aria-describedby', 'passwordStrengthText');
    }

    // إضافة ARIA labels
    if (checkButton && !checkButton.getAttribute('aria-label')) {
        checkButton.setAttribute('aria-label', 'فحص قوة كلمة المرور');
    }

    // تسجيل الحدث
    this.logEvent('password_form_initialized');
};

/**
 * تبديل رؤية كلمة المرور
 */
FormsManager.togglePasswordVisibility = function(passwordField, eyeIcon) {
    const isPassword = passwordField.type === 'password';
    passwordField.type = isPassword ? 'text' : 'password';
    
    if (eyeIcon) {
        eyeIcon.className = isPassword ? 'bi bi-eye-slash' : 'bi bi-eye';
    }
    
    // تحديث وصف ARIA
    passwordField.setAttribute('aria-describedby', 
        isPassword ? 'passwordHiddenText' : 'passwordVisibleText');
};

/**
 * تحديث قوة كلمة المرور
 */
FormsManager.updatePasswordStrength = function(password) {
    let score = 0;
    const feedback = [];
    const suggestions = [];

    // التحقق من الطول
    if (password.length >= 12) {
        score += 2;
        feedback.push('طول ممتاز');
    } else if (password.length >= 8) {
        score += 1;
        feedback.push('طول جيد');
        if (password.length < 12) {
            suggestions.push('حاول أن تجعل كلمة المرور أطول (12 حرفاً أو أكثر)');
        }
    } else {
        suggestions.push('كلمة المرور قصيرة جداً (8 أحرف على الأقل)');
    }

    // التحقق من الأحرف الكبيرة
    if (/[A-Z]/.test(password)) {
        score += 1;
        feedback.push('تحتوي على أحرف كبيرة');
    } else {
        suggestions.push('أضف حرفاً كبيراً على الأقل');
    }

    // التحقق من الأحرف الصغيرة
    if (/[a-z]/.test(password)) {
        score += 1;
        feedback.push('تحتوي على أحرف صغيرة');
    } else {
        suggestions.push('أضف حرفاً صغيراً على الأقل');
    }

    // التحقق من الأرقام
    if (/\d/.test(password)) {
        score += 1;
        feedback.push('تحتوي على أرقام');
    } else {
        suggestions.push('أضف رقماً على الأقل');
    }

    // التحقق من الرموز الخاصة
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        score += 1;
        feedback.push('تحتوي على رموز خاصة');
    } else {
        suggestions.push('أضف رمزاً خاصاً على الأقل (!@#$% الخ)');
    }

    // التحقق من الأنماط الشائعة
    const commonPatterns = [
        '123456', 'password', 'qwerty', 'admin', 
        '111111', 'abc123', 'password1', '12345678'
    ];
    
    const isCommon = commonPatterns.some(pattern => 
        password.toLowerCase().includes(pattern)
    );
    
    if (!isCommon) {
        score += 1;
        feedback.push('ليست من الأنماط الشائعة');
    } else {
        suggestions.push('تجنب استخدام كلمات المرور الشائعة');
    }

    // التحقق من التكرار
    const hasRepeatingChars = /(.)\1{2,}/.test(password);
    if (!hasRepeatingChars) {
        score += 0.5;
        feedback.push('لا تحتوي على أحرف مكررة بشكل مفرط');
    } else {
        suggestions.push('تجنب تكرار الأحرف بشكل متتالي');
    }

    // التحقق من التسلسل
    const hasSequence = /(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password);
    if (!hasSequence) {
        score += 0.5;
        feedback.push('لا تحتوي على تسلسلات واضحة');
    } else {
        suggestions.push('تجنب التسلسلات الواضحة (abc, 123, الخ)');
    }

    // تحديث العرض
    this.updateStrengthDisplay(score, feedback, suggestions);
};

/**
 * تحديث عرض قوة كلمة المرور
 */
FormsManager.updateStrengthDisplay = function(score, feedback, suggestions) {
    const strengthBar = document.getElementById('passwordStrength');
    const strengthText = document.getElementById('strengthText');
    const feedbackElement = document.getElementById('passwordFeedback');
    const suggestionsElement = document.getElementById('passwordSuggestions');

    if (!strengthBar || !strengthText) return;

    const maxScore = 7;
    let percentage = Math.min((score / maxScore) * 100, 100);
    let color = 'danger';
    let text = 'ضعيفة جداً';
    let textColor = 'danger';

    if (score >= 5) {
        color = 'success';
        text = 'قوية جداً';
        textColor = 'success';
    } else if (score >= 4) {
        color = 'info';
        text = 'قوية';
        textColor = 'info';
    } else if (score >= 3) {
        color = 'warning';
        text = 'متوسطة';
        textColor = 'warning';
    } else if (score >= 2) {
        color = 'secondary';
        text = 'ضعيفة';
        textColor = 'secondary';
    }

    // تحديث شريط القوة
    strengthBar.style.width = percentage + '%';
    strengthBar.className = `progress-bar bg-${color}`;
    strengthBar.setAttribute('aria-valuenow', percentage);
    strengthBar.setAttribute('aria-valuemin', 0);
    strengthBar.setAttribute('aria-valuemax', 100);

    // تحديث النص
    strengthText.textContent = text;
    strengthText.className = `text-${textColor} fw-bold`;

    // تحديث التغذية الراجعة
    if (feedbackElement && feedback.length > 0) {
        feedbackElement.innerHTML = feedback.map(item => 
            `<div class="text-success"><i class="bi bi-check-circle me-1"></i>${item}</div>`
        ).join('');
        feedbackElement.style.display = 'block';
    }

    // تحديث الاقتراحات
    if (suggestionsElement && suggestions.length > 0) {
        suggestionsElement.innerHTML = suggestions.map(item => 
            `<div class="text-warning"><i class="bi bi-lightbulb me-1"></i>${item}</div>`
        ).join('');
        suggestionsElement.style.display = 'block';
    }
};

/**
 * إعداد نموذج فحص النطاق
 */
FormsManager.setupWhoisForm = function() {
    const whoisForm = document.getElementById('whoisForm');
    if (!whoisForm) return;

    const domainInput = document.getElementById('domainInput');
    const scanButton = whoisForm.querySelector('[type="submit"]');

    // تخزين مرجع النموذج
    this.forms.whoisForm = whoisForm;

    // تنظيف إدخال النطاق
    if (domainInput) {
        domainInput.addEventListener('input', this.debounce(function() {
            let value = this.value.toLowerCase();
            // إزالة البروتوكولات والـ www
            value = value.replace(/^(https?:\/\/)?(www\.)?/, '');
            // إزالة المسارات
            value = value.split('/')[0];
            this.value = value;
            
            FormsManager.validateDomainField(this, value);
        }, 300));

        domainInput.addEventListener('blur', function() {
            FormsManager.validateDomainField(this, this.value);
        });

        // إضافة مثال للنطاق
        if (!domainInput.placeholder) {
            domainInput.placeholder = 'example.com';
        }
    }

    // إضافة ARIA labels
    if (scanButton && !scanButton.getAttribute('aria-label')) {
        scanButton.setAttribute('aria-label', 'فحص النطاق');
    }

    // تسجيل الحدث
    this.logEvent('whois_form_initialized');
};

/**
 * التحقق من حقل النطاق
 */
FormsManager.validateDomainField = function(field, domain) {
    if (!domain) {
        this.clearFieldValidation(field);
        return false;
    }

    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/;
    const isValid = domainRegex.test(domain);

    if (isValid) {
        this.markFieldAsValid(field, 'نطاق صالح');
        
        // التحقق من امتدادات النطاقات المعروفة
        const extensions = ['.com', '.org', '.net', '.edu', '.gov'];
        const hasKnownExtension = extensions.some(ext => domain.endsWith(ext));
        if (hasKnownExtension) {
            this.showFieldInfo(field, 'امتداد نطاق معروف');
        }
    } else {
        this.markFieldAsInvalid(field, 'نطاق غير صالح');
    }

    return isValid;
};

/**
 * إعداد نموذج تسجيل الدخول
 */
FormsManager.setupLoginForm = function() {
    const loginForm = document.getElementById('loginForm');
    if (!loginForm) return;

    const loginButton = loginForm.querySelector('[type="submit"]');
    const forgotPasswordLink = loginForm.querySelector('a[href*="forgot"]');

    // تخزين مرجع النموذج
    this.forms.loginForm = loginForm;

    // إضافة نسيت كلمة المرور
    if (forgotPasswordLink) {
        forgotPasswordLink.addEventListener('click', function(e) {
            e.preventDefault();
            FormsManager.showPasswordResetModal();
        });
    }

    // تحسين الوصول
    const inputs = loginForm.querySelectorAll('input');
    inputs.forEach(input => {
        if (input.type === 'email' || input.name.includes('email')) {
            input.autocomplete = 'email';
        } else if (input.type === 'password') {
            input.autocomplete = 'current-password';
        }
    });

    // إضافة ARIA labels
    if (loginButton && !loginButton.getAttribute('aria-label')) {
        loginButton.setAttribute('aria-label', 'تسجيل الدخول');
    }

    // تسجيل الحدث
    this.logEvent('login_form_initialized');
};

/**
 * إعداد نموذج التسجيل
 */
FormsManager.setupRegisterForm = function() {
    const registerForm = document.getElementById('registerForm');
    if (!registerForm) return;

    const registerButton = registerForm.querySelector('[type="submit"]');
    const termsLinks = registerForm.querySelectorAll('a[data-bs-target]');
    const passwordField = registerForm.querySelector('input[type="password"]');
    const confirmPasswordField = registerForm.querySelector('input[name="confirm_password"]');

    // تخزين مرجع النموذج
    this.forms.registerForm = registerForm;

    // التحقق من تطابق كلمات المرور
    if (passwordField && confirmPasswordField) {
        confirmPasswordField.addEventListener('input', this.debounce(function() {
            FormsManager.validatePasswordMatch(passwordField, this);
        }, 300));
    }

    // شروط الخدمة
    termsLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            const modalId = this.getAttribute('data-bs-target');
            const modalElement = document.querySelector(modalId);
            if (modalElement) {
                // يمكن إضافة معالجة إضافية هنا
                FormsManager.logEvent('terms_modal_opened', {
                    modalId: modalId,
                    timestamp: new Date().toISOString()
                });
            }
        });
    });

    // تحسين الوصول
    const inputs = registerForm.querySelectorAll('input');
    inputs.forEach(input => {
        if (input.type === 'email' || input.name.includes('email')) {
            input.autocomplete = 'email';
        } else if (input.type === 'password' && !input.name.includes('confirm')) {
            input.autocomplete = 'new-password';
        } else if (input.name.includes('username')) {
            input.autocomplete = 'username';
        }
    });

    // إضافة ARIA labels
    if (registerButton && !registerButton.getAttribute('aria-label')) {
        registerButton.setAttribute('aria-label', 'إنشاء حساب جديد');
    }

    // تسجيل الحدث
    this.logEvent('register_form_initialized');
};

/**
 * التحقق من تطابق كلمات المرور
 */
FormsManager.validatePasswordMatch = function(passwordField, confirmField) {
    if (!passwordField.value || !confirmField.value) {
        this.clearFieldValidation(confirmField);
        return false;
    }

    const isMatch = passwordField.value === confirmField.value;

    if (isMatch) {
        this.markFieldAsValid(confirmField, 'كلمات المرور متطابقة');
    } else {
        this.markFieldAsInvalid(confirmField, 'كلمات المرور غير متطابقة');
    }

    return isMatch;
};

/**
 * إعداد نموذج الاتصال
 */
FormsManager.setupContactForm = function() {
    const contactForm = document.getElementById('contactForm');
    if (!contactForm) return;

    const submitButton = contactForm.querySelector('[type="submit"]');

    // تخزين مرجع النموذج
    this.forms.contactForm = contactForm;

    // التحقق من حقل الاسم
    const nameInput = contactForm.querySelector('input[name="name"]');
    if (nameInput) {
        nameInput.addEventListener('input', this.debounce(function() {
            FormsManager.validateNameField(this);
        }, 300));
    }

    // التحقق من حقل الرسالة
    const messageInput = contactForm.querySelector('textarea[name="message"]');
    if (messageInput) {
        messageInput.addEventListener('input', this.debounce(function() {
            FormsManager.validateMessageField(this);
        }, 300));
        
        // إعداد العداد
        this.setupCharacterCounter(messageInput, 1000);
    }

    // إضافة ARIA labels
    if (submitButton && !submitButton.getAttribute('aria-label')) {
        submitButton.setAttribute('aria-label', 'إرسال رسالة الاتصال');
    }

    // تسجيل الحدث
    this.logEvent('contact_form_initialized');
};

/**
 * إعداد نموذج البحث
 */
FormsManager.setupSearchForm = function() {
    const searchForm = document.getElementById('searchForm');
    if (!searchForm) return;

    const searchInput = searchForm.querySelector('input[type="search"]');
    const searchButton = searchForm.querySelector('[type="submit"]');

    // تخزين مرجع النموذج
    this.forms.searchForm = searchForm;

    // تحسين تجربة البحث
    if (searchInput) {
        searchInput.autocomplete = 'off';
        searchInput.setAttribute('autocapitalize', 'off');
        searchInput.setAttribute('spellcheck', 'false');

        // البحث أثناء الكتابة (autocomplete)
        searchInput.addEventListener('input', this.debounce(function() {
            FormsManager.handleSearchInput(this);
        }, 500));
    }

    // إضافة ARIA labels
    if (searchButton && !searchButton.getAttribute('aria-label')) {
        searchButton.setAttribute('aria-label', 'بحث في الموقع');
    }

    // تسجيل الحدث
    this.logEvent('search_form_initialized');
};

/**
 * معالجة إدخال البحث
 */
FormsManager.handleSearchInput = function(field) {
    const query = field.value.trim();
    if (query.length < 2) return;

    // يمكن إضافة اقتراحات البحث هنا
    // هذا مثال بسيط
    console.log('بحث عن:', query);
    
    // تسجيل حدث البحث
    this.logEvent('search_typed', {
        query: query,
        length: query.length,
        timestamp: new Date().toISOString()
    });
};

/**
 * معالجة عامة للنماذج
 */
FormsManager.setupGeneralForms = function() {
    // التحقق من المدخلات المطلوبة
    const requiredInputs = document.querySelectorAll('input[required], textarea[required], select[required]');
    
    requiredInputs.forEach(input => {
        input.addEventListener('invalid', function(e) {
            e.preventDefault();
            FormsManager.handleInvalidInput(this);
        });

        input.addEventListener('input', function() {
            FormsManager.clearFieldValidation(this);
        });
    });

    // إعداد النماذج الديناميكية
    this.setupDynamicForms();

    // تحسين نماذج Bootstrap
    this.setupBootstrapForms();
};

/**
 * معالجة الإدخال غير الصالح
 */
FormsManager.handleInvalidInput = function(input) {
    let message = 'هذا الحقل مطلوب';

    if (input.type === 'email') {
        message = 'يرجى إدخال بريد إلكتروني صالح';
    } else if (input.type === 'url') {
        message = 'يرجى إدخال رابط صالح';
    } else if (input.type === 'tel') {
        message = 'يرجى إدخال رقم هاتف صالح';
    } else if (input.hasAttribute('minlength')) {
        const minlength = input.getAttribute('minlength');
        message = `يجب أن يكون ${minlength} أحرف على الأقل`;
    } else if (input.hasAttribute('maxlength')) {
        const maxlength = input.getAttribute('maxlength');
        message = `يجب أن يكون ${maxlength} أحرف على الأكثر`;
    } else if (input.hasAttribute('pattern')) {
        message = 'القيمة غير مطابقة للتنسيق المطلوب';
    }

    this.markFieldAsInvalid(input, message);
    
    // التركيز على الحقل
    input.focus();
};

/**
 * إعداد النماذج الديناميكية
 */
FormsManager.setupDynamicForms = function() {
    // مراقبة إضافة النماذج ديناميكياً
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === 1) { // Element node
                    const forms = node.querySelectorAll ? node.querySelectorAll('form') : [];
                    forms.forEach(form => {
                        if (!FormsManager.forms[form.id]) {
                            FormsManager.setupFormAutomatically(form);
                        }
                    });
                    
                    if (node.tagName === 'FORM' && !FormsManager.forms[node.id]) {
                        FormsManager.setupFormAutomatically(node);
                    }
                }
            });
        });
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
};

/**
 * إعداد النموذج تلقائياً
 */
FormsManager.setupFormAutomatically = function(form) {
    const formId = form.id || 'form_' + Date.now();
    FormsManager.forms[formId] = form;

    // إضافة مستمعي الأحداث الأساسية
    form.addEventListener('submit', function(e) {
        FormsManager.handleFormSubmit(this, e);
    });

    // تحسين الحقول
    const inputs = form.querySelectorAll('input, textarea, select');
    inputs.forEach(input => {
        if (input.type === 'email') {
            input.autocomplete = 'email';
        } else if (input.type === 'password') {
            input.autocomplete = 'current-password';
        }
    });

    FormsManager.logEvent('dynamic_form_added', {
        formId: formId,
        fieldsCount: inputs.length,
        timestamp: new Date().toISOString()
    });
};

/**
 * إعداد نماذج Bootstrap
 */
FormsManager.setupBootstrapForms = function() {
    // إضافة classes لتحسين مظهر النماذج
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        if (!form.classList.contains('needs-validation')) {
            form.classList.add('needs-validation');
        }
    });
};

/**
 * إعداد توافق جوجل أدسنس
 */
FormsManager.setupAdSenseCompatibility = function() {
    // منع تداخل النماذج مع الإعلانات
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        // التأكد من أن النماذج لا تتداخل مع حاويات الإعلانات
        const adContainers = form.querySelectorAll('.adsbygoogle, [class*="ad-"], [id*="ad-"]');
        adContainers.forEach(ad => {
            ad.style.zIndex = '1';
        });

        // منع تأثيرات النماذج على الإعلانات
        form.style.overflow = 'visible';
    });

    // مراقبة النقرات على الإعلانات
    document.addEventListener('click', function(e) {
        if (e.target.closest('.adsbygoogle') || 
            e.target.closest('[class*="ad-"]') || 
            e.target.closest('[id*="ad-"]')) {
            FormsManager.logEvent('ad_click_near_form', {
                target: e.target.tagName,
                timestamp: new Date().toISOString()
            });
        }
    });
};

/**
 * معالجة إرسال النموذج
 */
FormsManager.handleFormSubmit = function(form, event) {
    if (this.isSubmitting[form.id]) {
        event.preventDefault();
        return false;
    }

    // التحقق من النموذج
    if (!this.validateForm(form)) {
        event.preventDefault();
        this.showFormError(form, 'يرجى تصحيح الأخطاء قبل الإرسال');
        return false;
    }

    // تعيين حالة الإرسال
    this.isSubmitting[form.id] = true;

    // إظهار مؤشر التحميل
    const submitButton = form.querySelector('[type="submit"]');
    if (submitButton) {
        this.showLoading(submitButton);
    }

    // إعادة تعيين حالة الإرسال بعد 10 ثوانٍ
    setTimeout(() => {
        this.isSubmitting[form.id] = false;
        if (submitButton) {
            this.hideLoading(submitButton);
        }
    }, 10000);

    // تسجيل حدث الإرسال
    this.logEvent('form_submitted', {
        formId: form.id || 'unknown',
        formAction: form.action || 'unknown',
        method: form.method || 'POST',
        timestamp: new Date().toISOString()
    });
};

/**
 * إرسال النموذج برمجياً
 */
FormsManager.submitForm = function(form) {
    if (form && typeof form.requestSubmit === 'function') {
        form.requestSubmit();
    } else if (form) {
        form.dispatchEvent(new Event('submit', { cancelable: true }));
    }
};

/**
 * التحقق من النموذج كاملاً
 */
FormsManager.validateForm = function(form) {
    let isValid = true;
    const inputs = form.querySelectorAll('input, textarea, select[required]');

    inputs.forEach(input => {
        if (!this.validateField(input)) {
            isValid = false;
        }
    });

    return isValid;
};

/**
 * التحقق من الحقل
 */
FormsManager.validateField = function(field) {
    const value = field.value.trim();
    
    // إذا كان الحقل غير مطلوب وكان فارغاً، نعتبره صالحاً
    if (!field.required && !value) {
        this.clearFieldValidation(field);
        return true;
    }

    // التحقق بناءً على نوع الحقل
    let isValid = true;
    
    switch (field.type) {
        case 'email':
            isValid = this.validateEmailField(field, value);
            break;
        case 'url':
            isValid = this.validateURLField(field, value);
            break;
        case 'password':
            isValid = this.validatePasswordField(field, value);
            break;
        default:
            if (field.hasAttribute('pattern')) {
                const pattern = new RegExp(field.getAttribute('pattern'));
                isValid = pattern.test(value);
                if (!isValid) {
                    this.markFieldAsInvalid(field, 'القيمة غير مطابقة للنمط المطلوب');
                }
            } else {
                isValid = field.checkValidity();
                if (!isValid) {
                    this.handleInvalidInput(field);
                }
            }
    }

    if (isValid && value) {
        this.markFieldAsValid(field);
    }

    return isValid;
};

/**
 * التحقق من حقل كلمة المرور
 */
FormsManager.validatePasswordField = function(field, password) {
    if (!password) {
        return !field.required;
    }

    // التحقق من الحد الأدنى للطول
    if (field.hasAttribute('minlength')) {
        const minlength = parseInt(field.getAttribute('minlength'));
        if (password.length < minlength) {
            this.markFieldAsInvalid(field, `كلمة المرور يجب أن تكون ${minlength} أحرف على الأقل`);
            return false;
        }
    } else if (password.length < 8) {
        this.markFieldAsInvalid(field, 'كلمة المرور يجب أن تكون 8 أحرف على الأقل');
        return false;
    }

    return true;
};

/**
 * التحقق من حقل الاسم
 */
FormsManager.validateNameField = function(field) {
    const value = field.value.trim();
    if (!value && field.required) {
        this.markFieldAsInvalid(field, 'الاسم مطلوب');
        return false;
    }

    if (value && value.length < 2) {
        this.markFieldAsInvalid(field, 'الاسم يجب أن يكون حرفين على الأقل');
        return false;
    }

    if (value) {
        this.markFieldAsValid(field, 'اسم صالح');
    } else {
        this.clearFieldValidation(field);
    }

    return true;
};

/**
 * التحقق من حقل الرسالة
 */
FormsManager.validateMessageField = function(field) {
    const value = field.value.trim();
    if (!value && field.required) {
        this.markFieldAsInvalid(field, 'الرسالة مطلوبة');
        return false;
    }

    if (value && value.length < 10) {
        this.markFieldAsInvalid(field, 'الرسالة قصيرة جداً (10 أحرف على الأقل)');
        return false;
    }

    if (field.hasAttribute('maxlength')) {
        const maxlength = parseInt(field.getAttribute('maxlength'));
        if (value.length > maxlength) {
            this.markFieldAsInvalid(field, `الرسالة طويلة جداً (${maxlength} حرف كحد أقصى)`);
            return false;
        }
    }

    if (value) {
        this.markFieldAsValid(field, 'رسالة صالحة');
    } else {
        this.clearFieldValidation(field);
    }

    return true;
};

/**
 * تعليم الحقل كصالح
 */
FormsManager.markFieldAsValid = function(field, message = '') {
    field.classList.remove('is-invalid');
    field.classList.add('is-valid');
    field.setAttribute('aria-invalid', 'false');
    
    // إزالة رسالة الخطأ القديمة
    const errorId = field.id + '-error';
    const existingError = document.getElementById(errorId);
    if (existingError) {
        existingError.remove();
    }

    // إضافة رسالة النجاح إذا كانت موجودة
    if (message) {
        const successDiv = document.createElement('div');
        successDiv.id = field.id + '-success';
        successDiv.className = 'valid-feedback d-block';
        successDiv.textContent = message;
        field.parentNode.appendChild(successDiv);
    }
};

/**
 * تعليم الحقل كغير صالح
 */
FormsManager.markFieldAsInvalid = function(field, message) {
    field.classList.remove('is-valid');
    field.classList.add('is-invalid');
    field.setAttribute('aria-invalid', 'true');
    
    // إزالة رسالة النجاح القديمة
    const successId = field.id + '-success';
    const existingSuccess = document.getElementById(successId);
    if (existingSuccess) {
        existingSuccess.remove();
    }

    // إزالة رسالة الخطأ القديمة
    this.clearFieldError(field);

    // إضافة رسالة الخطأ الجديدة
    if (message) {
        const errorDiv = document.createElement('div');
        errorDiv.id = field.id + '-error';
        errorDiv.className = 'invalid-feedback d-block';
        errorDiv.textContent = message;
        field.parentNode.appendChild(errorDiv);
        
        // إضافة وصف ARIA
        field.setAttribute('aria-describedby', errorDiv.id);
    }
};

/**
 * إظهار معلومات إضافية للحقل
 */
FormsManager.showFieldInfo = function(field, message) {
    const infoId = field.id + '-info';
    const existingInfo = document.getElementById(infoId);
    
    if (!existingInfo) {
        const infoDiv = document.createElement('div');
        infoDiv.id = infoId;
        infoDiv.className = 'form-text text-info';
        infoDiv.textContent = message;
        field.parentNode.appendChild(infoDiv);
    }
};

/**
 * مسح التحقق من الحقل
 */
FormsManager.clearFieldValidation = function(field) {
    field.classList.remove('is-valid', 'is-invalid');
    field.removeAttribute('aria-invalid');
    
    // إزالة جميع رسائل التغذية الراجعة
    const feedbackIds = ['-error', '-success', '-info'];
    feedbackIds.forEach(suffix => {
        const elementId = field.id + suffix;
        const element = document.getElementById(elementId);
        if (element) {
            element.remove();
        }
    });
};

/**
 * مسح رسالة خطأ الحقل
 */
FormsManager.clearFieldError = function(field) {
    const errorId = field.id + '-error';
    const existingError = document.getElementById(errorId);
    if (existingError) {
        existingError.remove();
    }
    
    // إزالة وصف ARIA إذا كان يحتوي على error فقط
    const describedBy = field.getAttribute('aria-describedby');
    if (describedBy && describedBy.includes('error')) {
        field.removeAttribute('aria-describedby');
    }
};

/**
 * مسح التحقق من النموذج كاملاً
 */
FormsManager.clearFormValidation = function(form) {
    const fields = form.querySelectorAll('input, textarea, select');
    fields.forEach(field => {
        this.clearFieldValidation(field);
    });
};

/**
 * إظهار خطأ في النموذج
 */
FormsManager.showFormError = function(form, message) {
    // إزالة أي أخطاء سابقة
    const existingError = form.querySelector('.form-error-alert');
    if (existingError) {
        existingError.remove();
    }

    // إضافة خطأ جديد
    const errorDiv = document.createElement('div');
    errorDiv.className = 'alert alert-danger form-error-alert mt-3';
    errorDiv.setAttribute('role', 'alert');
    errorDiv.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="bi bi-exclamation-triangle-fill me-2"></i>
            <span>${message}</span>
        </div>
    `;

    form.prepend(errorDiv);

    // تمرير إلى الخطأ الأول
    const firstError = form.querySelector('.is-invalid');
    if (firstError) {
        firstError.scrollIntoView({ behavior: 'smooth', block: 'center' });
        firstError.focus();
    }

    // إخفاء الخطأ بعد 10 ثوانٍ
    setTimeout(() => {
        errorDiv.remove();
    }, 10000);
};

/**
 * إعداد عداد الأحرف
 */
FormsManager.setupCharacterCounter = function(field, maxLength) {
    const counterId = field.id + '-counter';
    let counter = document.getElementById(counterId);
    
    if (!counter) {
        counter = document.createElement('div');
        counter.id = counterId;
        counter.className = 'form-text text-end';
        field.parentNode.appendChild(counter);
    }

    const updateCounter = function() {
        const length = field.value.length;
        counter.textContent = `${length}/${maxLength}`;
        
        if (length > maxLength * 0.9) {
            counter.className = 'form-text text-end text-warning';
        } else if (length > maxLength) {
            counter.className = 'form-text text-end text-danger';
        } else {
            counter.className = 'form-text text-end';
        }
    };

    field.addEventListener('input', updateCounter);
    updateCounter(); // التهيئة الأولية
};

/**
 * إظهار نافذة إعادة تعيين كلمة المرور
 */
FormsManager.showPasswordResetModal = function() {
    // إنشاء وتفعيل المودال
    const modalId = 'passwordResetModal';
    let modal = document.getElementById(modalId);
    
    if (!modal) {
        const modalHTML = `
            <div class="modal fade" id="${modalId}" tabindex="-1" aria-labelledby="${modalId}Label" aria-hidden="true">
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="${modalId}Label">إعادة تعيين كلمة المرور</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="إغلاق"></button>
                        </div>
                        <div class="modal-body">
                            <p class="mb-3">أدخل بريدك الإلكتروني وسنرسل لك رابط إعادة التعيين</p>
                            <div class="mb-3">
                                <label for="resetEmail" class="form-label">البريد الإلكتروني</label>
                                <input type="email" class="form-control" id="resetEmail" placeholder="example@email.com" required>
                                <div class="invalid-feedback">يرجى إدخال بريد إلكتروني صالح</div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">إلغاء</button>
                            <button type="button" class="btn btn-primary" id="resetSubmit">إرسال رابط التعيين</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', modalHTML);
        modal = document.getElementById(modalId);
        
        // إعداد حدث الإرسال
        const resetSubmit = document.getElementById('resetSubmit');
        const resetEmail = document.getElementById('resetEmail');
        
        if (resetSubmit && resetEmail) {
            resetSubmit.addEventListener('click', function() {
                if (FormsManager.validateEmailField(resetEmail, resetEmail.value)) {
                    // محاكاة إرسال الطلب
                    resetSubmit.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>جاري الإرسال...';
                    resetSubmit.disabled = true;
                    
                    setTimeout(() => {
                        FormsManager.logEvent('password_reset_requested', {
                            email: resetEmail.value,
                            timestamp: new Date().toISOString()
                        });
                        
                        // إغلاق المودال وإظهار رسالة نجاح
                        const bsModal = bootstrap.Modal.getInstance(modal);
                        if (bsModal) bsModal.hide();
                        
                        FormsManager.showToast('تم إرسال رابط إعادة التعيين إلى بريدك الإلكتروني', 'success', 5000);
                    }, 1500);
                }
            });
        }
    }
    
    // إظهار المودال
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
};

/**
 * إظهار مؤشر التحميل على الزر
 */
FormsManager.showLoading = function(button, text = 'جاري المعالجة...') {
    if (button) {
        const originalHTML = button.innerHTML;
        const originalWidth = button.offsetWidth;
        
        button.setAttribute('data-original-html', originalHTML);
        button.setAttribute('data-original-width', originalWidth);
        
        button.innerHTML = `
            <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
            ${text}
        `;
        button.style.minWidth = originalWidth + 'px';
        button.disabled = true;
        button.setAttribute('aria-busy', 'true');
    }
};

/**
 * إخفاء مؤشر التحميل من الزر
 */
FormsManager.hideLoading = function(button) {
    if (button) {
        const originalHTML = button.getAttribute('data-original-html');
        const originalWidth = button.getAttribute('data-original-width');
        
        if (originalHTML) {
            button.innerHTML = originalHTML;
            button.removeAttribute('data-original-html');
        }
        
        if (originalWidth) {
            button.style.minWidth = '';
            button.removeAttribute('data-original-width');
        }
        
        button.disabled = false;
        button.removeAttribute('aria-busy');
    }
};

/**
 * دالة مساعدة: Debounce
 */
FormsManager.debounce = function(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func.apply(this, args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
};

/**
 * إظهار رسالة عائمة
 */
FormsManager.showToast = function(message, type = 'info', duration = 3000) {
    if (window.CyberSecurityPro && typeof window.CyberSecurityPro.showToast === 'function') {
        window.CyberSecurityPro.showToast(message, type, duration);
    } else {
        // تنفيذ بديل
        console.log(`[${type.toUpperCase()}] ${message}`);
    }
};

/**
 * تسجيل حدث
 */
FormsManager.logEvent = function(eventName, data = {}) {
    const event = {
        name: eventName,
        ...data,
        _timestamp: new Date().toISOString(),
        _source: 'FormsManager'
    };
    
    // إرسال لـ CyberSecurityPro إذا كان متاحاً
    if (window.CyberSecurityPro && typeof window.CyberSecurityPro.logEvent === 'function') {
        window.CyberSecurityPro.logEvent(eventName, data);
    } else {
        console.log('Form Event:', event);
    }
};

/**
 * تصدير الوظائف للاستخدام العام
 */
window.FormsManager = FormsManager;

// تهيئة نماذج Bootstrap إذا كانت موجودة
if (typeof bootstrap !== 'undefined') {
    document.addEventListener('DOMContentLoaded', function() {
        // إضافة classes للنماذج
        document.querySelectorAll('form').forEach(form => {
            form.classList.add('needs-validation');
        });
    });
}
