/* =====================================================================
   🚀 CYBERSHIELD ULTRA v4.0 - HYBRID AI ANALYZER ENGINE
   =====================================================================
   🔥 17 Tools | 22 Arab Countries | Zero Dependencies | Enterprise Grade
   ===================================================================== */
(function() {
    "use strict";

    // ---------- ذاكرة تخزين مؤقت ذكية ----------
    const AnalyzerCache = {
        _c: new Map(),
        _m: 200,
        get(k) {
            const i = this._c.get(k);
            if (!i) return null;
            if (Date.now() > i.e) {
                this._c.delete(k);
                return null;
            }
            this._c.delete(k);
            this._c.set(k, i);
            return i.v;
        },
        set(k, v, t = 3600000) {
            if (this._c.size >= this._m) {
                const f = this._c.keys().next().value;
                this._c.delete(f);
            }
            this._c.set(k, { v, e: Date.now() + t });
        }
    };

    // ---------- تنقية XSS ----------
    window.escapeHTML = function(str) {
        if (!str) return '';
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '/': '&#x2F;',
            '`': '&#x60;',
            '=': '&#x3D;'
        };
        return String(str).replace(/[&<>"'`=/]/g, c => map[c]);
    };

    // ---------- محرك تحليل المخاطر ----------
    window.RiskAnalyzer = {
        getLevel(s) {
            if (s < 20) return { class: 'badge-safe', text: 'آمن جداً', icon: '🟢', color: '#10b981' };
            if (s < 40) return { class: 'badge-low', text: 'منخفض', icon: '🟡', color: '#fbbf24' };
            if (s < 60) return { class: 'badge-medium', text: 'متوسط', icon: '🟠', color: '#f97316' };
            if (s < 80) return { class: 'badge-high', text: 'مرتفع', icon: '🔴', color: '#ef4444' };
            return { class: 'badge-critical', text: 'حرج جداً', icon: '💀', color: '#7f1d1d' };
        },

        renderProgress(id, p, c) {
            const el = document.getElementById(id);
            if (!el) return;
            const bar = document.createElement('div');
            bar.className = `progress-bar ${c}`;
            bar.style.width = '0%';
            el.innerHTML = '';
            el.appendChild(bar);
            requestAnimationFrame(() => bar.style.width = `${p}%`);
        },

        analyzeSignals(sigs) {
            const r = { critical: [], high: [], medium: [], low: [] };
            sigs.forEach(s => {
                if (s.includes('CRITICAL') || s.includes('INJECTION') || s.includes('NONE')) r.critical.push(s);
                else if (s.includes('SUSPICIOUS') || s.includes('MALWARE') || s.includes('DANGEROUS')) r.high.push(s);
                else if (s.includes('WEAK') || s.includes('DISPOSABLE') || s.includes('FAKE')) r.medium.push(s);
                else r.low.push(s);
            });
            return r;
        }
    };

    // ---------- أيقونات وأسماء الأدوات ----------
    const ToolIcons = {
        phone: '📱', email: '📧', password: '🔐', url: '🌍', domain: '🌐', ip: '🔌',
        username: '👤', hash: '🔑', base64: '🔍', credit_card: '💳', port: '🚪',
        api_key: '🔐', filename: '📁', jwt: '🔑', useragent: '🧑', file: '📄', dns: '🌐'
    };

    const ToolNames = {
        phone: 'الهاتف', email: 'البريد', password: 'كلمة المرور', url: 'الرابط',
        domain: 'النطاق', ip: 'IP', username: 'اسم المستخدم', hash: 'التجزئة',
        base64: 'Base64', credit_card: 'البطاقة', port: 'المنفذ', api_key: 'مفتاح API',
        filename: 'الملف', jwt: 'JWT', useragent: 'وكيل المستخدم', file: 'الملف', dns: 'DNS'
    };

    // ---------- ✅ ترجمة المفاتيح - مكتملة 100% ----------
    const KeyTranslation = {
        // 📱 الهاتف
        'valid_format': 'صيغة صحيحة',
        'country': 'الدولة',
        'country_code': 'رمز الدولة',
        'iso': 'الرمز الدولي',
        'carrier': 'المشغل',
        'line_type': 'نوع الخط',
        'is_fake': 'رقم وهمي',
        'is_emergency': 'رقم طوارئ',
        'entropy': 'الانتروبيا',

        // 📧 البريد
        'local_part': 'الجزء المحلي',
        'domain': 'النطاق',
        'tld': 'النطاق العلوي',
        'is_disposable': 'بريد مؤقت',
        'is_spoof': 'بريد مزيف',
        'is_free_provider': 'مزود مجاني',

        // 🔐 كلمة المرور
        'length': 'الطول',
        'strength': 'القوة',
        'crack_time': 'وقت الكسر',
        'char_types': 'أنواع الحروف',
        'score': 'الدرجة',
        'has_lower': 'يحتوي أحرف صغيرة',
        'has_upper': 'يحتوي أحرف كبيرة',
        'has_digit': 'يحتوي أرقام',
        'has_special': 'يحتوي رموز خاصة',
        'is_common': 'كلمة شائعة',
        'is_sequential': 'نمط تسلسلي',
        'is_keyboard': 'نمط لوحة مفاتيح',
        'has_repeated': 'نمط مكرر',

        // 🌍 الروابط
        'normalized': 'الرابط الطبيعي',
        'scheme': 'البروتوكول',
        'host': 'المضيف',
        'path': 'المسار',
        'is_https': 'اتصال آمن',
        'is_ip': 'رابط IP',
        'is_shortener': 'رابط مختصر',
        'has_punycode': 'نطاق Punycode',
        'is_phishing': 'رابط تصيد',
        'path_depth': 'عمق المسار',

        // 🌐 النطاقات
        'sld': 'النطاق الرئيسي',
        'subdomain_count': 'عدد النطاقات الفرعية',
        'suspicious_tld': 'نطاق علوي مشبوه',
        'has_lookalike': 'أحرف مشابهة',
        'subdomains': 'النطاقات الفرعية',

        // 🔌 IP
        'valid': 'صحيح',
        'is_valid': 'صحيح',
        'version': 'الإصدار',
        'is_private': 'IP خاص',
        'is_loopback': 'IP استرجاع',
        'is_reserved': 'IP محجوز',
        'is_multicast': 'IP متعدد الإرسال',
        'is_global': 'IP عام',
        'compressed': 'مضغوط',
        'exploded': 'مفصل',

        // 👤 اسم المستخدم
        'username': 'اسم المستخدم',
        'is_all_numeric': 'كله أرقام',
        'is_all_alpha': 'كله حروف',
        'has_special': 'يحتوي رموز خاصة',
        'is_email_like': 'يشبه البريد',
        'bot_pattern_score': 'درجة نمط البوت',

        // 🔑 التجزئة
        'algorithm': 'الخوارزمية',
        'is_hash': 'هل هو تجزئة',
        'is_weak': 'خوارزمية ضعيفة',

        // 🔍 Base64
        'is_base64': 'هل هو Base64',
        'has_padding': 'يحتوي حشو',
        'decoded': 'المفكوك',

        // 💳 بطاقة الائتمان
        'masked': 'مخفي',
        'valid_length': 'طول صحيح',
        'luhn_valid': 'لوهن صحيح',
        'issuer': 'المصدر',
        'is_test': 'بطاقة اختبار',

        // 🚪 المنافذ
        'port': 'المنفذ',
        'service': 'الخدمة',
        'is_dangerous': 'منفذ خطير',

        // 🔑 مفاتيح API
        'detected': 'المكتشفة',

        // 📁 أسماء الملفات
        'extension': 'الامتداد',
        'is_dangerous': 'امتداد خطير',
        'detected_patterns': 'الأنماط المكتشفة',

        // 🔐 JWT
        'is_jwt': 'هل هو JWT',
        'parts': 'الأجزاء',
        'expired': 'منتهي الصلاحية',
        'issuer': 'المصدر',
        'subject': 'الموضوع',

        // 🧑 User-Agent
        'is_allowed_bot': 'بوت مسموح',
        'is_malicious_bot': 'بوت خبيث',
        'bot_type': 'نوع البوت',

        // 📄 الملفات
        'filename': 'اسم الملف',
        'size': 'الحجم',
        'size_formatted': 'الحجم',
        'detected_type': 'النوع المكتشف',
        'mime_type': 'نوع MIME',
        'risk_score': 'درجة الخطر',
        'risk_level': 'مستوى الخطر',
        'threats': 'التهديدات',
        'scan_time': 'وقت الفحص',

        // 🌐 DNS
        'record': 'السجل',
        'type': 'النوع',
        'resolved': 'تم الحل',
        'dnssec': 'DNSSEC',
        'details': 'التفاصيل'
    };

    // ---------- API الخادم ----------
    window.API = {
        async scan(tool, input, options = {}) {
            const { timeout = 15000, cache = true } = options;
            if (!input?.trim()) throw new Error('INPUT_REQUIRED');

            const key = `${tool}:${input}`;
            if (cache) {
                const cached = AnalyzerCache.get(key);
                if (cached) return cached;
            }

            const controller = new AbortController();
            const tid = setTimeout(() => controller.abort(), timeout);

            try {
                const payload = { [tool]: input };
                const res = await fetch(`/api/v1/scan/${tool}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Request-ID': crypto.randomUUID?.() || Date.now().toString(36)
                    },
                    body: JSON.stringify(payload),
                    signal: controller.signal
                });

                clearTimeout(tid);
                const data = await res.json();
                if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`);

                if (cache) AnalyzerCache.set(key, data, 300000);
                return data;
            } catch (e) {
                if (e.name === 'AbortError') throw new Error('TIMEOUT');
                throw e;
            }
        }
    };

    // ---------- محرك العرض ----------
    window.ResultRenderer = {
        render(data, containerId) {
            const container = document.getElementById(containerId);
            if (!container) return;

            const risk = window.RiskAnalyzer.getLevel(data.risk_score);
            const signals = window.RiskAnalyzer.analyzeSignals(data.analysis?.signals || []);

            let analysisHtml = '', signalsHtml = '';

            // ✅ تحليل مفصل - مع ترجمة جميع المفاتيح
            if (data.analysis) {
                analysisHtml = '<div class="analysis-grid">';
                Object.entries(data.analysis).forEach(([k, v]) => {
                    if (!['signals', '_cache', 'entropy'].includes(k) && v !== null && v !== undefined && typeof v !== 'object') {
                        if (typeof v === 'string' && v.length > 100) return;

                        const key = KeyTranslation[k] || k.replace(/_/g, ' ');
                        let val = v;
                        if (typeof v === 'boolean') val = v ? 'نعم' : 'لا';
                        if (typeof v === 'number' && v > 999) val = v.toLocaleString('ar-SA');

                        analysisHtml += `
                            <div class="analysis-item">
                                <span class="analysis-key">${key}</span>
                                <span class="analysis-value ${typeof v === 'boolean' ? (v ? 'success' : 'danger') : ''}">${val}</span>
                            </div>
                        `;
                    }
                });
                analysisHtml += '</div>';
            }

            // ✅ الإشارات الأمنية
            if (signals.critical.length || signals.high.length || signals.medium.length || signals.low.length) {
                signalsHtml = '<div class="signals-section"><h4 class="signals-title">🔍 الإشارات الأمنية</h4><div class="signals-grid">';
                signals.critical.forEach(s => signalsHtml += `<span class="signal-tag signal-critical">⚠️ ${escapeHTML(s)}</span>`);
                signals.high.forEach(s => signalsHtml += `<span class="signal-tag signal-high">🔴 ${escapeHTML(s)}</span>`);
                signals.medium.forEach(s => signalsHtml += `<span class="signal-tag signal-medium">🟠 ${escapeHTML(s)}</span>`);
                signals.low.forEach(s => signalsHtml += `<span class="signal-tag signal-low">🟡 ${escapeHTML(s)}</span>`);
                signalsHtml += '</div></div>';
            }

            const progressId = `progress-${Date.now()}`;

            container.innerHTML = `
                <div class="result-card" data-tool="${data.tool}">
                    <div class="result-header">
                        <div>
                            <span class="result-badge">اكتمل التحليل</span>
                            <h3 class="result-title">
                                <span class="result-icon">${ToolIcons[data.tool] || '🛡️'}</span>
                                تحليل ${ToolNames[data.tool] || data.tool}
                            </h3>
                            <span class="badge ${risk.class}" style="background:${risk.color}20; color:${risk.color}; border-color:${risk.color}40;">
                                ${risk.icon} الخطر: ${risk.text} (${data.risk_score}/١٠٠)
                            </span>
                        </div>
                        <span class="result-shield">🛡️</span>
                    </div>

                    <div class="confidence-meter">
                        <div class="confidence-header">
                            <span>🧠 ثقة الذكاء الاصطناعي</span>
                            <span class="confidence-value">${data.confidence}%</span>
                        </div>
                        <div id="${progressId}" class="progress-container"></div>
                    </div>

                    <div class="ai-insight">
                        <span class="ai-icon">🧠</span>
                        <span class="ai-label">رؤية الذكاء الاصطناعي</span>
                        <p class="ai-text">${escapeHTML(data.ai_insight || 'تم التحليل بواسطة محرك المخاطر الهجين v4.0')}</p>
                    </div>

                    ${analysisHtml}
                    ${signalsHtml}

                    <div class="result-footer">
                        <span class="meta-item">📌 الإدخال: ${escapeHTML(data.input || '').substring(0, 50)}${(data.input || '').length > 50 ? '…' : ''}</span>
                        <span class="meta-item">🕒 ${new Date(data.timestamp || Date.now()).toLocaleString('ar-SA')}</span>
                    </div>
                </div>
            `;

            // ✅ تشغيل شريط التقدم
            setTimeout(() => {
                window.RiskAnalyzer.renderProgress(progressId, data.confidence,
                    risk.class.replace('badge-', 'progress-'));
            }, 50);
        }
    };

    console.log('🚀 CyberShield Ultra Analyzer v4.0 Loaded - 17 Tools Ready');
})();