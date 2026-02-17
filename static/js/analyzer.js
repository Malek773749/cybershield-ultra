/* =====================================================================
   🚀 CYBERSHIELD ULTRA v4.5 - HYBRID AI ANALYZER ENGINE (ULTIMATE EDITION)
   =====================================================================
   🔥 17 Tools | 22 Arab Countries | Zero Dependencies | Enterprise Grade
   💫 Advanced Cache | Full XSS Protection | Complete Arabic Translation
   ===================================================================== */

(function() {
    "use strict";

    // =================================================================
    // 🧠 ADVANCED CACHE SYSTEM - LRU + TTL + AUTO CLEANUP
    // =================================================================
    const AnalyzerCache = {
        _cache: new Map(),
        _maxSize: 250, // زيادة سعة التخزين
        _defaultTTL: 3600000, // ساعة واحدة
        _hits: 0,
        _misses: 0,

        get(key) {
            const item = this._cache.get(key);
            if (!item) {
                this._misses++;
                return null;
            }

            if (Date.now() > item.expires) {
                this._cache.delete(key);
                this._misses++;
                return null;
            }

            // LRU: حذف وإعادة إضافة لآخر القائمة
            this._cache.delete(key);
            this._cache.set(key, item);
            this._hits++;
            return item.value;
        },

        set(key, value, ttl = this._defaultTTL) {
            if (this._cache.size >= this._maxSize) {
                // حذف أقدم عنصر (أول عنصر في Map)
                const oldestKey = this._cache.keys().next().value;
                this._cache.delete(oldestKey);
            }

            this._cache.set(key, {
                value,
                expires: Date.now() + ttl,
                created: Date.now()
            });
        },

        clear() {
            this._cache.clear();
            this._hits = 0;
            this._misses = 0;
        },

        getStats() {
            const total = this._hits + this._misses;
            return {
                size: this._cache.size,
                maxSize: this._maxSize,
                hits: this._hits,
                misses: this._misses,
                hitRate: total > 0 ? Math.round((this._hits / total) * 100) : 0
            };
        },

        // تنظيف تلقائي للعناصر منتهية الصلاحية
        cleanup() {
            const now = Date.now();
            for (const [key, item] of this._cache.entries()) {
                if (now > item.expires) {
                    this._cache.delete(key);
                }
            }
        }
    };

    // تشغيل التنظيف التلقائي كل 5 دقائق
    setInterval(() => AnalyzerCache.cleanup(), 300000);

    // =================================================================
    // 🛡️ ULTIMATE XSS PROTECTION - تغطية جميع الرموز الخطيرة
    // =================================================================
    window.escapeHTML = (function() {
        const entityMap = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '/': '&#x2F;',
            '`': '&#x60;',
            '=': '&#x3D;',
            '\\': '&#92;',
            '(': '&#40;',
            ')': '&#41;',
            '{': '&#123;',
            '}': '&#125;',
            '[': '&#91;',
            ']': '&#93;'
        };

        return function(str) {
            if (str === null || str === undefined) return '';
            if (typeof str !== 'string') str = String(str);
            return str.replace(/[&<>"'`=\/\\(){}[\]']/g, c => entityMap[c] || c);
        };
    })();

    // =================================================================
    // 📊 RISK ANALYZER ENGINE - مع تصنيف متقدم
    // =================================================================
    window.RiskAnalyzer = {
        // مستويات الخطر مع ألوان وأيقونات محدثة
        levels: [
            { max: 20, class: 'badge-safe', text: 'آمن جداً', icon: '🟢', color: '#10b981', progress: 'progress-safe' },
            { max: 40, class: 'badge-low', text: 'منخفض', icon: '🟡', color: '#fbbf24', progress: 'progress-low' },
            { max: 60, class: 'badge-medium', text: 'متوسط', icon: '🟠', color: '#f97316', progress: 'progress-medium' },
            { max: 80, class: 'badge-high', text: 'مرتفع', icon: '🔴', color: '#ef4444', progress: 'progress-high' },
            { max: 100, class: 'badge-critical', text: 'حرج جداً', icon: '💀', color: '#7f1d1d', progress: 'progress-critical' }
        ],

        getLevel(score) {
            const level = this.levels.find(l => score < l.max) || this.levels[this.levels.length - 1];
            return {
                ...level,
                bgColor: `${level.color}20`,
                borderColor: `${level.color}40`
            };
        },

        renderProgress(containerId, percentage, progressClass) {
            const container = document.getElementById(containerId);
            if (!container) return;

            // تحسين الأداء - استخدام DocumentFragment
            const fragment = document.createDocumentFragment();
            const bar = document.createElement('div');
            bar.className = `progress-bar ${progressClass}`;
            bar.style.width = '0%';
            bar.setAttribute('role', 'progressbar');
            bar.setAttribute('aria-valuenow', percentage);
            bar.setAttribute('aria-valuemin', '0');
            bar.setAttribute('aria-valuemax', '100');

            fragment.appendChild(bar);
            container.innerHTML = '';
            container.appendChild(fragment);

            // استخدام requestAnimationFrame لحركة سلسة
            requestAnimationFrame(() => {
                bar.style.width = `${percentage}%`;
            });
        },

        analyzeSignals(signals) {
            const result = { critical: [], high: [], medium: [], low: [] };

            if (!Array.isArray(signals)) return result;

            // أنماط متقدمة للتصنيف
            const patterns = {
                critical: [/CRITICAL/i, /INJECTION/i, /NONE/i, /EXECUTABLE/i, /MALICIOUS/i, /PHISHING/i],
                high: [/SUSPICIOUS/i, /MALWARE/i, /DANGEROUS/i, /HIGH/i, /EMERGENCY/i],
                medium: [/WEAK/i, /DISPOSABLE/i, /FAKE/i, /MEDIUM/i, /SPOOF/i],
                low: [/LOW/i, /INFO/i, /NOTE/i]
            };

            signals.forEach(signal => {
                const sigStr = String(signal);
                if (patterns.critical.some(p => p.test(sigStr))) result.critical.push(signal);
                else if (patterns.high.some(p => p.test(sigStr))) result.high.push(signal);
                else if (patterns.medium.some(p => p.test(sigStr))) result.medium.push(signal);
                else result.low.push(signal);
            });

            return result;
        },

        // دالة مساعدة للحصول على توصيات بناءً على الإشارات
        getRecommendations(signals) {
            const recommendations = [];
            const signalMap = {
                'FAKE_NUMBER': 'استخدم أرقاماً حقيقية للتحقق',
                'DISPOSABLE_EMAIL': 'استخدم بريداً دائماً للحسابات المهمة',
                'COMMON_PASSWORD': 'كلمة المرور شائعة جداً - استخدم كلمة أقوى',
                'WEAK_HASH': 'استخدم خوارزمية تجزئة أقوى مثل SHA-256',
                'DANGEROUS_PORT': 'أغلق هذا المنفذ إذا كان غير ضروري',
                'SUSPICIOUS_TLD': 'كن حذراً - هذا النطاق قد يكون مشبوهاً',
                'IP_PRIVATE': 'هذا IP خاص - غير قابل للتوجيه على الإنترنت',
                'IP_LOOPBACK': 'هذا IP استرجاع - يستخدم محلياً فقط'
            };

            signals.forEach(s => {
                const rec = signalMap[String(s)];
                if (rec && !recommendations.includes(rec)) {
                    recommendations.push(rec);
                }
            });

            return recommendations;
        }
    };

    // =================================================================
    // 🛠️ TOOL CONFIGURATION - أيقونات وأسماء الأدوات الـ 17
    // =================================================================
    const ToolIcons = {
        phone: '📱', email: '📧', password: '🔐', url: '🌍',
        domain: '🌐', ip: '🔌', username: '👤', hash: '🔑',
        base64: '🔍', credit_card: '💳', port: '🚪', api_key: '🔐',
        filename: '📁', jwt: '🔑', useragent: '🧑', file: '📄', dns: '🌐'
    };

    const ToolNames = {
        phone: 'الهاتف', email: 'البريد الإلكتروني', password: 'كلمة المرور',
        url: 'الرابط', domain: 'النطاق', ip: 'IP', username: 'اسم المستخدم',
        hash: 'التجزئة', base64: 'Base64', credit_card: 'البطاقة الائتمانية',
        port: 'المنفذ', api_key: 'مفتاح API', filename: 'اسم الملف',
        jwt: 'JWT', useragent: 'وكيل المستخدم', file: 'الملف', dns: 'DNS'
    };

    // =================================================================
    // 🔤 COMPLETE ARABIC TRANSLATION - جميع المفاتيح مترجمة 100%
    // =================================================================
    const KeyTranslation = {
        // 📱 الهاتف
        'valid_format': 'صيغة صحيحة',
        'country': 'الدولة',
        'country_code': 'رمز الدولة',
        'iso': 'الرمز الدولي',
        'carrier': 'المشغل',
        'line_type': 'نوع الخط',
        'is_mobile': 'جوال',
        'is_fake': 'رقم وهمي',
        'is_emergency': 'رقم طوارئ',
        'national_number': 'الرقم الوطني',
        'international_format': 'الصيغة الدولية',

        // 📧 البريد
        'local_part': 'الجزء المحلي',
        'domain': 'النطاق',
        'tld': 'النطاق العلوي',
        'local_length': 'طول الجزء المحلي',
        'domain_length': 'طول النطاق',
        'subdomain_count': 'عدد النطاقات الفرعية',
        'has_plus_sign': 'يحتوي +',
        'is_disposable': 'بريد مؤقت',
        'is_spoof': 'بريد مزيف',
        'is_free_provider': 'مزود مجاني',
        'is_role_based': 'بريد وظيفي',
        'mx_records': 'سجلات MX',

        // 🔐 كلمة المرور
        'length': 'الطول',
        'entropy': 'الانتروبيا',
        'has_lower': 'أحرف صغيرة',
        'has_upper': 'أحرف كبيرة',
        'has_digit': 'أرقام',
        'has_special': 'رموز خاصة',
        'is_common': 'كلمة شائعة',
        'is_sequential': 'نمط تسلسلي',
        'is_keyboard': 'نمط لوحة مفاتيح',
        'has_repeated': 'نمط مكرر',
        'strength': 'القوة',
        'crack_time': 'وقت الكسر',
        'score': 'الدرجة',
        'char_types': 'أنواع الحروف',

        // 🌍 الروابط
        'normalized': 'الرابط الطبيعي',
        'scheme': 'البروتوكول',
        'host': 'المضيف',
        'path': 'المسار',
        'query': 'الاستعلام',
        'fragment': 'الجزء',
        'port': 'المنفذ',
        'host_length': 'طول المضيف',
        'is_https': 'اتصال آمن',
        'is_ip': 'رابط IP',
        'is_shortener': 'رابط مختصر',
        'has_punycode': 'نطاق Punycode',
        'is_phishing': 'رابط تصيد',
        'path_depth': 'عمق المسار',
        'query_params_count': 'عدد المعاملات',

        // 🌐 النطاقات
        'sld': 'النطاق الرئيسي',
        'subdomains': 'النطاقات الفرعية',
        'has_punycode': 'يحتوي Punycode',
        'suspicious_tld': 'نطاق علوي مشبوه',
        'has_lookalike': 'أحرف مشابهة',
        'has_hyphen': 'يحتوي شرطة',
        'hyphen_count': 'عدد الشرطات',
        'has_numbers': 'يحتوي أرقام',

        // 🔌 IP
        'valid': 'صحيح',
        'version': 'الإصدار',
        'is_private': 'IP خاص',
        'is_loopback': 'IP استرجاع',
        'is_reserved': 'IP محجوز',
        'is_multicast': 'IP متعدد الإرسال',
        'is_global': 'IP عام',
        'compressed': 'مضغوط',
        'exploded': 'مفصل',
        'ip_type': 'نوع IP',

        // 👤 اسم المستخدم
        'username': 'اسم المستخدم',
        'is_all_numeric': 'كله أرقام',
        'is_all_alpha': 'كله حروف',
        'has_special': 'يحتوي رموز خاصة',
        'is_email_like': 'يشبه البريد',
        'bot_pattern_score': 'درجة نمط البوت',

        // 🔑 التجزئة
        'algorithm': 'الخوارزمية',
        'is_hash': 'تجزئة',
        'is_weak': 'خوارزمية ضعيفة',
        'possible_algorithms': 'الخوارزميات المحتملة',

        // 🔍 Base64
        'is_base64': 'Base64',
        'is_url_safe': 'آمن للروابط',
        'has_padding': 'يحتاج حشو',
        'decoded_preview': 'معاينة المفكوك',

        // 💳 بطاقة الائتمان
        'masked': 'مخفي',
        'last_four': 'آخر 4 أرقام',
        'valid_length': 'طول صحيح',
        'luhn_valid': 'صحة Luhn',
        'issuer': 'الجهة المصدرة',
        'is_test': 'بطاقة اختبار',

        // 🚪 المنافذ
        'is_dangerous': 'منفذ خطير',
        'is_system_port': 'منفذ نظام',
        'is_user_port': 'منفذ مستخدم',
        'is_dynamic_port': 'منفذ ديناميكي',
        'category': 'التصنيف',
        'service': 'الخدمة',

        // 🔑 مفاتيح API
        'detected': 'المكتشفة',
        'patterns': 'الأنماط',

        // 📁 أسماء الملفات
        'filename': 'اسم الملف',
        'extension': 'الامتداد',
        'is_executable': 'ملف تنفيذي',
        'has_dots': 'نقاط متعددة',

        // 🔐 JWT
        'is_jwt': 'JWT',
        'parts': 'الأجزاء',
        'expired': 'منتهي الصلاحية',
        'subject': 'الموضوع',

        // 🧑 User-Agent
        'is_allowed_bot': 'بوت مسموح',
        'is_malicious_bot': 'بوت خبيث',
        'bot_type': 'نوع البوت',

        // 📄 الملفات
        'size': 'الحجم',
        'size_formatted': 'الحجم',
        'detected_type': 'النوع المكتشف',
        'mime_type': 'نوع MIME',
        'risk_level': 'مستوى الخطر',
        'threats': 'التهديدات',

        // 🌐 DNS
        'record': 'السجل',
        'resolved': 'تم الحل',
        'dnssec': 'DNSSEC',
        'records': 'السجلات',

        // عام
        'timestamp': 'الوقت',
        'risk_score': 'درجة الخطر',
        'confidence': 'الثقة',
        'version': 'الإصدار',
        'cached': 'من الذاكرة المؤقتة'
    };

    // =================================================================
    // 📡 API CLIENT - مع تحسينات الأداء وإعادة المحاولة
    // =================================================================
    window.API = {
        async scan(tool, input, options = {}) {
            const {
                timeout = 15000,
                cache = true,
                retries = 2,
                retryDelay = 1000
            } = options;

            if (!input || typeof input !== 'string' || !input.trim()) {
                throw new Error('INPUT_REQUIRED');
            }

            const trimmedInput = input.trim();
            const cacheKey = `${tool}:${trimmedInput}`;

            if (cache) {
                const cached = AnalyzerCache.get(cacheKey);
                if (cached) {
                    cached.fromCache = true;
                    return cached;
                }
            }

            let lastError = null;

            for (let attempt = 0; attempt <= retries; attempt++) {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), timeout);

                try {
                    const payload = { [tool]: trimmedInput };

                    const response = await fetch(`/api/v1/scan/${tool}`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Accept': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest',
                            'X-Request-ID': crypto.randomUUID ? crypto.randomUUID() : `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
                        },
                        body: JSON.stringify(payload),
                        signal: controller.signal,
                        credentials: 'same-origin'
                    });

                    clearTimeout(timeoutId);

                    let data;
                    const contentType = response.headers.get('content-type');

                    if (contentType && contentType.includes('application/json')) {
                        data = await response.json();
                    } else {
                        const text = await response.text();
                        throw new Error('INVALID_RESPONSE');
                    }

                    if (!response.ok) {
                        throw new Error(data.error || data.message || `HTTP_${response.status}`);
                    }

                    if (data.success === false) {
                        throw new Error(data.error || 'ANALYSIS_FAILED');
                    }

                    if (cache) {
                        AnalyzerCache.set(cacheKey, data, 300000); // 5 دقائق
                    }

                    return data;

                } catch (error) {
                    clearTimeout(timeoutId);
                    lastError = error;

                    if (error.name === 'AbortError') {
                        if (attempt < retries) continue;
                        throw new Error('TIMEOUT');
                    }

                    if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
                        if (attempt < retries) {
                            await new Promise(r => setTimeout(r, retryDelay * Math.pow(2, attempt)));
                            continue;
                        }
                        throw new Error('NETWORK_ERROR');
                    }

                    throw error;
                }
            }

            throw lastError || new Error('MAX_RETRIES_EXCEEDED');
        },

        async getStats() {
            try {
                const response = await fetch('/api/stats', {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                        'Cache-Control': 'no-cache'
                    }
                });

                if (!response.ok) {
                    throw new Error(`HTTP_${response.status}`);
                }

                return await response.json();

            } catch (error) {
                console.error('Stats error:', error);
                return null;
            }
        },

        // دالة مساعدة للتحقق من صحة الإدخال
        validateInput(tool, input) {
            const validators = {
                email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
                phone: (v) => /^[\+\d\s\-\(\)]{8,}$/.test(v),
                ip: (v) => /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/.test(v),
                url: (v) => /^https?:\/\//.test(v) || /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(v)
            };

            return validators[tool] ? validators[tool](input) : true;
        }
    };

    // =================================================================
    // 🎨 RESULT RENDERER - مع تحسينات العرض والأداء
    // =================================================================
    window.ResultRenderer = {
        render(data, containerId) {
            const container = document.getElementById(containerId);
            if (!container) {
                console.error(`Container #${containerId} not found`);
                return;
            }

            if (!data || typeof data !== 'object') {
                this.renderError('بيانات غير صالحة', containerId);
                return;
            }

            const tool = data.tool || 'unknown';
            const riskScore = typeof data.risk_score === 'number' ? data.risk_score : 0;
            const confidence = typeof data.confidence === 'number' ? data.confidence : 0;
            const analysis = data.analysis || {};
            const signals = analysis.signals || [];
            const inputValue = data.input || '';
            const aiInsight = data.ai_insight || this.generateAIInsight(data);
            const fromCache = data.fromCache || false;

            const risk = window.RiskAnalyzer.getLevel(riskScore);
            const categorizedSignals = window.RiskAnalyzer.analyzeSignals(signals);
            const recommendations = window.RiskAnalyzer.getRecommendations(signals);

            // توليد HTML للتحليل المفصل
            let analysisHtml = this.generateAnalysisHTML(analysis);

            // توليد HTML للإشارات الأمنية
            let signalsHtml = this.generateSignalsHTML(categorizedSignals);

            // توليد HTML للتوصيات
            let recommendationsHtml = this.generateRecommendationsHTML(recommendations);

            const progressId = `progress-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;

            // استخدام DocumentFragment لتحسين الأداء
            const fragment = document.createDocumentFragment();
            const resultCard = document.createElement('div');
            resultCard.className = `result-card ${fromCache ? 'cached' : ''}`;
            resultCard.setAttribute('data-tool', tool);
            resultCard.setAttribute('role', 'article');
            resultCard.setAttribute('aria-label', `نتائج تحليل ${ToolNames[tool] || tool}`);

            resultCard.innerHTML = `
                <div class="result-header">
                    <div>
                        <span class="result-badge">
                            ${fromCache ? '⚡ من الذاكرة المؤقتة' : '✅ اكتمل التحليل'}
                        </span>
                        <h3 class="result-title">
                            <span class="result-icon" aria-hidden="true">${ToolIcons[tool] || '🛡️'}</span>
                            تحليل ${ToolNames[tool] || tool}
                        </h3>
                        <div class="result-badges">
                            <span class="badge ${risk.class}"
                                  style="background:${risk.bgColor}; color:${risk.color}; border-color:${risk.borderColor};"
                                  title="درجة الخطورة: ${riskScore}/100">
                                ${risk.icon} مستوى الخطر: ${risk.text} (${riskScore}/١٠٠)
                            </span>
                            <span class="badge badge-cyan" title="نسبة ثقة الذكاء الاصطناعي">
                                🧠 ثقة: ${confidence}%
                            </span>
                        </div>
                    </div>
                    <span class="result-shield" aria-hidden="true">🛡️</span>
                </div>

                <div class="confidence-meter" role="group" aria-label="مقياس الثقة">
                    <div class="confidence-header">
                        <span class="confidence-label">🧠 ثقة الذكاء الاصطناعي</span>
                        <span class="confidence-value">${confidence}%</span>
                    </div>
                    <div id="${progressId}" class="progress-container" role="presentation"></div>
                </div>

                <div class="ai-insight" role="complementary" aria-label="رؤية الذكاء الاصطناعي">
                    <div class="ai-insight-header">
                        <span class="ai-icon" aria-hidden="true">🧠</span>
                        <span class="ai-label">رؤية الذكاء الاصطناعي</span>
                    </div>
                    <p class="ai-text">${escapeHTML(aiInsight)}</p>
                </div>

                ${analysisHtml}
                ${signalsHtml}
                ${recommendationsHtml}

                <div class="result-footer">
                    <span class="meta-item" title="القيمة المدخلة">
                        <span aria-hidden="true">📌</span>
                        <span>الإدخال: </span>
                        <code class="input-preview">${escapeHTML(inputValue.substring(0, 50))}${inputValue.length > 50 ? '…' : ''}</code>
                    </span>
                    <span class="meta-item" title="وقت التحليل">
                        <span aria-hidden="true">🕒</span>
                        <time datetime="${data.timestamp || new Date().toISOString()}">
                            ${data.timestamp ? new Date(data.timestamp).toLocaleString('ar-SA') : new Date().toLocaleString('ar-SA')}
                        </time>
                    </span>
                </div>
            `;

            fragment.appendChild(resultCard);
            container.innerHTML = '';
            container.appendChild(fragment);

            // تشغيل شريط التقدم
            setTimeout(() => {
                window.RiskAnalyzer.renderProgress(progressId, confidence, risk.progress);
            }, 50);

            // إضافة تأثير ظهور سلس
            resultCard.style.animation = 'slideIn 0.3s ease-out';
        },

        generateAnalysisHTML(analysis) {
            const items = [];

            for (const [key, value] of Object.entries(analysis)) {
                // تجاهل الحقول الداخلية والكبيرة
                if (['signals', '_cache', 'entropy'].includes(key)) continue;
                if (value === null || value === undefined) continue;
                if (typeof value === 'object') continue;
                if (typeof value === 'string' && value.length > 200) continue;

                const label = KeyTranslation[key] || key.replace(/_/g, ' ');
                let displayValue = value;
                let valueClass = '';

                if (typeof value === 'boolean') {
                    displayValue = value ? 'نعم' : 'لا';
                    valueClass = value ? 'success' : 'danger';
                } else if (typeof value === 'number') {
                    displayValue = value.toLocaleString('ar-SA');
                    if (key.includes('score') || key.includes('risk')) {
                        if (value >= 70) valueClass = 'danger';
                        else if (value >= 40) valueClass = 'warning';
                        else valueClass = 'success';
                    }
                } else if (typeof value === 'string' && value.length > 50) {
                    displayValue = value.substring(0, 50) + '…';
                }

                items.push(`
                    <div class="analysis-item" role="listitem">
                        <span class="analysis-key">${escapeHTML(label)}</span>
                        <span class="analysis-value ${valueClass}">${escapeHTML(displayValue)}</span>
                    </div>
                `);
            }

            return items.length ?
                `<div class="analysis-section" role="list" aria-label="نتائج التحليل المفصلة">
                    <h4 class="analysis-title">📊 نتائج التحليل</h4>
                    <div class="analysis-grid">${items.join('')}</div>
                </div>` : '';
        },

        generateSignalsHTML(signals) {
            const sections = [];
            const icons = { critical: '🚨', high: '🔴', medium: '🟠', low: '🟡' };

            for (const [level, items] of Object.entries(signals)) {
                if (items.length) {
                    sections.push(`
                        <div class="signal-group signal-${level}">
                            <span class="signal-group-icon">${icons[level]}</span>
                            <div class="signal-tags">
                                ${items.map(s =>
                                    `<span class="signal-tag signal-${level}" role="status">${escapeHTML(s)}</span>`
                                ).join('')}
                            </div>
                        </div>
                    `);
                }
            }

            return sections.length ?
                `<div class="signals-section" role="region" aria-label="الإشارات الأمنية">
                    <h4 class="signals-title">🔍 الإشارات الأمنية</h4>
                    <div class="signals-container">${sections.join('')}</div>
                </div>` : '';
        },

        generateRecommendationsHTML(recommendations) {
            if (!recommendations.length) return '';

            return `
                <div class="recommendations-section" role="region" aria-label="التوصيات">
                    <h4 class="recommendations-title">💡 التوصيات</h4>
                    <ul class="recommendations-list">
                        ${recommendations.map(rec =>
                            `<li class="recommendation-item">${escapeHTML(rec)}</li>`
                        ).join('')}
                    </ul>
                </div>
            `;
        },

        generateAIInsight(data) {
            const risk = data.risk_score;
            const signals = data.analysis?.signals || [];

            if (risk >= 80) return '⚠️ خطر شديد - تجنب التعامل مع هذا الإدخال فوراً';
            if (risk >= 60) return '🔴 خطر مرتفع - يوصى بالحذر الشديد والتحقق';
            if (risk >= 40) return '🟠 خطر متوسط - تحقق من المصدر قبل الاستخدام';
            if (signals.length === 0) return '✅ آمن - لا توجد مؤشرات خطر';
            return '🟢 منخفض المخاطر - يمكن الاستخدام مع الاحتياطات الأساسية';
        },

        renderError(message, containerId) {
            const container = document.getElementById(containerId);
            if (!container) return;

            container.innerHTML = `
                <div class="error-message" role="alert">
                    <span class="error-icon" aria-hidden="true">⚠️</span>
                    <div class="error-content">
                        <strong>حدث خطأ:</strong>
                        <p>${escapeHTML(message)}</p>
                    </div>
                </div>
            `;
        },

        clear(containerId) {
            const container = document.getElementById(containerId);
            if (container) {
                container.innerHTML = '';
            }
        }
    };

    // =================================================================
    // 📊 STATS LOADER - مع تحديث تلقائي
    // =================================================================
    window.StatsLoader = {
        interval: null,

        async load(containerId, options = {}) {
            const { autoRefresh = true, refreshInterval = 30000 } = options;
            const container = document.getElementById(containerId);

            if (!container) return;

            const loadStats = async () => {
                const data = await window.API.getStats();
                if (!data) {
                    container.innerHTML = '<p class="stats-error">⚠️ تعذر تحميل الإحصائيات</p>';
                    return;
                }

                container.innerHTML = `
                    <div class="stats-section" role="region" aria-label="إحصائيات المنصة">
                        <div class="stat-card">
                            <div class="stat-value">${(data.total_scans || 0).toLocaleString('ar-SA')}</div>
                            <div class="stat-label">إجمالي الفحوصات</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${(data.today_scans || 0).toLocaleString('ar-SA')}</div>
                            <div class="stat-label">فحوصات اليوم</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.avg_response_time || '< ١٠٠'}ms</div>
                            <div class="stat-label">متوسط وقت الاستجابة</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${AnalyzerCache.getStats().hitRate}%</div>
                            <div class="stat-label">كفاءة الذاكرة المؤقتة</div>
                        </div>
                    </div>
                `;
            };

            await loadStats();

            if (autoRefresh) {
                if (this.interval) clearInterval(this.interval);
                this.interval = setInterval(loadStats, refreshInterval);
            }
        },

        stop() {
            if (this.interval) {
                clearInterval(this.interval);
                this.interval = null;
            }
        }
    };

    // =================================================================
    // 🚀 TOOLTIP SYSTEM - تحسين إضافي
    // =================================================================
    const TooltipSystem = {
        init() {
            document.addEventListener('mouseover', (e) => {
                const target = e.target.closest('[data-tooltip]');
                if (target) this.show(target, target.dataset.tooltip);
            });

            document.addEventListener('mouseout', (e) => {
                if (e.target.closest('[data-tooltip]')) this.hide();
            });
        },

        show(element, text) {
            let tooltip = document.getElementById('dynamic-tooltip');
            if (!tooltip) {
                tooltip = document.createElement('div');
                tooltip.id = 'dynamic-tooltip';
                tooltip.className = 'dynamic-tooltip';
                document.body.appendChild(tooltip);
            }

            tooltip.textContent = text;
            tooltip.style.display = 'block';

            const rect = element.getBoundingClientRect();
            tooltip.style.top = `${rect.bottom + window.scrollY + 5}px`;
            tooltip.style.left = `${rect.left + window.scrollX}px`;
        },

        hide() {
            const tooltip = document.getElementById('dynamic-tooltip');
            if (tooltip) tooltip.style.display = 'none';
        }
    };

    // =================================================================
    // 🎯 INITIALIZATION - تشغيل النظام
    // =================================================================
    document.addEventListener('DOMContentLoaded', () => {
        // تنظيف الذاكرة المؤقتة
        AnalyzerCache.cleanup();

        // تشغيل نظام التلميحات
        TooltipSystem.init();

        // إحصائيات الأداء
        console.log('🚀 CyberShield Ultra v4.5 Loaded', {
            cache: AnalyzerCache.getStats(),
            tools: Object.keys(ToolNames).length,
            timestamp: new Date().toLocaleString('ar-SA')
        });

        // مراقبة أداء الصفحة
        if (window.performance) {
            const perfData = performance.timing;
            const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
            console.log(`📊 Page load time: ${pageLoadTime}ms`);
        }
    });

    // تنظيف عند مغادرة الصفحة
    window.addEventListener('beforeunload', () => {
        StatsLoader.stop();
    });

})();