// static/js/main.js
// كود JavaScript للتحسينات الإضافية

document.addEventListener('DOMContentLoaded', function() {
    // تحسين أداء الصور واللازي لود
    const lazyLoadImages = () => {
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.classList.remove('lazy');
                    observer.unobserve(img);
                }
            });
        });

        document.querySelectorAll('img[data-src]').forEach(img => {
            imageObserver.observe(img);
        });
    };

    // تحميل الصور بالتدرج
    lazyLoadImages();

    // إضافة تأثيرات عند التمرير
    const animateOnScroll = () => {
        const elements = document.querySelectorAll('.feature-card, .stat-card, .step');

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, {
            threshold: 0.1
        });

        elements.forEach(el => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(20px)';
            el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            observer.observe(el);
        });
    };

    // تفعيل تأثيرات التمرير
    animateOnScroll();

    // إدارة حالة التحميل
    const handleLoadingState = () => {
        const loadingElements = document.querySelectorAll('[data-loading]');

        loadingElements.forEach(el => {
            el.addEventListener('click', function() {
                const originalText = this.innerHTML;
                this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> جاري المعالجة...';
                this.disabled = true;

                // استعادة النص الأصلي بعد 3 ثواني (للاستخدام الفعلي، استخدم then للوعود)
                setTimeout(() => {
                    this.innerHTML = originalText;
                    this.disabled = false;
                }, 3000);
            });
        });
    };

    handleLoadingState();

    // تحسين الوصول Accessibility
    const improveAccessibility = () => {
        // إضافة labels للصور
        document.querySelectorAll('img:not([alt])').forEach(img => {
            img.setAttribute('alt', 'صورة توضيحية');
        });

        // تحسين التنقل بلوحة المفاتيح
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                document.documentElement.classList.add('keyboard-navigation');
            }
        });

        document.addEventListener('mousedown', () => {
            document.documentElement.classList.remove('keyboard-navigation');
        });
    };

    improveAccessibility();

    // تحديث الوقت الحقيقي للإحصائيات
    const updateLiveStats = () => {
        const updateElement = (selector, value) => {
            const el = document.querySelector(selector);
            if (el) {
                const current = parseInt(el.textContent.replace(/,/g, '')) || 0;
                const increment = Math.ceil((value - current) / 10);

                let count = current;
                const interval = setInterval(() => {
                    count += increment;
                    if (count >= value) {
                        count = value;
                        clearInterval(interval);
                    }
                    el.textContent = count.toLocaleString();
                }, 50);
            }
        };

        // تحديث الإحصائيات كل 30 ثانية
        setInterval(() => {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateElement('.hero-stat:nth-child(1) .stat-number', data.data.total_unique_users);
                        updateElement('.hero-stat:nth-child(2) .stat-number', data.data.total_scans);
                        updateElement('.hero-stat:nth-child(3) .stat-number', data.data.total_visits);
                        updateElement('.hero-stat:nth-child(4) .stat-number', data.data.active_users_today);
                    }
                })
                .catch(error => console.error('Error fetching stats:', error));
        }, 30000);
    };

    // تفعيل تحديث الإحصائيات
    updateLiveStats();

    // إدارة وضع التخفي (Dark Mode)
    const initDarkMode = () => {
        const darkModeToggle = document.createElement('button');
        darkModeToggle.innerHTML = '<i class="fas fa-moon"></i>';
        darkModeToggle.className = 'dark-mode-toggle';
        darkModeToggle.title = 'تبديل الوضع المظلم';

        darkModeToggle.addEventListener('click', () => {
            document.body.classList.toggle('dark-mode');
            const isDarkMode = document.body.classList.contains('dark-mode');
            localStorage.setItem('darkMode', isDarkMode);
            darkModeToggle.innerHTML = isDarkMode ?
                '<i class="fas fa-sun"></i>' :
                '<i class="fas fa-moon"></i>';
        });

        // التحقق من التفضيل المحفوظ
        if (localStorage.getItem('darkMode') === 'true') {
            document.body.classList.add('dark-mode');
            darkModeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        }

        // إضافة الزر إلى الصفحة
        document.querySelector('.nav-container')?.appendChild(darkModeToggle);
    };

    initDarkMode();

    // تحسين تجربة اللمس للهواتف
    const improveTouchExperience = () => {
        let lastTap = 0;

        document.addEventListener('touchend', (e) => {
            const currentTime = new Date().getTime();
            const tapLength = currentTime - lastTap;

            if (tapLength < 500 && tapLength > 0) {
                e.preventDefault();
                // عمل مزدوج النقر
            }

            lastTap = currentTime;
        });

        // منع التكبير على العناصر النشطة
        document.addEventListener('touchstart', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                document.documentElement.style.zoom = '100%';
            }
        });
    };

    improveTouchExperience();

    // تحسين محركات البحث
    const improveSEO = () => {
        // إضافة Structured Data الديناميكي
        const addDynamicStructuredData = () => {
            const script = document.createElement('script');
            script.type = 'application/ld+json';
            script.textContent = JSON.stringify({
                "@context": "https://schema.org",
                "@type": "WebSite",
                "name": "CyberShield Pro",
                "url": window.location.origin,
                "potentialAction": {
                    "@type": "SearchAction",
                    "target": `${window.location.origin}/tools?q={search_term_string}`,
                    "query-input": "required name=search_term_string"
                }
            });
            document.head.appendChild(script);
        };

        addDynamicStructuredData();

        // تتبع أحداث التركيز
        document.querySelectorAll('a, button, input, textarea').forEach(el => {
            el.addEventListener('focus', () => {
                el.setAttribute('data-focused', 'true');
            });

            el.addEventListener('blur', () => {
                el.removeAttribute('data-focused');
            });
        });
    };

    improveSEO();
});

// كود خاص بـ Google AdSense
window.onload = function() {
    // إعادة تحميل الإعلانات عند تغيير الحجم
    window.addEventListener('resize', () => {
        if (window.adsbygoogle && Array.isArray(window.adsbygoogle)) {
            window.adsbygoogle.forEach(ad => {
                try {
                    ad.push({});
                } catch (e) {
                    console.warn('Ad reload error:', e);
                }
            });
        }
    });

    // تحسين عرض الإعلانات على الهواتف
    if (window.innerWidth < 768) {
        document.querySelectorAll('.ad-container ins').forEach(ad => {
            ad.style.minWidth = '320px';
            ad.style.maxWidth = '100%';
        });
    }
};

// Service Worker للتخزين المؤقت (اختياري)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .then(registration => {
                console.log('Service Worker registered with scope:', registration.scope);
            })
            .catch(error => {
                console.log('Service Worker registration failed:', error);
            });
    });
}