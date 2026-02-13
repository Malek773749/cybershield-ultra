// نظام نسخ الأكواد المتكامل
class CodeCopySystem {
    constructor() {
        this.init();
    }

    init() {
        // إضافة أزرار النسخ الديناميكية
        this.addCopyButtons();
        // تتبع أحداث النسخ
        this.trackCopyEvents();
    }

    addCopyButtons() {
        // إضافة أزرار نسخ لجميع عناصر الكود
        document.querySelectorAll('pre code').forEach((codeBlock) => {
            if (!codeBlock.parentElement.querySelector('.copy-btn')) {
                const button = document.createElement('button');
                button.className = 'copy-btn';
                button.innerHTML = '<i class="far fa-copy"></i> نسخ الكود';
                button.onclick = () => this.copyCode(codeBlock, button);

                const header = document.createElement('div');
                header.className = 'code-header';
                header.innerHTML = `<span>${this.getFileName(codeBlock)}</span>`;
                header.appendChild(button);

                codeBlock.parentElement.insertBefore(header, codeBlock);
            }
        });
    }

    getFileName(codeBlock) {
        // استخراج اسم الملف من class أو parent
        const classes = codeBlock.className.split(' ');
        const language = classes.find(c => c.startsWith('language-')) || 'code';
        return `${language.replace('language-', '')}.${this.getFileExtension(language)}`;
    }

    getFileExtension(language) {
        const extensions = {
            'javascript': 'js',
            'html': 'html',
            'css': 'css',
            'python': 'py',
            'php': 'php',
            'java': 'java',
            'sql': 'sql',
            'bash': 'sh',
            'json': 'json',
            'xml': 'xml'
        };
        return extensions[language.replace('language-', '')] || 'txt';
    }

    async copyCode(codeBlock, button) {
        try {
            const text = codeBlock.textContent;
            await navigator.clipboard.writeText(text);

            this.showSuccess(button);
            this.logCopyEvent(codeBlock);
        } catch (err) {
            this.showError(button);
            console.error('Failed to copy:', err);
            // Fallback method
            this.fallbackCopyMethod(codeBlock);
        }
    }

    showSuccess(button) {
        const originalHTML = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check"></i> تم النسخ!';
        button.style.backgroundColor = '#28a745';

        setTimeout(() => {
            button.innerHTML = originalHTML;
            button.style.backgroundColor = '';
        }, 2000);
    }

    showError(button) {
        button.innerHTML = '<i class="fas fa-times"></i> فشل النسخ';
        button.style.backgroundColor = '#dc3545';

        setTimeout(() => {
            button.innerHTML = '<i class="far fa-copy"></i> نسخ الكود';
            button.style.backgroundColor = '';
        }, 2000);
    }

    fallbackCopyMethod(codeBlock) {
        const textArea = document.createElement('textarea');
        textArea.value = codeBlock.textContent;
        document.body.appendChild(textArea);
        textArea.select();

        try {
            document.execCommand('copy');
            alert('تم نسخ الكود باستخدام الطريقة القديمة');
        } catch (err) {
            alert('تعذر نسخ الكود. يرجى النسخ يدوياً');
        }

        document.body.removeChild(textArea);
    }

    trackCopyEvents() {
        // يمكن إضافة تتبع إحصائي هنا
        console.log('نظام نسخ الأكواد جاهز');
    }

    logCopyEvent(codeBlock) {
        const eventData = {
            timestamp: new Date().toISOString(),
            language: codeBlock.className.match(/language-(\w+)/)?.[1] || 'unknown',
            length: codeBlock.textContent.length,
            source: window.location.href
        };

        // حفظ في localStorage للإحصائيات
        this.saveCopyStatistic(eventData);
    }

    saveCopyStatistic(eventData) {
        let stats = JSON.parse(localStorage.getItem('copy_stats') || '[]');
        stats.push(eventData);

        // حفظ آخر 100 حدث فقط
        if (stats.length > 100) {
            stats = stats.slice(-100);
        }

        localStorage.setItem('copy_stats', JSON.stringify(stats));
    }

    getCopyStatistics() {
        const stats = JSON.parse(localStorage.getItem('copy_stats') || '[]');
        return {
            totalCopies: stats.length,
            byLanguage: this.groupByLanguage(stats),
            recentCopies: stats.slice(-10)
        };
    }

    groupByLanguage(stats) {
        return stats.reduce((acc, event) => {
            const lang = event.language;
            acc[lang] = (acc[lang] || 0) + 1;
            return acc;
        }, {});
    }
}

// تصدير النظام للاستخدام العام
window.CodeCopySystem = CodeCopySystem;

// تهيئة النظام عند تحميل الصفحة
document.addEventListener('DOMContentLoaded', () => {
    window.codeCopySystem = new CodeCopySystem();
});