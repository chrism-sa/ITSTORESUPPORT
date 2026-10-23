/* motion-layer.js — animasi ala Framer Motion untuk Alfamidi Field Tracker
   Memakai library "Motion" (mesin animasi dari pembuat Framer Motion), dimuat lewat CDN.
   Pasang SETELAH app.js. Kalau Motion gagal dimuat, aplikasi tetap jalan seperti biasa. */
(function () {
    if (!window.Motion || typeof window.app !== 'function') return;
    const { animate, stagger } = window.Motion;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) return;

    // Matikan animasi CSS lama yang bentrok dengan Motion
    const css = document.createElement('style');
    css.textContent = '.anim-up{animation:none!important}';
    document.head.appendChild(css);

    const ORDER = { dashboard: 0, units: 1, settings: 1, form: 2, reader: 2 };
    const SPRING = { type: 'spring', stiffness: 380, damping: 34 };
    const EASE = [0.22, 1, 0.36, 1];
    let pendingDir = 0;
    let busy = false;

    const screenOf = v => Array.from(document.querySelectorAll('main > [x-show]'))
        .find(e => e.getAttribute('x-show') === "view === '" + v + "'");
    const $ = sel => document.querySelector(sel);

    function enter(view) {
        const el = screenOf(view);
        if (!el) return;
        const dir = pendingDir; pendingDir = 0;
        const kids = Array.from(new Set(el.querySelectorAll(
            '.dashboard-heading, .overview-panel, .store-browser, .region-heading, .card'
        ))).filter(k => k.offsetParent !== null).slice(0, 18);

        el.style.opacity = '0';
        kids.forEach(k => { k.style.opacity = '0'; });

        const main = animate(el, { opacity: [0, 1], x: [dir * 48, 0] }, SPRING);
        const list = animate(kids, { opacity: [0, 1], y: [18, 0] },
            { duration: 0.42, ease: EASE, delay: stagger(0.045, { startDelay: 0.05 }) });
        const clearMainStyles = () => {
            el.style.removeProperty('opacity');
            el.style.removeProperty('transform');
        };
        const clearListStyles = () => kids.forEach(k => {
            k.style.removeProperty('opacity');
            k.style.removeProperty('transform');
        });
        main.finished.then(clearMainStyles, clearMainStyles);
        list.finished.then(clearListStyles, clearListStyles);
    }

    function pop(selector, from) {
        requestAnimationFrame(() => {
            const el = $(selector);
            if (el) animate(el, Object.assign({ opacity: [0, 1] }, from), SPRING);
        });
    }

    const originalApp = window.app;
    window.app = function () {
        const o = originalApp();

        // 1) Transisi pindah halaman: keluar geser + fade, lalu halaman baru masuk dengan spring + stagger
        const origGo = o.go;
        o.go = async function (view) {
            if (busy || view === this.view || !(view in ORDER)) return origGo.call(this, view);
            busy = true;
            const from = this.view;
            const dir = Math.sign((ORDER[view] ?? 0) - (ORDER[from] ?? 0)) || 1;
            const cur = screenOf(from);
            try {
                if (cur) await animate(cur, { opacity: [1, 0], x: [0, -30 * dir] }, { duration: 0.16, ease: 'easeIn' }).finished;
            } catch (e) {}
            pendingDir = dir;
            const next = screenOf(view);
            if (next) next.style.opacity = '0'; // cegah kedip sebelum animasi masuk
            origGo.call(this, view);
            setTimeout(() => { if (cur) { cur.style.opacity = ''; cur.style.transform = ''; } busy = false; }, 60);
        };

        // 2) Animasi masuk halaman (dipanggil oleh go() asli lewat $nextTick)
        o.animateView = function (view) { enter(view); };

        // 3) Getar saat PIN salah
        const origUnlock = o.unlockApp;
        o.unlockApp = async function () {
            const before = Number((this.pinSecurity && this.pinSecurity.failures) || 0);
            await origUnlock.call(this);
            const after = Number((this.pinSecurity && this.pinSecurity.failures) || 0);
            if (after > before) {
                const panel = $('.lock-panel');
                if (panel) animate(panel, { x: [0, -12, 12, -9, 9, -4, 0] }, { duration: 0.45 });
            }
        };

        // 4) Modal, dialog, toast, scanner, dan sub-halaman pengaturan
        const origInit = o.init;
        o.init = async function () {
            await origInit.call(this);
            const mobile = () => window.innerWidth < 640;
            this.$watch('modal.open', v => v && this.$nextTick(() =>
                pop('[x-show="modal.open"] > div', mobile() ? { y: [90, 0] } : { y: [24, 0], scale: [0.97, 1] })));
            this.$watch('confirmState.open', v => v && this.$nextTick(() =>
                pop('[x-show="confirmState.open"] > div', { scale: [0.9, 1], y: [12, 0] })));
            this.$watch('ocrChoiceModal.open', v => v && this.$nextTick(() =>
                pop('[x-show="ocrChoiceModal.open"] > div', { scale: [0.92, 1], y: [16, 0] })));
            this.$watch('scanOpen', v => v && this.$nextTick(() =>
                pop('[x-show="scanOpen"]', { scale: [1.04, 1] })));
            this.$watch('toastMsg', v => v && this.$nextTick(() =>
                pop('[role="status"]', { y: [24, 0], scale: [0.92, 1] })));
            this.$watch('settingsPage', () => this.$nextTick(() => {
                const el = screenOf('settings');
                if (!el) return;
                const kids = Array.from(el.querySelectorAll('.card')).slice(0, 14);
                kids.forEach(k => { k.style.opacity = '0'; });
                animate(kids, { opacity: [0, 1], x: [20, 0] },
                    { duration: 0.36, ease: EASE, delay: stagger(0.04) })
                    .finished.then(
                        () => kids.forEach(k => { k.style.removeProperty('opacity'); k.style.removeProperty('transform'); }),
                        () => kids.forEach(k => { k.style.removeProperty('opacity'); k.style.removeProperty('transform'); })
                    );
            }));
        };
        return o;
    };
})();
