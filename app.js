/* ===================== PWA MANIFEST ===================== */
(function initPWA() {
    try {
        const iconSvg = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'%3E%3Crect width='512' height='512' rx='112' fill='%23dc2626'/%3E%3Cpath d='M128 192h256l-24 192H152L128 192zm32-64h192l24 64H136l24-64z' fill='none' stroke='%23fff' stroke-width='28' stroke-linecap='round' stroke-linejoin='round'/%3E%3Cpath d='M208 264v56M304 264v56' stroke='%23fff' stroke-width='28' stroke-linecap='round'/%3E%3C/svg%3E";
        const manifest = {
            name: 'Alfamidi Field Tracker',
            short_name: 'Field Tracker',
            description: 'Aplikasi Pendataan Perangkat IT Kasir & Server Alfamidi',
            start_url: window.location.href.split('#')[0],
            display: 'standalone',
            orientation: 'portrait',
            background_color: '#0f172a',
            theme_color: '#0f172a',
            icons: [{ src: iconSvg, sizes: '512x512', type: 'image/svg+xml', purpose: 'any maskable' }]
        };
        const mUrl = URL.createObjectURL(new Blob([JSON.stringify(manifest)], { type: 'application/manifest+json' }));
        const link = document.createElement('link');
        link.rel = 'manifest';
        link.href = mUrl;
        document.head.appendChild(link);
    } catch (e) {}
})();

(function checkAppVersion() {
    const APP_VERSION = '2.5.1';
    try {
        if (localStorage.getItem('aft2:version') !== APP_VERSION) localStorage.setItem('aft2:version', APP_VERSION);
    } catch (e) {}
})();

/* ===================== UTIL & STORAGE ===================== */
const NS = 'aft2:';
const SCHEMA_REV = 6;
const isSafeId = value => {
    const id = String(value || '');
    return /^[a-z0-9_-]{1,80}$/i.test(id) && !['__proto__', 'constructor', 'prototype'].includes(id);
};
const uid = () => Date.now().toString(36).slice(-5) + Math.random().toString(36).slice(2, 7);
const clone = (o) => JSON.parse(JSON.stringify(o));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const isValidMonth = (value) => /^\d{4}-(0[1-9]|1[0-2])$/.test(String(value || ''));
const localMonth = () => {
    const now = new Date();
    return now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0');
};
const formatMonth = (value) => {
    if (!isValidMonth(value)) return '';
    const [year, month] = value.split('-').map(Number);
    return new Date(year, month - 1, 1).toLocaleDateString('id-ID', { month: 'long', year: 'numeric' });
};

function migrateMonthlyEntries(entries, fallbackMonth) {
    const migrated = {};
    Object.entries(entries && typeof entries === 'object' ? entries : {}).forEach(([key, value]) => {
        const monthPrefix = key.match(/^(\d{4}-(?:0[1-9]|1[0-2]))\|/);
        if (monthPrefix) migrated[key] = value;
        else if (key.split('|').length === 2) migrated[fallbackMonth + '|' + key] = value;
    });
    return migrated;
}

const store = {
    get(k, fb = null) {
        try {
            const r = localStorage.getItem(NS + k);
            return r === null ? fb : JSON.parse(r);
        } catch (e) {
            return fb;
        }
    },
    set(k, v) {
        try {
            localStorage.setItem(NS + k, JSON.stringify(v));
            return true;
        } catch (e) {
            return false;
        }
    },
    del(k) {
        try {
            localStorage.removeItem(NS + k);
        } catch (e) {}
    }
};

const sessionStore = {
    get(key) {
        try { return sessionStorage.getItem(NS + key); } catch (e) { return null; }
    },
    set(key, value) {
        try { sessionStorage.setItem(NS + key, value); return true; } catch (e) { return false; }
    },
    del(key) {
        try { sessionStorage.removeItem(NS + key); } catch (e) {}
    }
};

/* Verifikasi hash PIN lama sebelum migrasi ke PBKDF2. */
async function hashPin(pin) {
    const encoder = new TextEncoder();
    const data = encoder.encode(String(pin));
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

const PIN_HASH_ITERATIONS = 310000;

async function createPinHash(pin) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PIN_HASH_ITERATIONS }, key, 256);
    const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    return 'pbkdf2$' + PIN_HASH_ITERATIONS + '$' + hex(salt) + '$' + hex(new Uint8Array(bits));
}

async function verifyPin(pin, savedHash) {
    if (!String(savedHash || '').startsWith('pbkdf2$')) {
        const valid = await hashPin(pin) === savedHash;
        return { valid, upgradedHash: valid ? await createPinHash(pin) : null };
    }

    const [, iterationsText, saltHex, expectedHex] = String(savedHash).split('$');
    const iterations = Number(iterationsText);
    if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000 || !/^[0-9a-f]{32}$/i.test(saltHex || '') || !/^[0-9a-f]{64}$/i.test(expectedHex || '')) {
        return { valid: false, upgradedHash: null };
    }

    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
    const actual = new Uint8Array(bits);
    const expected = expectedHex.match(/.{2}/g).map(byte => parseInt(byte, 16));
    let difference = 0;
    actual.forEach((byte, index) => { difference |= byte ^ expected[index]; });
    return { valid: difference === 0, upgradedHash: null };
}

// Hash PIN bawaan dipertahankan untuk kompatibilitas dan dimigrasikan setelah login berhasil.
const DEFAULT_PIN_HASH = 'e7042ac7d09c7bc41c8cfa5749e41858f6980643bc0db1a83cc793d3e24d3f77';

let beepCtx = null;
function playScanBeep() {
    try {
        const Ctx = window.AudioContext || window.webkitAudioContext;
        if (!Ctx) return;
        if (!beepCtx) beepCtx = new Ctx();
        if (beepCtx.state === 'suspended') beepCtx.resume();
        const osc = beepCtx.createOscillator();
        const gain = beepCtx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(1350, beepCtx.currentTime);
        gain.gain.setValueAtTime(0.18, beepCtx.currentTime);
        osc.connect(gain);
        gain.connect(beepCtx.destination);
        osc.start();
        osc.stop(beepCtx.currentTime + 0.09);
    } catch (e) {}
}

/* ===================== IMAGE ENHANCEMENT & OCR (v2.1 cepat) ===================== */
const GUIDE = { w: 0.84, h: 0.50 };
const NATIVE_FORMATS = ['code_128', 'code_39', 'code_93', 'qr_code', 'ean_13', 'ean_8', 'itf', 'codabar', 'upc_a', 'upc_e', 'data_matrix'];
const OCR_WHITELIST = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-:. ';

let nativeDetector;
let nativeScanTimer = null;

async function getNativeDetector() {
    if (nativeDetector !== undefined) return nativeDetector;
    try {
        const supported = await BarcodeDetector.getSupportedFormats();
        const formats = NATIVE_FORMATS.filter(f => supported.includes(f));
        nativeDetector = formats.length ? new BarcodeDetector({ formats }) : null;
    } catch (e) {
        nativeDetector = null;
    }
    return nativeDetector;
}

function makeCanvas(w, h) {
    const c = document.createElement('canvas');
    c.width = Math.max(1, Math.round(w));
    c.height = Math.max(1, Math.round(h));
    return c;
}

function scaleToWidth(src, targetW) {
    const scale = Math.min(3, Math.max(0.4, targetW / src.width));
    const out = makeCanvas(src.width * scale, src.height * scale);
    const ctx = out.getContext('2d', { willReadFrequently: true });
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(src, 0, 0, out.width, out.height);
    return out;
}

/* Ukuran ketajaman (varians Laplacian) untuk memilih frame terbaik. */
function canvasSharpness(src) {
    const w = Math.min(240, src.width);
    const h = Math.max(3, Math.round(src.height * w / src.width));
    const c = makeCanvas(w, h);
    const ctx = c.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(src, 0, 0, w, h);
    const d = ctx.getImageData(0, 0, w, h).data;
    const g = new Float32Array(w * h);
    for (let i = 0, p = 0; i < d.length; i += 4, p++) g[p] = 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
    let sum = 0, sumSq = 0, n = 0;
    for (let y = 1; y < h - 1; y++) {
        for (let x = 1; x < w - 1; x++) {
            const i = y * w + x;
            const lap = 4 * g[i] - g[i - 1] - g[i + 1] - g[i - w] - g[i + w];
            sum += lap; sumSq += lap * lap; n++;
        }
    }
    const mean = sum / (n || 1);
    return sumSq / (n || 1) - mean * mean;
}

/* Regangkan kontras berdasarkan persentil 2%-98%. */
function stretchGray(gray) {
    const hist = new Uint32Array(256);
    for (let i = 0; i < gray.length; i++) hist[gray[i]]++;
    const total = gray.length;
    let acc = 0, lo = 0, hi = 255;
    for (let i = 0; i < 256; i++) { acc += hist[i]; if (acc >= total * 0.02) { lo = i; break; } }
    acc = 0;
    for (let i = 255; i >= 0; i--) { acc += hist[i]; if (acc >= total * 0.02) { hi = i; break; } }
    if (hi - lo < 20) return gray;
    const out = new Uint8ClampedArray(gray.length);
    const k = 255 / (hi - lo);
    for (let i = 0; i < gray.length; i++) out[i] = (gray[i] - lo) * k;
    return out;
}

/* Threshold adaptif (rata-rata lokal dengan integral image), tahan bayangan & pencahayaan tidak rata. */
function adaptiveBinarize(gray, w, h, win, c) {
    const integral = new Float64Array((w + 1) * (h + 1));
    for (let y = 1; y <= h; y++) {
        let rowSum = 0;
        for (let x = 1; x <= w; x++) {
            rowSum += gray[(y - 1) * w + (x - 1)];
            integral[y * (w + 1) + x] = integral[(y - 1) * (w + 1) + x] + rowSum;
        }
    }
    const half = Math.max(2, win >> 1);
    const out = new Uint8ClampedArray(w * h);
    for (let y = 0; y < h; y++) {
        const y1 = Math.max(0, y - half), y2 = Math.min(h - 1, y + half);
        for (let x = 0; x < w; x++) {
            const x1 = Math.max(0, x - half), x2 = Math.min(w - 1, x + half);
            const area = (x2 - x1 + 1) * (y2 - y1 + 1);
            const s = integral[(y2 + 1) * (w + 1) + (x2 + 1)] - integral[y1 * (w + 1) + (x2 + 1)] - integral[(y2 + 1) * (w + 1) + x1] + integral[y1 * (w + 1) + x1];
            out[y * w + x] = gray[y * w + x] < (s / area) - c ? 0 : 255;
        }
    }
    return out;
}

function grayToCanvas(gray, w, h, pad = 24) {
    const tmp = makeCanvas(w, h);
    const tctx = tmp.getContext('2d');
    const img = tctx.createImageData(w, h);
    for (let i = 0, p = 0; p < gray.length; i += 4, p++) {
        img.data[i] = img.data[i + 1] = img.data[i + 2] = gray[p];
        img.data[i + 3] = 255;
    }
    tctx.putImageData(img, 0, 0);
    const out = makeCanvas(w + pad * 2, h + pad * 2);
    const octx = out.getContext('2d');
    octx.fillStyle = '#fff';
    octx.fillRect(0, 0, out.width, out.height);
    octx.drawImage(tmp, pad, pad);
    return out;
}

/* Membuat varian gambar untuk OCR. fastOnly = hanya 'gray' + 'adaptive' pada ukuran kecil (jauh lebih ringan). */
function buildOcrVariants(sourceCanvas, targetWidth = 1800, fastOnly = false) {
    const base = scaleToWidth(sourceCanvas, targetWidth);
    const w = base.width, h = base.height;
    const d = base.getContext('2d', { willReadFrequently: true }).getImageData(0, 0, w, h).data;
    let gray = new Uint8ClampedArray(w * h);
    let sum = 0;
    for (let i = 0, p = 0; i < d.length; i += 4, p++) {
        const lum = 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
        gray[p] = lum; sum += lum;
    }
    if (sum / gray.length < 100) {
        for (let i = 0; i < gray.length; i++) gray[i] = 255 - gray[i];
    }
    gray = stretchGray(gray);
    const winA = (Math.max(21, Math.round(w / 14)) | 1);
    const out = {
        gray: grayToCanvas(gray, w, h),
        adaptive: grayToCanvas(adaptiveBinarize(gray, w, h, winA, 8), w, h)
    };
    if (!fastOnly) {
        const winB = (Math.max(15, Math.round(w / 30)) | 1);
        out.fine = grayToCanvas(adaptiveBinarize(gray, w, h, winB, 12), w, h);
    }
    return out;
}

function extractLabelCandidates(rawText, fieldType) {
    const candidates = [];
    const pushUnique = (val) => {
        const clean = String(val || '').trim();
        if (clean && !candidates.includes(clean)) candidates.push(clean);
    };

    const upper = String(rawText || '').toUpperCase()
        .replace(/[|\\]/g, '/')
        .replace(/[\u2013\u2014]/g, '-');

    if (fieldType === 'mac') {
        const macSepRegex = /(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}/g;
        (upper.match(macSepRegex) || []).forEach(m => {
            const hex = m.replace(/[^0-9A-F]/g, '');
            if (hex.length === 12) pushUnique(hex.match(/.{1,2}/g).join('-'));
        });

        upper.split(/[\s,.;()/]+/).forEach(tok => {
            const fixed = tok.replace(/O/g, '0').replace(/[IL]/g, '1').replace(/S/g, '5').replace(/[^0-9A-F]/g, '');
            if (fixed.length === 12) pushUnique(fixed.match(/.{1,2}/g).join('-'));
        });

        const allHex = upper.replace(/O/g, '0').replace(/[IL]/g, '1').replace(/[^0-9A-F]/g, '');
        for (let i = 0; i + 12 <= allHex.length && candidates.length < 6; i++) {
            if (i === 0 || allHex.length <= 24) pushUnique(allHex.slice(i, i + 12).match(/.{1,2}/g).join('-'));
        }
    } else {
        const lines = upper.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

        lines.forEach(line => {
            const cleanedLine = line.replace(/\s*\/\s*/g, '/');
            const slashTokens = cleanedLine.match(/[A-Z0-9]+\/[A-Z0-9/]+/g) || [];
            slashTokens.forEach(tok => {
                const parts = tok.split('/').filter(Boolean);
                if (parts.length >= 2) {
                    const fixedParts = parts.map((p, idx) => {
                        if (idx >= parts.length - 2 && /^[0-9OILSZB]+$/.test(p) && /\d/.test(p)) {
                            return p.replace(/O/g, '0').replace(/[IL]/g, '1').replace(/Z/g, '2').replace(/S/g, '5').replace(/B/g, '8');
                        }
                        return p;
                    });
                    pushUnique(fixedParts.join('/'));
                } else {
                    pushUnique(tok);
                }
            });
        });

        lines.forEach(line => {
            line.split(/\s+/).forEach(w => {
                const cl = w.replace(/[^A-Z0-9/-]/g, '');
                if (cl.length >= 5 && /[0-9]/.test(cl)) pushUnique(cl);
            });
        });

        /* Tag hanya huruf / nama (mis. "NO TAGGING", "LOGITECH", "TIDAK ADA") */
        if (!candidates.length) {
            lines.forEach(line => {
                const cl = line.replace(/[^A-Z \-]/g, '').replace(/\s+/g, ' ').trim();
                if (cl.length < 3) return;
                pushUnique(cl === 'NO TAGGING' ? 'No Tagging' : cl);
            });
        }
    }

    return candidates.slice(0, 8);
}

/* Skor kemiripan kandidat dengan pola label tagging / MAC. */
function scoreCandidate(c, fieldType) {
    if (fieldType === 'mac') {
        const hex = String(c).replace(/[^0-9A-F]/g, '');
        return hex.length === 12 ? 6 : (hex.length > 0 && hex.length % 12 === 0 ? 4 : 0);
    }
    let s = 0;
    const parts = String(c).split('/').filter(Boolean);
    if (parts.length >= 4) s += 4; else if (parts.length === 3) s += 3; else if (parts.length === 2) s += 1.5;
    if (parts.length >= 2 && /^\d+$/.test(parts[parts.length - 1])) s += 1.5;
    if (parts.length >= 3 && /^\d{3,5}$/.test(parts[parts.length - 2])) s += 1.5;
    if (/^S[A-Z0-9]{1,5}$/.test(parts[0] || '')) s += 1;
    if (c.length >= 6 && c.length <= 26) s += 1; else s -= 1;
    if (/[^A-Za-z0-9/\- ]/.test(c)) s -= 2;
    /* Nama huruf saja diberi skor kecil tapi positif */
    if (parts.length < 2 && /^[A-Za-z][A-Za-z \-]{2,}$/.test(c)) s += 1.5;
    return s;
}

let ocrWorker = null, ocrWorkerLoading = null, ocrLogger = null;
function getOcrWorker(logger) {
    ocrLogger = logger;
    if (ocrWorker) return Promise.resolve(ocrWorker);
    if (!ocrWorkerLoading) {
        ocrWorkerLoading = (async () => {
            const w = await Tesseract.createWorker('eng', 1, { logger: (m) => { if (ocrLogger) ocrLogger(m); } });
            try { await w.setParameters({ tessedit_pageseg_mode: '6', preserve_interword_spaces: '0', user_defined_dpi: '300' }); } catch (e) {}
            ocrWorker = w;
            return w;
        })().catch((e) => { ocrWorkerLoading = null; throw e; });
    }
    return ocrWorkerLoading;
}

/* OCR multi-pass. mode 'fast' = 2 pass ringan & berhenti begitu yakin. mode 'deep' = 4 pass. */
async function recognizeBestCandidates(worker, variants, fieldType, onPass, mode = 'deep') {
    const passes = mode === 'fast'
        ? [
            { v: 'gray', psm: '6', wl: true },
            { v: 'adaptive', psm: '6', wl: true }
        ]
        : [
            { v: 'gray', psm: '6', wl: true },
            { v: 'adaptive', psm: '6', wl: true },
            { v: 'adaptive', psm: '11', wl: false },
            { v: 'fine', psm: '6', wl: false }
        ];
    const votes = new Map();
    const rawTexts = [];

    const topEntry = () => Array.from(votes.values())
        .sort((a, b) => (b.base + b.count * 2) - (a.base + a.count * 2))[0];
    const isConfident = (top) => {
        if (!top) return false;
        if (mode === 'fast') return top.base >= 5 || (top.count >= 2 && top.base >= 1);
        return top.base >= 6.5 && top.count >= 2;
    };

    for (let i = 0; i < passes.length; i++) {
        const p = passes[i];
        if (onPass) onPass(i + 1, passes.length);
        try {
            await worker.setParameters({
                tessedit_pageseg_mode: p.psm,
                tessedit_char_whitelist: p.wl ? OCR_WHITELIST : ''
            });
        } catch (e) {}
        const res = await worker.recognize(variants[p.v].toDataURL('image/png'));
        const text = (res && res.data && res.data.text) ? res.data.text : '';
        const conf = (res && res.data && res.data.confidence) ? res.data.confidence : 0;
        rawTexts.push(text);

        extractLabelCandidates(text, fieldType).forEach(c => {
            const e = votes.get(c) || { c, count: 0, base: scoreCandidate(c, fieldType), conf: 0 };
            e.count++;
            e.conf = Math.max(e.conf, conf);
            votes.set(c, e);
        });

        if (isConfident(topEntry())) break;
    }

    const ranked = Array.from(votes.values())
        .sort((a, b) => (b.base + b.count * 2 + b.conf / 50) - (a.base + a.count * 2 + a.conf / 50))
        .map(e => e.c)
        .slice(0, 6);
    return { candidates: ranked, rawText: rawTexts.join('\n'), confident: isConfident(topEntry()) };
}

/* CONFIG & DATA DEFAULTS */
const REGION_COLORS = {
    blitar: '#dc2626',
    tulungagung: '#059669',
    malang: '#2563eb',
    kediri: '#d97706'
};

const PALETTE = ['#dc2626', '#059669', '#2563eb', '#d97706', '#7c3aed', '#db2777', '#0891b2', '#475569'];
const SHEET_ICONS = ['monitor', 'server', 'shield', 'cctv', 'printer', 'wifi', 'router', 'scale', 'cpu', 'hard-drive', 'package'];
const FIELD_TYPES = [
    { id: 'text', label: 'Teks' },
    { id: 'number', label: 'Angka' },
    { id: 'mac', label: 'MAC' },
    { id: 'choice', label: 'Pilihan' },
    { id: 'note', label: 'Catatan' }
];
const TYPE_HINTS = {
    text: 'Isian bebas. Bisa diberi pilihan cepat (chips) dan tombol scan barcode + OCR.',
    number: 'Hanya angka, keyboard angka muncul otomatis.',
    mac: 'Diformat otomatis menjadi AA-BB-CC-DD-EE-FF.',
    choice: 'Pilih salah satu opsi dengan sekali tap.',
    note: 'Teks panjang untuk catatan tambahan.'
};

const NORMAL_OPTIONS = ['normal', 'ok', 'bersih', 'rapi', 'berfungsi normal', 'baik'];
const fld = (id, label, o = {}) => ({ id, label, placeholder: '', type: 'text', options: [], scan: false, section: '', ...o });

const defaultSheets = () => [
    {
        id: 'kasir', name: 'Kasir / PC', unitLabel: 'Kasir', icon: 'monitor', color: '#dc2626', defaultCount: 3,
        fields: [
            fld('q1', 'Komputer kondisi bersih / divakum', { type: 'choice', options: ['Bersih', 'Belum divakum'], section: 'Kondisi Fisik' }),
            fld('q2', 'Fan processor berfungsi dan baik?', { type: 'choice', options: ['OK', 'Berfungsi normal', 'Bermasalah', 'Mati'], section: 'Kondisi Fisik' }),
            fld('q4', 'Label Tagging Komputer', { placeholder: 'S/MB/2203/1 atau No Tagging', scan: true, options: ['No Tagging'], section: 'Label Tagging' }),
            fld('q5', 'Label Tagging Printer', { placeholder: 'SLZ1/... atau No Tagging', scan: true, options: ['No Tagging'], section: 'Label Tagging' }),
            fld('q6', 'Label Tagging Scanner', { placeholder: 'SLZ1/... atau No Tagging', scan: true, options: ['No Tagging'], section: 'Label Tagging' }),
            fld('q3', 'Kondisi Keyboard Kasir', { placeholder: 'Logitech / HP / Normal', options: ['Normal', 'Logitech', 'HP', 'Rusak'], section: 'Perangkat Kasir' }),
            fld('q7', 'Kondisi PC Kasir (Merk)', { placeholder: 'Wearnes / HP / Dell / Normal', options: ['HP', 'Dell', 'Wearnes', 'Normal'], section: 'Perangkat Kasir' }),
            fld('q8', 'Kondisi Mouse Kasir (Merk)', { placeholder: 'Logitech / Votre / Normal', options: ['Normal', 'Logitech', 'Votre', 'Rusak'], section: 'Perangkat Kasir' }),
            fld('q9', 'Kondisi Printer Kasir', { placeholder: 'Epson / SNBC / Normal', options: ['Normal', 'Epson', 'SNBC', 'Rusak'], section: 'Perangkat Kasir' }),
            fld('q10', 'Kondisi Scanner Kasir', { placeholder: 'Honeywell / Datalogic / Normal', options: ['Normal', 'Honeywell', 'Datalogic', 'Rusak'], section: 'Perangkat Kasir' })
        ]
    },
    {
        id: 'server', name: 'Server', unitLabel: 'Server', icon: 'server', color: '#2563eb', defaultCount: 1,
        fields: [
            fld('sv1', 'Kondisi Access Point', { placeholder: 'TP-Link 2 Pcs / Ubiquiti / Normal', options: ['TP-Link 1 Pcs', 'TP-Link 2 Pcs', 'Ubiquiti', 'Mikrotik', 'Normal', 'Rusak'], section: 'Kondisi Umum & Jaringan' }),
            fld('sv2', 'Kondisi CCTV', { placeholder: 'HIKVISION / Dahua / Normal', options: ['HIKVISION', 'DAHUA', 'Normal', 'Bermasalah'], section: 'Kondisi Umum & Jaringan' }),
            fld('sv3', 'Komputer Kondisi', { placeholder: 'Bersih / Kotor', options: ['Bersih', 'Belum divakum', 'Kotor'], section: 'Kondisi Umum & Jaringan' }),
            fld('sv4', 'DVR Terpasang Aktif', { placeholder: 'OK / Bermasalah / Mati', options: ['OK', 'Bermasalah', 'Mati', 'Tidak Ada'], section: 'Kondisi Umum & Jaringan' }),
            fld('sv5', 'Fan Processor Berfungsi', { placeholder: 'OK / Bermasalah / Mati', options: ['OK', 'Bermasalah', 'Mati'], section: 'Kondisi Umum & Jaringan' }),
            fld('sv6', 'Kondisi Fingerprint', { placeholder: 'NITGEN / Solution / Normal', options: ['NITGEN', 'Solution', 'ZKTeco', 'Normal', 'Rusak'], section: 'Kondisi Umum & Jaringan' }),
            fld('sv7', 'Kerapian Kabel Jaringan', { placeholder: 'RAPI / Kurang Rapi', options: ['RAPI', 'Kurang Rapi', 'Berantakan'], section: 'Kondisi Umum & Jaringan' }),
            fld('sv8', 'Kondisi Komputer Server', { placeholder: 'Normal / Bermasalah', options: ['Normal', 'Bermasalah', 'Mati'], section: 'Kondisi Umum & Jaringan' }),
            fld('sv9', 'Label Tagging Access Point', { placeholder: 'SLZ1/.../.../... atau No Tagging', scan: true, options: ['No Tagging'], section: 'Label Tagging Perangkat' }),
            fld('sv10', 'Label Tagging DVR', { placeholder: 'SLZ1/.../.../... atau No Tagging', scan: true, options: ['No Tagging'], section: 'Label Tagging Perangkat' }),
            fld('sv11', 'Label Tagging Komputer', { placeholder: 'SLZ1/.../.../... atau No Tagging', scan: true, options: ['No Tagging'], section: 'Label Tagging Perangkat' }),
            fld('sv12', 'Label Tagging PDA', { placeholder: 'SLZ1/.../.../... atau No Tagging', scan: true, options: ['No Tagging', 'Tidak Ada'], section: 'Label Tagging Perangkat' }),
            fld('sv13', 'Label Tagging Printer', { placeholder: 'SLZ1/.../.../... atau No Tagging', scan: true, options: ['No Tagging'], section: 'Label Tagging Perangkat' }),
            fld('sv14', 'Label Tagging Scanner', { placeholder: 'SLZ1/.../.../... atau No Tagging', scan: true, options: ['No Tagging'], section: 'Label Tagging Perangkat' }),
            fld('sv15', 'Label Tagging Timbangan', { placeholder: 'SLZ1/.../.../... atau No Tagging', scan: true, options: ['No Tagging', 'Tidak Ada'], section: 'Label Tagging Perangkat' }),
            fld('sv16', 'Label Tagging UPS', { placeholder: 'SLZ1/.../.../... atau No Tagging', scan: true, options: ['No Tagging'], section: 'Label Tagging Perangkat' }),
            fld('sv17', 'MAC Address Access Point', { type: 'mac', placeholder: 'AA-BB-CC-DD-EE-FF', scan: true, options: ['Tidak Terbaca'], section: 'MAC Address Perangkat' }),
            fld('sv18', 'MAC Address PDA', { type: 'mac', placeholder: 'AA-BB-CC-DD-EE-FF', scan: true, options: ['Tidak Ada', 'Tidak Terbaca'], section: 'MAC Address Perangkat' }),
            fld('sv19', 'MAC Address Timbangan', { type: 'mac', placeholder: 'AA-BB-CC-DD-EE-FF', scan: true, options: ['Tidak Ada', 'Tidak Terbaca'], section: 'MAC Address Perangkat' }),
            fld('sv20', 'Kondisi Modem Server', { placeholder: 'Normal / Telkomsel / Indihome', options: ['Normal', 'OK', 'Bermasalah', 'Tidak Ada'], section: 'Kondisi Perangkat Server' }),
            fld('sv21', 'Monitor Server', { placeholder: 'Normal / LG / HP / AOC', options: ['Normal', 'OK', 'LG', 'HP', 'Dell', 'Rusak'], section: 'Kondisi Perangkat Server' }),
            fld('sv22', 'Kondisi PC Server', { placeholder: 'Normal / HP / Dell / Lenovo', options: ['Normal', 'OK', 'HP', 'Dell', 'Lenovo', 'Bermasalah'], section: 'Kondisi Perangkat Server' }),
            fld('sv23', 'Kondisi PDT Server', { placeholder: 'Normal / Zebra / Honeywell', options: ['Normal', 'OK', 'Zebra', 'Honeywell', 'Rusak', 'Tidak Ada'], section: 'Kondisi Perangkat Server' }),
            fld('sv24', 'Kondisi Printer LX-300', { placeholder: 'Normal / Epson LX-300+II', options: ['Normal', 'OK', 'Epson LX-300', 'Rusak', 'Tidak Ada'], section: 'Kondisi Perangkat Server' }),
            fld('sv25', 'Kondisi Router', { placeholder: 'Normal / Mikrotik / Cisco', options: ['Normal', 'OK', 'Mikrotik', 'Cisco', 'TP-Link', 'Bermasalah'], section: 'Kondisi Perangkat Server' }),
            fld('sv26', 'Kondisi Scanner', { placeholder: 'Normal / Honeywell / Datalogic', options: ['Normal', 'OK', 'Honeywell', 'Datalogic', 'Rusak'], section: 'Kondisi Perangkat Server' })
        ]
    },
    {
        id: 'server_admin', name: 'Server Admin', unitLabel: 'Server Admin', icon: 'shield', color: '#d97706', defaultCount: 1,
        fields: [
            fld('sa1', 'KONDISI MONITOR', { type: 'choice', options: ['BAIK', 'RUSAK'], section: 'Pemeriksaan Utama' }),
            fld('sa2', 'KONDISI PC', { type: 'choice', options: ['BAIK', 'RUSAK'], section: 'Pemeriksaan Utama' }),
            fld('sa3', 'KONDISI SCANNER', { type: 'choice', options: ['BAIK', 'RUSAK'], section: 'Pemeriksaan Utama' })
        ]
    }
];

const defaultRegions = () => [
    { id: 'blitar', name: 'BLITAR', color: REGION_COLORS.blitar },
    { id: 'tulungagung', name: 'TULUNGAGUNG', color: REGION_COLORS.tulungagung },
    { id: 'malang', name: 'MALANG', color: REGION_COLORS.malang },
    { id: 'kediri', name: 'KEDIRI', color: REGION_COLORS.kediri }
];

const DEFAULT_STORES = {
    blitar: [
        { code: 'NB46', nama: 'NB46 - SRENGAT BLITAR', alamat: 'Srengat, Blitar' },
        { code: 'NB61', nama: 'NB61 - DANDONG SRENGAT', alamat: 'Dandong, Srengat' },
        { code: 'NB43', nama: 'NB43 - PONGGOK BLITAR', alamat: 'Ponggok, Blitar' },
        { code: 'SL2E', nama: 'SL2E - SANANKULON BLITAR', alamat: 'Sanankulon, Blitar' },
        { code: 'SL1Z', nama: 'SL1Z - JATI BLITAR', alamat: 'Jati, Blitar' },
        { code: 'NB60', nama: 'NB60 - TULISKRIYO BLITAR', alamat: 'Tuliskriyo, Blitar' },
        { code: 'SL1P', nama: 'SL1P - BANTENG BLOROK', alamat: 'Banteng Blorok' },
        { code: 'SL2F', nama: 'SL2F - SUDANCO SUPRIADI', alamat: 'Sudanco Supriadi' },
        { code: 'SL1Q', nama: 'SL1Q - GARUM BLITAR', alamat: 'Garum, Blitar' },
        { code: 'NB57', nama: 'NB57 - PANGSUD WLINGI', alamat: 'Pangsud, Wlingi' },
        { code: '044B', nama: '044B - SUPER GAJAHMADA', alamat: 'Gajahmada' }
    ],
    tulungagung: [
        { code: 'NB41', nama: 'NB41 - NGANTRU TULUNGAGUNG', alamat: 'Ngantru, Tulungagung' },
        { code: 'NB39', nama: 'NB39 - SULTAN AGUNG', alamat: 'Sultan Agung' },
        { code: 'NB48', nama: 'NB48 - PAHLAWAN TULUNGAGUNG', alamat: 'Pahlawan, Tulungagung' },
        { code: 'NB44', nama: 'NB44 - MT HARYONO T.AGUNG', alamat: 'MT Haryono, Tulungagung' },
        { code: 'NB50', nama: 'NB50 - BANDUNG TULUNGAGUNG', alamat: 'Bandung, Tulungagung' },
        { code: 'NB32', nama: 'NB32 - NGUNUT TULUNGAGUNG', alamat: 'Ngunut, Tulungagung' }
    ]
};

function makeDefaultUnits(sheets, storeObj) {
    const out = [];
    const storeName = storeObj ? storeObj.nama.toUpperCase() : '';
    const isSuper = storeName.includes('SUPER');

    sheets.forEach(sh => {
        if (sh.id === 'server_admin' && !isSuper) return;
        for (let i = 1; i <= sh.defaultCount; i++) {
            out.push({ id: uid(), sheetId: sh.id, name: sh.unitLabel + ' ' + i });
        }
    });
    return out;
}

function buildDefaultState() {
    const sheets = defaultSheets(), regions = defaultRegions();
    const stores = [
        ...DEFAULT_STORES.blitar.map((s, idx) => ({ id: 'st_b' + (idx + 1), code: s.code, nama: s.nama, alamat: s.alamat, maps: '', regionId: 'blitar' })),
        ...DEFAULT_STORES.tulungagung.map((s, idx) => ({ id: 'st_t' + (idx + 1), code: s.code, nama: s.nama, alamat: s.alamat, maps: '', regionId: 'tulungagung' }))
    ];
    const units = {};
    stores.forEach(s => { units[s.id] = makeDefaultUnits(sheets, s); });
    return { v: 2, schemaRev: SCHEMA_REV, activeMonth: localMonth(), sheets, regions, stores, units, records: {}, drafts: {} };
}

function sanitizeState(st) {
    const out = { v: 2, schemaRev: st.schemaRev || SCHEMA_REV };
    const savedMonth = isValidMonth(st.activeMonth) ? st.activeMonth : localMonth();
    out.activeMonth = localMonth();
    out.sheets = (Array.isArray(st.sheets) ? st.sheets : []).filter(s => s && s.id).map(s => ({
        id: String(s.id),
        name: s.name || 'Sheet',
        unitLabel: s.unitLabel || 'Unit',
        icon: SHEET_ICONS.includes(s.icon) ? s.icon : 'package',
        color: /^#[0-9a-f]{6}$/i.test(String(s.color || '')) ? s.color : PALETTE[0],
        defaultCount: Math.max(0, Math.min(10, parseInt(s.defaultCount, 10) || 0)),
        fields: (Array.isArray(s.fields) ? s.fields : []).filter(f => f && f.id).map(f => ({
            id: String(f.id),
            label: f.label || '',
            placeholder: f.placeholder || '',
            type: FIELD_TYPES.some(t => t.id === f.type) ? f.type : 'text',
            options: Array.isArray(f.options) ? f.options.map(String) : [],
            scan: !!f.scan,
            section: f.section || ''
        }))
    }));
    if (!out.sheets.length) out.sheets = defaultSheets();

    const defaultRegionList = defaultRegions();
    const defaultRegionIds = new Set(defaultRegionList.map(region => region.id));
    const savedRegions = Array.isArray(st.regions) ? st.regions : [];
    const normalizeRegion = (region, fallbackColor) => ({
        id: String(region.id),
        name: String(region.name || 'WILAYAH').trim().toUpperCase().slice(0, 60),
        color: /^#[0-9a-f]{6}$/i.test(String(region.color || '')) ? region.color : fallbackColor
    });
    out.regions = defaultRegionList
        .filter(defaultRegion => savedRegions.some(region => region && region.id === defaultRegion.id))
        .map(defaultRegion => {
            const existing = savedRegions.find(region => region && region.id === defaultRegion.id);
            return normalizeRegion(existing, defaultRegion.color);
        });
    const regionIds = new Set(out.regions.map(region => region.id));
    savedRegions.forEach((region, index) => {
        if (!region || !isSafeId(region.id) || defaultRegionIds.has(region.id) || regionIds.has(region.id)) return;
        out.regions.push(normalizeRegion(region, PALETTE[index % PALETTE.length]));
        regionIds.add(String(region.id));
    });
    if (!out.regions.length) out.regions = defaultRegionList;

    const rids = out.regions.map(r => r.id);
    out.stores = (Array.isArray(st.stores) ? st.stores : []).filter(s => s && isSafeId(s.id)).map(s => ({
        id: String(s.id),
        code: String(s.code || '').trim().toUpperCase(),
        nama: String(s.nama || 'TOKO').trim().toUpperCase(),
        alamat: s.alamat || '',
        maps: s.maps || '',
        regionId: rids.includes(s.regionId) ? s.regionId : rids[0]
    }));

    const sids = out.sheets.map(s => s.id);
    out.units = {};
    out.stores.forEach(s => {
        const list = st.units && Array.isArray(st.units[s.id]) ? st.units[s.id] : null;
        out.units[s.id] = list
            ? list.filter(u => u && u.id && sids.includes(u.sheetId)).map(u => ({ id: String(u.id), sheetId: u.sheetId, name: u.name || 'Unit' }))
            : makeDefaultUnits(out.sheets, s);
    });

    out.records = migrateMonthlyEntries(st.records, savedMonth);
    out.drafts = migrateMonthlyEntries(st.drafts, savedMonth);
    return out;
}

let scannerInstance = null;
let confirmResolver = null;
let lastScanBuffer = { text: '', count: 0, time: 0 };
let wakeLock = null;

const scanConfig = () => ({
    formatsToSupport: [
        Html5QrcodeSupportedFormats.CODE_128,
        Html5QrcodeSupportedFormats.CODE_39,
        Html5QrcodeSupportedFormats.CODE_93,
        Html5QrcodeSupportedFormats.QR_CODE,
        Html5QrcodeSupportedFormats.EAN_13,
        Html5QrcodeSupportedFormats.EAN_8,
        Html5QrcodeSupportedFormats.UPC_A,
        Html5QrcodeSupportedFormats.UPC_E,
        Html5QrcodeSupportedFormats.ITF,
        Html5QrcodeSupportedFormats.CODABAR,
        Html5QrcodeSupportedFormats.DATA_MATRIX
    ],
    experimentalFeatures: { useBarCodeDetectorIfSupported: true },
    verbose: false
});

/* ===================== APP MAIN ===================== */
function app() {
    return {
        isLoading: true,
        isLocked: true,
        showPostUnlockSplash: false,
        splashMessage: '',
        pinInput: '',
        showPinAuth: false,
        correctPinHash: store.get('custom_pin_hash', DEFAULT_PIN_HASH),
        pinSecurity: store.get('pin_security', { failures: 0, lockedUntil: 0 }),

        changePinForm: { oldPin: '', newPin: '', confirmPin: '' },
        showOldPin: false, showNewPin: false, showConfirmPin: false,

        view: 'dashboard',
        sheets: [], regions: [], stores: [], units: {}, records: {}, drafts: {},
        activeMonth: localMonth(),
        activeToko: {}, activeUnit: {}, formData: {}, draftDirty: false,

        search: '', filterRegion: 'all', filterStatus: 'all',
        settingsPage: 'menu', editSheetId: '', storeSearch: '', storeRegion: 'all',

        readerUnitId: 'all',
        readerHideEmpty: false,

        modal: { open: false, type: '', data: {} },
        confirmState: { open: false, title: '', message: '', okLabel: 'Ya', danger: false },
        toastMsg: '', toastType: 'ok', toastTimer: null,
        saveTimer: null, draftTimer: null,

        isOnline: navigator.onLine,
        pwaPrompt: null,

        scanOpen: false, scanTarget: null, scanStatus: '', scanBusy: false,
        scanContinuous: false,
        scanHasTorch: false, scanTorchOn: false,
        scanZoom: 1, scanZoomMin: 1, scanZoomMax: 1, scanZoomStep: 0.1,
        scanCameras: [], scanCamIdx: 0,

        ocrBusy: false,
        ocrProgressText: '',
        ocrChoiceModal: { open: false, field: null, fieldLabel: '', candidates: [], editedText: '', previewUrl: '' },

        paletteColors: PALETTE, sheetIcons: SHEET_ICONS, fieldTypes: FIELD_TYPES,

        async init() {
            this.loadState();
            
            const sessionUnlocked = sessionStore.get('unlocked');
            if (sessionUnlocked === 'true') {
                this.isLocked = false;
            }

            this.restoreSession();
            this.syncCurrentMonth();
            this.monthCheckTimer = setInterval(() => this.syncCurrentMonth(), 60000);
            this.watchIcons();

            try { if (navigator.storage && navigator.storage.persist) navigator.storage.persist(); } catch (e) {}

            window.addEventListener('online', () => { this.isOnline = true; this.toast('Koneksi internet kembali online'); });
            window.addEventListener('offline', () => { this.isOnline = false; this.toast('Mode offline aktif — data tetap aman'); });
            window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); this.pwaPrompt = e; });

            document.addEventListener('keydown', (e) => { if (e.key === 'Escape') this.onEscape(); });
            window.addEventListener('pagehide', () => this.flush());
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) {
                    this.syncCurrentMonth();
                    this.flush();
                    if (this.scanOpen) this.closeScanner();
                } else this.syncCurrentMonth();
            });

            this.isLoading = false;
            this.$nextTick(() => this.animateView(this.view));
        },

        async unlockApp() {
            const cleanPin = this.pinInput.trim();
            if (!cleanPin) {
                this.toast('Masukkan PIN terlebih dahulu', 'error');
                return;
            }
            if (!/^\d{5}$/.test(cleanPin)) {
                this.toast('PIN harus berupa 5 digit angka', 'error');
                this.pinInput = '';
                return;
            }
            if (!this.pinSecurity || typeof this.pinSecurity !== 'object') {
                this.pinSecurity = { failures: 0, lockedUntil: 0 };
            }
            const remaining = Number(this.pinSecurity.lockedUntil || 0) - Date.now();
            if (remaining > 0) {
                this.pinInput = '';
                this.toast('Terlalu banyak percobaan. Coba lagi dalam ' + Math.ceil(remaining / 60000) + ' menit.', 'error');
                return;
            }
            const result = await verifyPin(cleanPin, this.correctPinHash);
            if (result.valid) {
                if (result.upgradedHash) {
                    this.correctPinHash = result.upgradedHash;
                    store.set('custom_pin_hash', result.upgradedHash);
                }
                this.pinSecurity = { failures: 0, lockedUntil: 0 };
                store.set('pin_security', this.pinSecurity);
                this.isLocked = false;
                this.pinInput = '';
                sessionStore.set('unlocked', 'true');
                await this.playDashboardSplash();
            } else {
                this.pinSecurity.failures = Number(this.pinSecurity.failures || 0) + 1;
                if (this.pinSecurity.failures >= 5) {
                    const delay = Math.min(15 * 60 * 1000, 30 * 1000 * (2 ** Math.min(this.pinSecurity.failures - 5, 5)));
                    this.pinSecurity.lockedUntil = Date.now() + delay;
                }
                store.set('pin_security', this.pinSecurity);
                this.toast(this.pinSecurity.lockedUntil > Date.now()
                    ? 'Terlalu banyak percobaan. Coba lagi dalam ' + Math.ceil((this.pinSecurity.lockedUntil - Date.now()) / 60000) + ' menit.'
                    : 'PIN salah. Percobaan ke-' + this.pinSecurity.failures + '.', 'error');
                this.pinInput = '';
            }
        },

        async playDashboardSplash() {
            const message = 'PIN benar. Mengarahkan ke dashboard...';
            this.splashMessage = '';
            this.showPostUnlockSplash = true;
            for (let index = 1; index <= message.length; index++) {
                this.splashMessage = message.slice(0, index);
                await new Promise(resolve => setTimeout(resolve, 28));
            }
            await new Promise(resolve => setTimeout(resolve, 350));
            this.go('dashboard');
            this.showPostUnlockSplash = false;
            this.splashMessage = '';
            this.toast('Aplikasi berhasil dibuka');
        },

        lockApp() {
            this.isLocked = true;
            sessionStore.del('unlocked');
            this.toast('Aplikasi terkunci');
        },

        async updatePin() {
            const { oldPin, newPin, confirmPin } = this.changePinForm;
            if (!/^\d{5}$/.test(oldPin)) return this.toast('PIN lama harus 5 digit angka', 'error');
            if (!/^\d{5}$/.test(newPin)) return this.toast('PIN baru harus tepat 5 digit angka', 'error');
            if (newPin !== confirmPin) return this.toast('Konfirmasi PIN baru tidak cocok', 'error');

            const oldPinResult = await verifyPin(oldPin, this.correctPinHash);
            if (!oldPinResult.valid) return this.toast('PIN lama salah!', 'error');

            const newHash = await createPinHash(newPin);
            this.correctPinHash = newHash;
            store.set('custom_pin_hash', newHash);

            this.changePinForm = { oldPin: '', newPin: '', confirmPin: '' };
            this.toast('PIN berhasil diubah');
        },

        async installPwa() {
            if (!this.pwaPrompt) return;
            this.pwaPrompt.prompt();
            await this.pwaPrompt.userChoice;
            this.pwaPrompt = null;
        },

        loadState() {
            let st = store.get('state');
            if (!st || st.v !== 2) st = buildDefaultState();
            try { st = sanitizeState(st); } catch (e) { st = sanitizeState(buildDefaultState()); }
            this.applyState(st);
            this.saveNow();
        },

        applyState(st) {
            this.sheets = st.sheets; this.regions = st.regions; this.stores = st.stores;
            this.units = st.units; this.records = st.records; this.drafts = st.drafts;
            this.activeMonth = st.activeMonth || localMonth();
        },

        snapshot() {
            return { v: 2, schemaRev: SCHEMA_REV, activeMonth: this.activeMonth, sheets: this.sheets, regions: this.regions, stores: this.stores, units: this.units, records: this.records, drafts: this.drafts };
        },
        saveNow() {
            clearTimeout(this.saveTimer);
            if (!store.set('state', this.snapshot())) this.toast('Penyimpanan browser penuh atau diblokir', 'error');
        },
        flush() { this.commitDraftNow(); this.saveNow(); },

        restoreSession() {
            const s = store.get('session', {}) || {};
            const t = this.stores.find(x => x.id === s.storeId);
            if (t && (s.view === 'units' || s.view === 'form')) {
                this.activeToko = t;
                const list = this.units[t.id] || [];
                const u = list.find(x => x.id === s.unitId);
                if (s.view === 'form' && u) {
                    this.loadForm(u);
                    this.view = 'form';
                } else {
                    this.view = 'units';
                }
            } else {
                this.view = 'dashboard';
            }
        },

        watchIcons() {
            let refreshQueued = false;
            const containsIcon = node => node.nodeType === Node.ELEMENT_NODE &&
                (node.matches('[data-lucide]') || node.querySelector('[data-lucide]'));
            const observer = new MutationObserver(mutations => {
                const addedIcons = mutations.some(mutation => Array.from(mutation.addedNodes).some(containsIcon));
                if (!addedIcons || refreshQueued) return;
                refreshQueued = true;
                requestAnimationFrame(() => {
                    refreshQueued = false;
                    if (window.lucide) lucide.createIcons();
                });
            });
            observer.observe(document.body, { childList: true, subtree: true });
            if (window.lucide) lucide.createIcons();
        },

        animateView(view) {
            if (!Element.prototype.animate || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
            const screen = Array.from(document.querySelectorAll('main > [x-show]'))
                .find(element => element.getAttribute('x-show') === "view === '" + view + "'");
            if (!screen) return;

            const targets = [...screen.querySelectorAll('.dashboard-heading, .overview-panel, .store-browser, .region-section, .store-card, .card')];
            targets.forEach((target, index) => target.animate(
                [{ opacity: 0, transform: 'translateY(12px)' }, { opacity: 1, transform: 'translateY(0)' }],
                { duration: 340, delay: Math.min(index * 28, 280), easing: 'cubic-bezier(.2,.7,.2,1)' }
            ));
        },

        icon(name, cls) {
            const safeName = SHEET_ICONS.includes(name) || ['circle-check'].includes(name) ? name : 'package';
            const safeClass = /^[a-z0-9\s-]*$/i.test(String(cls || '')) ? cls : '';
            return '<i data-lucide="' + safeName + '" class="' + safeClass + '"></i>';
        },
        key(s, u) { return this.activeMonth + '|' + s + '|' + u; },
        get monthLabel() { return formatMonth(this.activeMonth); },
        syncCurrentMonth() {
            const currentMonth = localMonth();
            if (currentMonth === this.activeMonth) return false;
            this.commitDraftNow();
            this.activeMonth = currentMonth;
            if (this.view === 'form' && this.activeUnit.id) this.loadForm(this.activeUnit);
            this.saveNow();
            this.toast('Periode pencatatan sekarang ' + formatMonth(currentMonth));
            return true;
        },
        toast(msg, type = 'ok') {
            this.toastMsg = msg; this.toastType = type;
            clearTimeout(this.toastTimer);
            this.toastTimer = setTimeout(() => { this.toastMsg = ''; }, 2800);
        },
        ask(title, message, okLabel = 'Ya', danger = false) {
            return new Promise(resolve => {
                confirmResolver = resolve;
                this.confirmState = { open: true, title, message, okLabel, danger };
            });
        },
        answer(v) {
            this.confirmState.open = false;
            if (confirmResolver) { const r = confirmResolver; confirmResolver = null; r(v); }
        },
        onEscape() {
            if (this.confirmState.open) this.answer(false);
            else if (this.ocrChoiceModal.open) this.ocrChoiceModal.open = false;
            else if (this.scanOpen) this.closeScanner();
            else if (this.modal.open) this.closeModal();
        },

        go(view) {
            if (this.view === 'form' && view !== 'form') this.commitDraftNow();
            this.view = view;
            store.set('session', {
                view: view === 'reader' ? 'units' : view,
                storeId: this.activeToko.id || '',
                unitId: view === 'form' ? (this.activeUnit.id || '') : '',
                activeMonth: this.activeMonth
            });
            window.scrollTo({ top: 0 });
            this.$nextTick(() => this.animateView(view));
        },
        openStore(t) { this.activeToko = t; this.activeUnit = {}; this.ensureSuperAdminUnit(t); this.go('units'); },
        openExamination() {
            if (this.activeToko && this.activeToko.id) {
                this.go('units');
                return;
            }
            this.go('dashboard');
            this.toast('Pilih toko terlebih dahulu untuk membuka pemeriksaan', 'error');
            this.$nextTick(() => {
                const storeList = document.querySelector('.store-browser');
                if (storeList) storeList.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
        },

        hasSuperAdminSheet(storeObj) {
            if (!storeObj || !storeObj.nama) return false;
            return storeObj.nama.toUpperCase().includes('SUPER');
        },

        ensureSuperAdminUnit(t) {
            if (!t || !t.id) return;
            const isSuper = this.hasSuperAdminSheet(t);
            let uList = this.units[t.id] || [];
            const hasSA = uList.some(u => u.sheetId === 'server_admin');

            if (isSuper && !hasSA) {
                uList.push({ id: uid(), sheetId: 'server_admin', name: 'Server Admin 1' });
                this.units[t.id] = uList;
                this.saveNow();
            } else if (!isSuper && hasSA) {
                this.units[t.id] = uList.filter(u => u.sheetId !== 'server_admin');
                this.saveNow();
            }
        },

        get headerSubtitle() { return this.regions.length + ' wilayah · ' + this.stores.length + ' toko'; },
        get totalStores() { return this.stores.length; },
        get doneStores() { return this.stores.filter(s => this.isStoreDone(s.id)).length; },
        get totalUnits() { return this.stores.reduce((n, s) => n + (this.units[s.id] || []).length, 0); },
        get doneUnits() { return this.stores.reduce((n, s) => n + (this.units[s.id] || []).filter(u => this.isUnitDone(s.id, u.id)).length, 0); },
        get progress() { return this.totalStores ? (this.doneStores / this.totalStores) * 100 : 0; },
        get totalFields() { return this.sheets.reduce((n, s) => n + s.fields.length, 0); },
        get filtersActive() { return !!this.search.trim() || this.filterRegion !== 'all' || this.filterStatus !== 'all'; },
        get visibleRegions() {
            return this.regions.filter(r => (this.filterRegion === 'all' || this.filterRegion === r.id) && this.regionStores(r.id).length > 0);
        },

        get unitGroups() {
            const list = this.units[this.activeToko.id] || [];
            const isSuper = this.hasSuperAdminSheet(this.activeToko);

            return this.sheets
                .filter(sh => sh.id !== 'server_admin' || isSuper)
                .map(sh => ({ sheet: sh, units: list.filter(u => u.sheetId === sh.id) }));
        },

        get formFields() { return this.fieldsOf(this.activeUnit); },
        get filledCount() { return this.formFields.filter(f => String(this.formData[f.id] || '').trim() !== '').length; },
        get currentSheet() { return this.sheets.find(s => s.id === this.editSheetId) || null; },
        get settingsStores() {
            const q = this.storeSearch.trim().toLowerCase();
            return this.stores
                .filter(s => this.storeRegion === 'all' || s.regionId === this.storeRegion)
                .filter(s => !q || (s.code + ' ' + s.nama + ' ' + s.alamat).toLowerCase().includes(q));
        },
        get settingsTitle() {
            const map = { menu: 'Pengaturan', sheets: 'Jenis pemeriksaan', stores: 'Toko', regions: 'Wilayah', pin: 'Ubah PIN keamanan', data: 'Data & Cadangan' };
            if (this.settingsPage === 'sheetEdit') return this.currentSheet ? this.currentSheet.name : 'Sheet';
            return map[this.settingsPage] || 'Pengaturan';
        },
        get modalTitle() {
            const edit = !!this.modal.data.id;
            const map = {
                store: edit ? 'Edit toko' : 'Toko baru', region: edit ? 'Edit wilayah' : 'Wilayah baru',
                sheet: edit ? 'Ubah jenis pemeriksaan' : 'Jenis pemeriksaan baru', field: edit ? 'Ubah pertanyaan' : 'Pertanyaan baru', unit: 'Ganti nama unit'
            };
            return map[this.modal.type] || '';
        },
        get modalCanDelete() { return ['store', 'region', 'field'].includes(this.modal.type) && !!this.modal.data.id; },

        get readerUnits() {
            const t = this.activeToko;
            if (!t || !t.id || !this.units) return [];
            const list = this.units[t.id];
            return Array.isArray(list) ? list.filter(u => u && u.id) : [];
        },
        get readerItems() {
            try {
                const t = this.activeToko;
                if (!t || !t.id) return [];
                const order = (this.sheets || []).map(s => s.id);
                const list = this.readerUnits
                    .filter(u => this.readerUnitId === 'all' || u.id === this.readerUnitId)
                    .slice()
                    .sort((a, b) => order.indexOf(a.sheetId) - order.indexOf(b.sheetId));

                return list.map(u => {
                    const sh = this.sheetOf(u) || { id: '', name: 'Unit', color: '#475569', icon: 'package', fields: [] };
                    const fields = Array.isArray(sh.fields) ? sh.fields : [];
                    const vals = this.valuesOf(t.id, u.id) || {};
                    const rows = [];
                    let lastSection = '';
                    let filled = 0;

                    fields.forEach(f => {
                        if (!f || !f.id) return;
                        const rawVal = vals[f.id];
                        const v = rawVal == null ? '' : String(rawVal).trim();
                        if (v) filled++;
                        if (this.readerHideEmpty && !v) return;
                        const sec = f.section ? String(f.section) : '';
                        const showSection = sec && sec !== lastSection ? sec : '';
                        if (sec) lastSection = sec;
                        rows.push({ id: f.id, label: f.label || f.id, value: v, section: showSection });
                    });

                    return {
                        unit: u,
                        sheet: sh,
                        status: this.statusOf(t.id, u.id),
                        rows,
                        filled,
                        total: fields.length
                    };
                });
            } catch (err) { return []; }
        },

        sheetOf(unit) { return unit ? (this.sheets.find(s => s.id === unit.sheetId) || null) : null; },
        fieldsOf(unit) { const sh = this.sheetOf(unit); return sh ? sh.fields : []; },
        sheetColor(unit) { const sh = this.sheetOf(unit); return sh ? sh.color : '#475569'; },
        sheetIconOf(unit) { const sh = this.sheetOf(unit); return sh ? sh.icon : 'package'; },
        regionName(id) { const r = this.regions.find(x => x.id === id); return r ? r.name : ''; },
        regionColor(id) {
            const r = this.regions.find(x => x.id === id);
            return r ? r.color : '#94a3b8';
        },
        regionStoreCount(id) { return this.stores.filter(s => s.regionId === id).length; },
        mapsUrl(t) {
            if (!t) return '#';
            if (t.maps && t.maps.trim()) {
                try {
                    const url = new URL(t.maps.trim());
                    return ['https:', 'http:'].includes(url.protocol) ? url.href : '#';
                } catch (e) { return '#'; }
            }
            const query = [t.nama, t.alamat].filter(Boolean).join(' ');
            return 'https://www.google.com/maps/search/?api=1&query=' + encodeURIComponent(query);
        },

        isUnitDone(s, u) { const r = this.records[this.key(s, u)]; return !!(r && r.done); },
        hasDraft(s, u) { return !!this.drafts[this.key(s, u)] && !this.isUnitDone(s, u); },
        unitProgress(storeId) {
            const l = this.units[storeId] || [];
            return { total: l.length, done: l.filter(u => this.isUnitDone(storeId, u.id)).length };
        },
        unitPercent(storeId) { const p = this.unitProgress(storeId); return p.total ? (p.done / p.total) * 100 : 0; },
        isStoreDone(storeId) { const p = this.unitProgress(storeId); return p.total > 0 && p.done === p.total; },
        groupDone(g) { return g.units.filter(u => this.isUnitDone(this.activeToko.id, u.id)).length; },
        sheetProgress(storeId) {
            const l = this.units[storeId] || [];
            return this.sheets.map(sh => {
                const us = l.filter(u => u.sheetId === sh.id);
                return { sheet: sh, total: us.length, done: us.filter(u => this.isUnitDone(storeId, u.id)).length };
            }).filter(x => x.total > 0);
        },
        spStyle(sp) {
            return sp.total > 0 && sp.done === sp.total ? 'background:#d1fae5;color:#047857' : 'background:' + sp.sheet.color + '1a;color:' + sp.sheet.color;
        },
        storeCardStyle(t, r) {
            const color = r.color;
            const base = 'border-left:4px solid ' + color + ';';
            return this.isStoreDone(t.id) ? base + 'background:#f0fdf4;' : base;
        },
        regionStores(rid) {
            const q = this.search.trim().toLowerCase();
            return this.stores
                .filter(s => s.regionId === rid)
                .filter(s => !q || (s.code + ' ' + s.nama + ' ' + s.alamat).toLowerCase().includes(q))
                .filter(s => this.filterStatus === 'all' || (this.filterStatus === 'done') === this.isStoreDone(s.id));
        },
        regionProgressText(rid) {
            const l = this.stores.filter(s => s.regionId === rid);
            return l.filter(s => this.isStoreDone(s.id)).length + '/' + l.length + ' selesai';
        },
        resetFilters() { this.search = ''; this.filterRegion = 'all'; this.filterStatus = 'all'; },
        sectionOf(list, index) {
            const f = list[index];
            if (!f || !f.section) return '';
            const p = list[index - 1];
            return !p || p.section !== f.section ? f.section : '';
        },
        sectionNames(sheetId) {
            const sh = this.sheets.find(s => s.id === sheetId);
            return sh ? [...new Set(sh.fields.map(f => f.section).filter(Boolean))] : [];
        },
        typeHint(t) { return TYPE_HINTS[t] || ''; },
        typeLabel(t) { const f = FIELD_TYPES.find(x => x.id === t); return f ? f.label : 'Teks'; },
        fieldMeta(f) {
            const parts = [this.typeLabel(f.type)];
            if (f.scan) parts.push('scan + OCR');
            if (f.options && f.options.length) parts.push(f.options.length + ' pilihan');
            return parts.join(' · ');
        },

        openReader(unitId) {
            this.readerUnitId = (typeof unitId === 'string' && unitId) ? unitId : 'all';
            this.readerHideEmpty = false;
            this.go('reader');
        },
        readerStatusStyle(status) {
            if (status === 'Selesai') return 'background:#d1fae5;color:#047857';
            if (status === 'Draft') return 'background:#fef3c7;color:#b45309';
            return 'background:#f1f5f9;color:#64748b';
        },
        async copyText(text, label) {
            const t = String(text == null ? '' : text);
            if (!t) return;
            let ok = false;
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(t);
                    ok = true;
                }
            } catch (e) { ok = false; }
            if (!ok) {
                try {
                    const ta = document.createElement('textarea');
                    ta.value = t;
                    ta.setAttribute('readonly', '');
                    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;font-size:16px';
                    document.body.appendChild(ta);
                    ta.select();
                    ta.setSelectionRange(0, t.length);
                    ok = document.execCommand('copy');
                    ta.remove();
                } catch (e) { ok = false; }
            }
            this.toast(ok ? (label ? label + ' disalin' : 'Disalin') : 'Gagal menyalin', ok ? 'ok' : 'error');
        },
        copyUnitText(item) {
            if (!item || !item.unit) return;
            const lines = [(this.activeToko.nama || 'Toko') + ' - ' + item.unit.name];
            (item.rows || []).forEach(r => {
                if (r.section) lines.push('', '[' + r.section + ']');
                lines.push(r.label + ': ' + (r.value || '-'));
            });
            this.copyText(lines.join('\n'), item.unit.name);
        },

        addUnit(sheetId) {
            const sh = this.sheets.find(s => s.id === sheetId);
            const list = this.units[this.activeToko.id];
            if (!sh || !list) return;
            const maxNo = list.filter(u => u.sheetId === sheetId).reduce((m, u) => Math.max(m, parseInt((u.name.match(/\d+/) || [0])[0], 10)), 0);
            const name = sh.unitLabel + ' ' + (maxNo + 1);
            list.push({ id: uid(), sheetId, name });
            this.saveNow();
            this.toast(name + ' ditambahkan');
        },
        async deleteUnit(unit) {
            const list = this.units[this.activeToko.id] || [];
            if (list.length <= 1) return this.toast('Minimal harus ada 1 unit di toko', 'error');
            const ok = await this.ask('Hapus ' + unit.name + '?', 'Data isian unit ini ikut terhapus.', 'Hapus', true);
            if (!ok) return;
            this.units[this.activeToko.id] = list.filter(u => u.id !== unit.id);
            this.purgeUnit(this.activeToko.id, unit.id);
            if (this.readerUnitId === unit.id) this.readerUnitId = 'all';
            this.saveNow();
        },
        renameUnit(unit) { this.openModal('unit', { id: unit.id, name: unit.name }); },

        loadForm(unit) {
            this.activeUnit = unit;
            const saved = this.valuesOf(this.activeToko.id, unit.id);
            const data = {};
            this.fieldsOf(unit).forEach(f => { data[f.id] = saved[f.id] != null ? String(saved[f.id]) : ''; });
            this.formData = data;
            this.draftDirty = false;
        },
        openForm(unit) { this.loadForm(unit); this.go('form'); },

        canCopyFromSiblingUnit() {
            if (!this.activeToko.id || !this.activeUnit.id) return false;
            const sameSheetUnits = (this.units[this.activeToko.id] || []).filter(u => u.sheetId === this.activeUnit.sheetId);
            return sameSheetUnits.length > 1 && sameSheetUnits[0].id !== this.activeUnit.id;
        },
        copyFromFirstSiblingUnit() {
            const sameSheetUnits = (this.units[this.activeToko.id] || []).filter(u => u.sheetId === this.activeUnit.sheetId);
            const firstUnit = sameSheetUnits[0];
            if (!firstUnit) return;
            const srcVals = this.valuesOf(this.activeToko.id, firstUnit.id);
            let copied = 0;
            this.formFields.forEach(f => {
                if (!f.scan && f.type !== 'mac' && srcVals[f.id]) {
                    this.formData[f.id] = srcVals[f.id];
                    copied++;
                }
            });
            if (copied > 0) {
                this.saveDraft();
                this.toast(copied + ' kolom kondisi disalin dari ' + firstUnit.name);
            } else {
                this.toast(firstUnit.name + ' belum memiliki data kondisi untuk disalin', 'error');
            }
        },

        isNonMacValue(v) {
            const s = String(v || '').trim().toLowerCase();
            return ['tidak ada', 'tidak terbaca', 'no tagging', '-'].includes(s);
        },

        formatMac(raw) {
            if (this.isNonMacValue(raw)) return raw;
            const hex = String(raw || '').replace(/[^0-9a-fA-F]/g, '').toUpperCase().slice(0, 48);
            if (!hex) return '';
            const macChunks = hex.match(/.{1,12}/g) || [];
            return macChunks.map(chunk => (chunk.match(/.{1,2}/g) || []).join('-')).join(', ');
        },

        macLen(v) { return String(v || '').replace(/[^0-9a-fA-F]/g, '').length; },

        isMacValid(v) {
            if (!v || this.isNonMacValue(v)) return true;
            const len = this.macLen(v);
            return len > 0 && len <= 48 && len % 12 === 0;
        },

        macStatusText(v) {
            const len = this.macLen(v);
            const count = Math.ceil(len / 12);
            const rem = len % 12;
            if (rem === 0) return '✓ ' + count + ' MAC Address lengkap (' + count + '/4 perangkat)';
            return 'MAC ke-' + count + ' belum lengkap (' + rem + '/12 karakter hex)';
        },

        normalizeTag(v) {
            let s = String(v || '').trim().replace(/\s*\/\s*/g, '/').replace(/\s+/g, ' ');
            if (s.includes('/')) s = s.toUpperCase();
            return s;
        },

        onInput(q, ev) {
            let v = ev.target.value;
            if (q.type === 'mac') v = this.formatMac(v);
            else if (q.type === 'number') v = v.replace(/[^0-9.,]/g, '');
            if (ev.target.value !== v) ev.target.value = v;
            this.formData[q.id] = v;
            this.saveDraft();
        },
        setChoice(q, opt) {
            this.formData[q.id] = this.formData[q.id] === opt ? '' : opt;
            this.saveDraft();
        },
        choiceOptions(q) {
            const cur = this.formData[q.id];
            const opts = q.options || [];
            return cur && !opts.includes(cur) ? [...opts, cur] : opts;
        },
        fillDefaultNormals() {
            let count = 0;
            this.formFields.forEach(f => {
                if (String(this.formData[f.id] || '').trim() || f.scan || f.type === 'mac' || !f.options || !f.options.length) return;
                const normal = f.options.find(o => NORMAL_OPTIONS.includes(String(o).trim().toLowerCase()));
                if (normal) {
                    this.formData[f.id] = normal;
                    count++;
                }
            });
            if (count > 0) {
                this.saveDraft();
                this.toast(count + ' kolom kondisi terisi otomatis');
            } else {
                this.toast('Tidak ada kolom kosong yang bisa diisi standar');
            }
        },
        saveDraft() {
            this.draftDirty = true;
            clearTimeout(this.draftTimer);
            this.draftTimer = setTimeout(() => this.commitDraftNow(), 250);
        },
        commitDraftNow() {
            clearTimeout(this.draftTimer);
            if (!this.draftDirty || !this.activeToko.id || !this.activeUnit.id) return;
            const k = this.key(this.activeToko.id, this.activeUnit.id);
            const hasAnyValue = Object.values(this.formData).some(v => String(v || '').trim() !== '');

            if (hasAnyValue) {
                this.drafts[k] = clone(this.formData);
            } else {
                delete this.drafts[k];
                delete this.records[k];
            }
            this.draftDirty = false;
            this.saveNow();
        },
        focusNext(index) {
            for (let i = index + 1; i < this.formFields.length; i++) {
                const el = document.querySelector('[data-field="' + i + '"]');
                if (el) { el.focus(); if (el.tagName === 'INPUT' && el.select) el.select(); return; }
            }
            if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
        },
        async clearForm() {
            const ok = await this.ask('Kosongkan form?', 'Semua isian dan status selesai pada unit ini akan direset.', 'Kosongkan', true);
            if (!ok) return;
            clearTimeout(this.draftTimer);
            const data = {};
            this.formFields.forEach(f => { data[f.id] = ''; });
            this.formData = data;
            this.draftDirty = false;

            const k = this.key(this.activeToko.id, this.activeUnit.id);
            delete this.records[k];
            delete this.drafts[k];

            this.saveNow();
            this.toast('Form dikosongkan & status unit direset');
        },
        async saveForm() {
            const isSA = this.activeUnit.sheetId === 'server_admin';
            const emptyCount = this.formFields.filter(f => String(this.formData[f.id] || '').trim() === '').length;

            if (isSA && emptyCount > 0) {
                this.toast('Seluruh 3 pertanyaan Server Admin wajib dijawab!', 'error');
                return;
            }

            const hasAnyValue = this.formFields.some(f => String(this.formData[f.id] || '').trim() !== '');
            const sid = this.activeToko.id, k = this.key(sid, this.activeUnit.id), name = this.activeUnit.name;

            if (!hasAnyValue) {
                clearTimeout(this.draftTimer);
                delete this.records[k];
                delete this.drafts[k];
                this.draftDirty = false;
                this.saveNow();
                this.go('units');
                this.toast(name + ' dikosongkan (Belum diisi)');
                return;
            }

            const bad = this.formFields.filter(f => f.type === 'mac' && this.formData[f.id] && !this.isMacValid(this.formData[f.id]));
            if (bad.length) {
                const ok = await this.ask('MAC Address belum lengkap', bad.length + ' kolom MAC belum genap 12 karakter hex: ' + bad.map(b => b.label).join(', ') + '. Tetap simpan?', 'Tetap simpan');
                if (!ok) return;
            }

            if (!isSA && emptyCount > 0) {
                const ok = await this.ask('Masih ada kolom kosong', emptyCount + ' dari ' + this.formFields.length + ' kolom belum terisi. Tetap simpan?', 'Tetap simpan');
                if (!ok) return;
            }

            clearTimeout(this.draftTimer);
            this.records[k] = { values: clone(this.formData), done: true, at: new Date().toISOString() };
            delete this.drafts[k];
            this.draftDirty = false;
            this.saveNow();
            this.go('units');
            this.toast(name + ' tersimpan');
            if (this.isStoreDone(sid) && window.confetti) {
                const all = this.doneStores === this.totalStores;
                confetti({ particleCount: all ? 220 : 80, spread: all ? 100 : 60, origin: { y: 0.7 } });
            }
        },

        /* ===================== SCANNER (v2.1 cepat) ===================== */
        async openScanner(q) {
            if (!window.Html5Qrcode) return this.toast('Library scanner belum termuat. Cek koneksi.', 'error');
            this.scanTarget = q;
            this.scanBusy = false;
            this.ocrBusy = false;
            this.scanOpen = true;
            this.scanHasTorch = false;
            this.scanTorchOn = false;
            this.scanZoomMax = 1;
            lastScanBuffer = { text: '', count: 0, time: 0 };
            this.requestWakeLock();

            /* Muat mesin OCR di latar belakang supaya OCR pertama tidak menunggu */
            if (window.Tesseract) getOcrWorker(null).catch(() => {});

            if (!window.isSecureContext) {
                this.scanStatus = 'Kamera langsung memerlukan HTTPS. Gunakan opsi pindai dari foto.';
                return;
            }

            this.scanStatus = 'Menyiapkan kamera fokus otomatis...';
            await this.$nextTick();

            try {
                const devices = await Html5Qrcode.getCameras();
                this.scanCameras = devices || [];
                if (this.scanCameras.length > 0 && this.scanCamIdx === 0) {
                    const backIdx = this.scanCameras.findIndex(c => /back|rear|belakang|environment/i.test(c.label) && !/wide|ultra|0\.5/i.test(c.label));
                    this.scanCamIdx = backIdx >= 0 ? backIdx : (this.scanCameras.length - 1);
                }
            } catch (e) {
                this.scanCameras = [];
            }

            await this.startCameraStream();
        },

        async requestWakeLock() {
            try { if ('wakeLock' in navigator) wakeLock = await navigator.wakeLock.request('screen'); } catch (e) { wakeLock = null; }
        },
        releaseWakeLock() {
            try { if (wakeLock) wakeLock.release(); } catch (e) {}
            wakeLock = null;
        },

        async startCameraStream() {
            await this.stopCamera();
            this.scanStatus = 'Arahkan ke barcode atau tag toko.';

            try {
                scannerInstance = new Html5Qrcode('scan-reader', scanConfig());
                const camSource = this.scanCameras[this.scanCamIdx]
                    ? { deviceId: { exact: this.scanCameras[this.scanCamIdx].id } }
                    : { facingMode: { ideal: 'environment' } };

                await scannerInstance.start(
                    camSource,
                    {
                        fps: 15,
                        aspectRatio: 1.333334,
                        disableFlip: false,
                        videoConstraints: {
                            ...camSource,
                            width: { ideal: 1920 },
                            height: { ideal: 1080 },
                            focusMode: { ideal: 'continuous' }
                        }
                    },
                    (decodedText) => this.handleScan(decodedText),
                    () => {}
                );

                setTimeout(() => this.detectCameraCapabilities(), 350);
                this.startNativeLoop();
            } catch (e) {
                scannerInstance = null;
                this.scanStatus = 'Kamera tidak dapat diakses. Periksa izin kamera perangkat.';
            }
        },

        /* Loop tambahan: BarcodeDetector native membaca seluruh frame video (lebih cepat & toleran blur). */
        startNativeLoop() {
            this.stopNativeLoop();
            const tick = async () => {
                if (!this.scanOpen) return;
                try {
                    if (!this.scanBusy && !this.ocrBusy) {
                        const video = document.querySelector('#scan-reader video');
                        if (video && video.readyState >= 2 && video.videoWidth) {
                            const det = await getNativeDetector();
                            if (!det) return;
                            const codes = await det.detect(video);
                            if (codes && codes.length && codes[0].rawValue) this.handleScan(codes[0].rawValue);
                        }
                    }
                } catch (e) {}
                nativeScanTimer = setTimeout(tick, 180);
            };
            nativeScanTimer = setTimeout(tick, 600);
        },
        stopNativeLoop() {
            if (nativeScanTimer) clearTimeout(nativeScanTimer);
            nativeScanTimer = null;
        },

        detectCameraCapabilities() {
            try {
                const videoEl = document.querySelector('#scan-reader video');
                if (!videoEl || !videoEl.srcObject) return;
                const track = videoEl.srcObject.getVideoTracks()[0];
                if (!track || !track.getCapabilities) return;
                const caps = track.getCapabilities();

                if (caps.torch) this.scanHasTorch = true;
                if (Array.isArray(caps.focusMode) && caps.focusMode.includes('continuous')) {
                    track.applyConstraints({ advanced: [{ focusMode: 'continuous' }] }).catch(() => {});
                }
                if (caps.zoom) {
                    this.scanZoomMin = caps.zoom.min || 1;
                    this.scanZoomMax = Math.min(caps.zoom.max || 1, 4);
                    this.scanZoomStep = caps.zoom.step || 0.1;
                    const startZoom = Math.min(Math.max(1.4, this.scanZoomMin), this.scanZoomMax);
                    this.scanZoom = startZoom;
                    track.applyConstraints({ advanced: [{ zoom: startZoom }] }).catch(() => {});
                }
            } catch (e) {}
        },

        currentVideoTrack() {
            const videoEl = document.querySelector('#scan-reader video');
            return videoEl && videoEl.srcObject ? videoEl.srcObject.getVideoTracks()[0] : null;
        },

        async toggleTorch() {
            try {
                const track = this.currentVideoTrack();
                if (!track) return;
                this.scanTorchOn = !this.scanTorchOn;
                await track.applyConstraints({ advanced: [{ torch: this.scanTorchOn }] });
            } catch (e) { this.scanTorchOn = false; }
        },

        async applyZoom() {
            try {
                const track = this.currentVideoTrack();
                if (!track) return;
                await track.applyConstraints({ advanced: [{ zoom: Number(this.scanZoom) }] });
            } catch (e) {}
        },

        async switchCamera() {
            if (this.scanCameras.length < 2) return;
            this.scanCamIdx = (this.scanCamIdx + 1) % this.scanCameras.length;
            await this.startCameraStream();
        },

        async handleScan(rawText) {
            if (!this.scanOpen || this.scanBusy || this.ocrBusy) return;
            const cleaned = String(rawText || '').trim();
            if (cleaned.length < 2) return;

            const now = Date.now();
            if (lastScanBuffer.text === cleaned && (now - lastScanBuffer.time) < 1500) return;
            lastScanBuffer = { text: cleaned, count: 1, time: now };

            this.scanBusy = true;
            playScanBeep();
            if (navigator.vibrate) navigator.vibrate([50, 30, 50]);

            const q = this.scanTarget;
            const upperCode = cleaned.toUpperCase();

            // Saat mengisi kolom, hanya kode toko yang persis sama yang dianggap tag toko (hindari salah deteksi).
            const matchedStore = this.stores.find(s =>
                s.code.toUpperCase() === upperCode ||
                (!q && upperCode.length >= 4 && s.nama.toUpperCase().includes(upperCode))
            );

            if (matchedStore) {
                await this.closeScanner();
                this.openStore(matchedStore);
                this.toast('Tag Toko Ditemukan: ' + matchedStore.nama);
                return;
            }

            if (q) {
                if (this.scanContinuous) {
                    this.applyScanAndAdvance(cleaned, q);
                } else {
                    await this.closeScanner();
                    this.applyScan(cleaned, q);
                }
            } else {
                this.toast('Kode di-scan: ' + cleaned);
                setTimeout(() => { this.scanBusy = false; }, 1500);
            }
        },

        getGuideCropRect(videoEl) {
            const box = document.getElementById('scan-box');
            const vw = videoEl.videoWidth, vh = videoEl.videoHeight;
            const ca = box && box.clientHeight ? box.clientWidth / box.clientHeight : 4 / 3;
            const va = vw / vh;
            let sw, sh;
            if (va > ca) { sh = vh; sw = vh * ca; } else { sw = vw; sh = vw / ca; }
            const sx = (vw - sw) / 2, sy = (vh - sh) / 2;
            const gw = sw * GUIDE.w, gh = sh * GUIDE.h;
            return { x: Math.floor(sx + (sw - gw) / 2), y: Math.floor(sy + (sh - gh) / 2), w: Math.floor(gw), h: Math.floor(gh) };
        },

        /* Ambil beberapa frame beruntun, pilih yang paling tajam untuk OCR. */
        async captureOcrFromLiveVideo() {
            if (this.ocrBusy) return;
            const videoEl = document.querySelector('#scan-reader video');
            if (!videoEl || !videoEl.videoWidth) return this.toast('Kamera belum siap', 'error');

            this.ocrBusy = true;
            this.ocrProgressText = 'Mengambil gambar tertajam...';
            try {
                let bestCanvas = null, bestScore = -1;
                for (let i = 0; i < 3; i++) {
                    const r = this.getGuideCropRect(videoEl);
                    const c = makeCanvas(r.w, r.h);
                    c.getContext('2d').drawImage(videoEl, r.x, r.y, r.w, r.h, 0, 0, r.w, r.h);
                    const sc = canvasSharpness(c);
                    if (sc > bestScore) { bestScore = sc; bestCanvas = c; }
                    await sleep(70);
                }
                await this.runOcrPipeline(bestCanvas, this.scanTarget);
            } catch (e) {
                this.ocrBusy = false;
                this.toast('Gagal mengambil gambar', 'error');
            }
        },

        /* Coba baca barcode dari gambar (native dulu, lalu html5-qrcode pada gambar yang sudah dipertajam). */
        async tryDecodeBarcode(sourceCanvas, enhancedCanvas) {
            try {
                const det = await getNativeDetector();
                if (det) {
                    const codes = await det.detect(sourceCanvas);
                    if (codes && codes.length && String(codes[0].rawValue || '').trim().length >= 2) return String(codes[0].rawValue).trim();
                    const codes2 = await det.detect(enhancedCanvas);
                    if (codes2 && codes2.length && String(codes2[0].rawValue || '').trim().length >= 2) return String(codes2[0].rawValue).trim();
                }
            } catch (e) {}

            let qrReader = null;
            try {
                const blob = await new Promise(res => enhancedCanvas.toBlob(res, 'image/png'));
                const file = new File([blob], 'enhanced.png', { type: 'image/png' });
                qrReader = new Html5Qrcode('scan-file', scanConfig());
                const hit = await qrReader.scanFile(file, false);
                if (hit && String(hit).trim().length >= 2) return String(hit).trim();
            } catch (e) {
            } finally {
                try { if (qrReader) qrReader.clear(); } catch (e) {}
            }
            return null;
        },

        /* OCR: jalur CEPAT dulu (gambar kecil, 2 pass), baru MENDALAM bila belum yakin. */
        async runOcrPipeline(sourceCanvas, targetField) {
            if (!window.Tesseract) { this.ocrBusy = false; return this.toast('Library OCR belum termuat', 'error'); }
            this.ocrBusy = true;
            this.ocrProgressText = 'Membaca...';

            try {
                await sleep(30);
                let variants = buildOcrVariants(sourceCanvas, 1000, true);

                this.ocrProgressText = 'Memeriksa barcode...';
                const barcodeHit = await this.tryDecodeBarcode(sourceCanvas, variants.gray);
                if (barcodeHit) {
                    this.ocrBusy = false;
                    this.handleScan(barcodeHit);
                    return;
                }

                this.ocrProgressText = 'Menyiapkan mesin OCR...';
                const worker = await getOcrWorker((m) => {
                    if (m.status === 'recognizing text') {
                        this.ocrProgressText = (this.ocrPassLabel || 'Membaca') + ' ' + Math.round((m.progress || 0) * 100) + '%';
                    } else if (m.status && /load|init/i.test(m.status)) {
                        this.ocrProgressText = 'Menyiapkan mesin OCR...';
                    }
                });

                const fieldType = targetField ? targetField.type : 'text';
                const onPass = (label) => (i, n) => {
                    this.ocrPassLabel = label + ' ' + i + '/' + n + ':';
                    this.ocrProgressText = this.ocrPassLabel + ' 0%';
                };

                let result = await recognizeBestCandidates(worker, variants, fieldType, onPass('Cepat'), 'fast');

                /* Belum yakin -> pembacaan mendalam (lebih lama) */
                if (!result.confident) {
                    this.ocrProgressText = 'Pembacaan mendalam...';
                    await sleep(30);
                    variants = buildOcrVariants(sourceCanvas);
                    result = await recognizeBestCandidates(worker, variants, fieldType, onPass('Mendalam'), 'deep');
                }
                this.ocrPassLabel = '';

                const { candidates, rawText } = result;
                this.ocrBusy = false;
                if (!candidates.length && !rawText.trim()) {
                    this.scanStatus = 'Teks tidak terbaca. Dekatkan, pastikan terang & fokus.';
                    this.toast('Teks tidak terbaca', 'error');
                    return;
                }

                playScanBeep();
                await this.closeScanner();
                const best = candidates[0] || rawText.trim().split(/\s+/)[0] || '';
                this.ocrChoiceModal = {
                    open: true,
                    field: targetField,
                    fieldLabel: targetField ? targetField.label : 'Hasil OCR',
                    candidates,
                    editedText: targetField && targetField.type === 'mac' ? this.formatMac(best) : best,
                    previewUrl: variants.gray.toDataURL('image/jpeg', 0.85)
                };
            } catch (err) {
                this.ocrBusy = false;
                this.toast('Gagal OCR, periksa koneksi', 'error');
            }
        },

        confirmOcrText() {
            const q = this.ocrChoiceModal.field;
            const val = String(this.ocrChoiceModal.editedText || '').trim();
            this.ocrChoiceModal.open = false;
            if (!val) return;
            if (q) this.applyScan(val, q);
            else this.handleScan(val);
        },

        async setQuickNoTagging() {
            const q = this.scanTarget;
            if (!q) return;
            if (this.scanContinuous) {
                this.applyScanAndAdvance('No Tagging', q);
            } else {
                await this.closeScanner();
                this.formData[q.id] = 'No Tagging';
                this.saveDraft();
                this.toast(q.label + ': No Tagging');
            }
        },

        async stopCamera() {
            this.stopNativeLoop();
            const s = scannerInstance;
            scannerInstance = null;
            this.scanTorchOn = false;
            if (!s) return;
            try { if (s.isScanning) await s.stop(); s.clear(); } catch (e) {}
        },
        async closeScanner() {
            this.scanOpen = false;
            this.ocrBusy = false;
            this.releaseWakeLock();
            await this.stopCamera();
        },

        async scanFromPhoto(ev) {
            const file = ev.target.files && ev.target.files[0];
            ev.target.value = '';
            if (!file) return;
            const q = this.scanTarget;
            this.scanStatus = 'Membaca kode dari foto...';
            await this.stopCamera();

            let bmp = null;
            try { bmp = await createImageBitmap(file); } catch (e) { bmp = null; }

            // 1) BarcodeDetector native langsung pada foto asli
            if (bmp) {
                try {
                    const det = await getNativeDetector();
                    if (det) {
                        const codes = await det.detect(bmp);
                        if (codes && codes.length && String(codes[0].rawValue || '').trim().length >= 2) {
                            playScanBeep();
                            this.scanBusy = false;
                            await this.handleScan(String(codes[0].rawValue).trim());
                            if (this.scanOpen) await this.startCameraStream();
                            return;
                        }
                    }
                } catch (e) {}
            }

            // 2) html5-qrcode pada file asli
            let reader;
            try {
                reader = new Html5Qrcode('scan-file', scanConfig());
                const text = await reader.scanFile(file, false);
                playScanBeep();
                this.scanBusy = false;
                await this.handleScan(text);
                if (this.scanOpen) await this.startCameraStream();
                return;
            } catch (e) {
            } finally {
                try { if (reader) reader.clear(); } catch (e) {}
            }

            // 3) OCR (cepat dulu, lalu mendalam) pada foto
            try {
                if (!bmp) bmp = await createImageBitmap(file);
                const maxSide = 2600;
                const scale = Math.min(1, maxSide / Math.max(bmp.width, bmp.height));
                const cvs = makeCanvas(bmp.width * scale, bmp.height * scale);
                cvs.getContext('2d').drawImage(bmp, 0, 0, cvs.width, cvs.height);
                await this.runOcrPipeline(cvs, q);
            } catch (err) {
                this.ocrBusy = false;
                this.scanStatus = 'Gagal memproses foto.';
            }
        },

        applyScanAndAdvance(raw, q) {
            let value = String(raw).trim();
            value = q.type === 'mac' ? this.formatMac(value) : this.normalizeTag(value);
            this.formData[q.id] = value;
            this.saveDraft();

            const dup = this.findDuplicate(value, q.id);
            if (dup) this.toast('Peringatan: kode sudah dipakai di ' + dup, 'error');
            else this.toast(q.label + ' → ' + value);

            const curIdx = this.formFields.findIndex(x => x.id === q.id);
            const nextScanField = this.formFields.slice(curIdx + 1).find(f => f.scan);
            if (nextScanField) {
                this.scanTarget = nextScanField;
                this.scanStatus = 'Lanjut ke: ' + nextScanField.label;
                setTimeout(() => { this.scanBusy = false; lastScanBuffer = { text: '', count: 0, time: 0 }; }, 900);
            } else {
                this.closeScanner();
                this.toast('Selesai di-scan!');
            }
        },

        applyScan(raw, q) {
            let value = String(raw).trim();
            value = q.type === 'mac' ? this.formatMac(value) : this.normalizeTag(value);
            this.formData[q.id] = value;
            this.saveDraft();

            const dup = this.findDuplicate(value, q.id);
            if (dup) this.toast('Peringatan: kode dipakai di ' + dup, 'error');
            else this.toast('Terisi: ' + value);

            const idx = this.formFields.findIndex(x => x.id === q.id);
            this.$nextTick(() => this.focusNext(idx));
        },

        findDuplicate(value, qid) {
            const v = String(value || '').toUpperCase();
            if (!v || v === 'NO TAGGING' || v === 'TIDAK ADA' || v === 'TIDAK TERBACA') return null;
            const hit = (vals, fields, skipId) => fields.some(f => f.scan && f.id !== skipId && String(vals[f.id] || '').trim().toUpperCase() === v);
            if (hit(this.formData, this.formFields, qid)) return 'kolom lain di unit ini';
            const cur = this.key(this.activeToko.id, this.activeUnit.id);
            for (const s of this.stores) {
                for (const u of (this.units[s.id] || [])) {
                    const k = this.key(s.id, u.id);
                    if (k === cur) continue;
                    const vals = this.valuesOf(s.id, u.id);
                    if (vals && hit(vals, this.fieldsOf(u), null)) return s.nama + ' – ' + u.name;
                }
            }
            return null;
        },

        openSettings(page = 'menu', sheetId = '') {
            this.settingsPage = page;
            if (sheetId) this.editSheetId = sheetId;
            this.go('settings');
        },
        openSettingsPage(page) { this.settingsPage = page; window.scrollTo({ top: 0 }); },
        editSheet(id) { this.editSheetId = id; this.settingsPage = 'sheetEdit'; window.scrollTo({ top: 0 }); },
        settingsBack() {
            if (this.settingsPage === 'sheetEdit') this.settingsPage = 'sheets';
            else if (this.settingsPage !== 'menu') this.settingsPage = 'menu';
            else this.go('dashboard');
            window.scrollTo({ top: 0 });
        },

        openModal(type, data = {}) { this.modal = { open: true, type, data: clone(data) }; },
        closeModal() { this.modal.open = false; },
        modalSave() {
            const t = this.modal.type;
            if (t === 'store') this.saveStoreModal();
            else if (t === 'region') this.saveRegionModal();
            else if (t === 'sheet') this.saveSheetModal();
            else if (t === 'field') this.saveFieldModal();
            else if (t === 'unit') this.saveUnitModal();
        },
        modalDelete() {
            const t = this.modal.type, id = this.modal.data.id;
            if (t === 'store') this.deleteStore(id);
            else if (t === 'region') this.deleteRegion(id);
            else if (t === 'field') this.deleteField(this.modal.data.sheetId, id);
        },

        saveUnitModal() {
            const d = this.modal.data;
            if (!d.name || !d.name.trim()) return this.toast('Nama unit wajib diisi', 'error');
            const u = (this.units[this.activeToko.id] || []).find(x => x.id === d.id);
            if (u) u.name = d.name.trim();
            this.saveNow(); this.closeModal();
        },

        openStoreModal(t) {
            this.openModal('store', t
                ? { id: t.id, code: t.code || '', nama: t.nama, alamat: t.alamat || '', maps: t.maps || '', regionId: t.regionId }
                : { id: null, code: '', nama: '', alamat: '', maps: '', regionId: this.regions[0] ? this.regions[0].id : '' });
        },
        saveStoreModal() {
            const d = this.modal.data;
            const code = String(d.code || '').trim().toUpperCase();
            const nama = String(d.nama || '').trim().toUpperCase();

            if (!code) return this.toast('Kode toko wajib diisi', 'error');
            if (!nama) return this.toast('Nama toko wajib diisi', 'error');

            const dupCode = this.stores.find(s => s.id !== d.id && s.code === code);
            if (dupCode) return this.toast('Kode toko ' + code + ' sudah digunakan', 'error');

            const payload = { code, nama, alamat: (d.alamat || '').trim(), maps: (d.maps || '').trim(), regionId: d.regionId };
            if (d.id) {
                const t = this.stores.find(s => s.id === d.id);
                if (t) Object.assign(t, payload);
                this.ensureSuperAdminUnit(t);
                this.toast('Toko diperbarui');
            } else {
                const id = 'st_' + uid();
                const newStore = { id, ...payload, alamat: payload.alamat || 'Alamat belum diisi' };
                this.stores.push(newStore);
                this.units[id] = makeDefaultUnits(this.sheets, newStore);
                this.toast('Toko ditambahkan');
            }
            this.saveNow(); this.closeModal();
        },
        async deleteStore(id) {
            const t = this.stores.find(s => s.id === id);
            if (!t) return;
            const ok = await this.ask('Hapus toko?', '"' + t.nama + '" beserta semua datanya akan dihapus.', 'Hapus', true);
            if (!ok) return;
            this.stores = this.stores.filter(s => s.id !== id);
            delete this.units[id];
            this.purge('|' + id + '|');
            if (this.activeToko.id === id) { this.activeToko = {}; this.activeUnit = {}; }
            this.saveNow(); this.closeModal(); this.toast('Toko dihapus');
        },
        purge(storePrefix) {
            Object.keys(this.records).forEach(k => { if (k.includes(storePrefix)) delete this.records[k]; });
            Object.keys(this.drafts).forEach(k => { if (k.includes(storePrefix)) delete this.drafts[k]; });
        },
        purgeUnit(storeId, unitId) {
            const suffix = '|' + storeId + '|' + unitId;
            Object.keys(this.records).forEach(k => { if (k.endsWith(suffix)) delete this.records[k]; });
            Object.keys(this.drafts).forEach(k => { if (k.endsWith(suffix)) delete this.drafts[k]; });
        },

        openRegionModal(r) {
            this.openModal('region', r
                ? { id: r.id, name: r.name, color: r.color }
                : { id: null, name: '', color: PALETTE[this.regions.length % PALETTE.length] });
        },
        saveRegionModal() {
            const d = this.modal.data;
            const name = (d.name || '').trim().toUpperCase();
            if (!name) return this.toast('Nama wilayah wajib diisi', 'error');
            if (this.regions.some(r => r.id !== d.id && r.name.toUpperCase() === name)) return this.toast('Nama wilayah sudah ada', 'error');
            if (d.id) {
                const r = this.regions.find(x => x.id === d.id);
                if (r) { r.name = name; r.color = d.color; }
                this.toast('Wilayah diperbarui');
            } else {
                const slug = name.toLowerCase().replace(/[^a-z0-9]/g, '_') || 'wilayah';
                const baseId = isSafeId(slug) ? slug : 'wilayah_' + uid();
                const id = this.regions.some(region => region.id === baseId) ? baseId + '_' + uid() : baseId;
                this.regions.push({ id, name, color: d.color });
                this.toast('Wilayah ditambahkan');
            }
            this.saveNow(); this.closeModal();
        },
        async deleteRegion(id) {
            if (this.regions.length <= 1) return this.toast('Minimal harus ada 1 wilayah', 'error');
            const r = this.regions.find(x => x.id === id);
            if (!r) return;
            const target = this.regions.find(x => x.id !== id);
            const n = this.regionStoreCount(id);
            const msg = n > 0 ? n + ' toko akan dipindahkan ke wilayah "' + target.name + '".' : 'Wilayah ini kosong.';
            const ok = await this.ask('Hapus wilayah "' + r.name + '"?', msg, 'Hapus', true);
            if (!ok) return;
            this.stores.forEach(s => { if (s.regionId === id) s.regionId = target.id; });
            this.regions = this.regions.filter(x => x.id !== id);
            if (this.filterRegion === id) this.filterRegion = 'all';
            if (this.storeRegion === id) this.storeRegion = 'all';
            this.saveNow(); this.closeModal(); this.toast('Wilayah dihapus');
        },

        openSheetModal(sh) {
            this.openModal('sheet', sh
                ? { id: sh.id, name: sh.name, unitLabel: sh.unitLabel, icon: sh.icon, color: sh.color, defaultCount: sh.defaultCount }
                : { id: null, name: '', unitLabel: '', icon: 'package', color: PALETTE[this.sheets.length % PALETTE.length], defaultCount: 1 });
        },
        saveSheetModal() {
            const d = this.modal.data;
            const name = (d.name || '').trim();
            if (!name) return this.toast('Nama sheet wajib diisi', 'error');
            const payload = { name, unitLabel: (d.unitLabel || '').trim() || name, icon: d.icon, color: d.color, defaultCount: Math.max(0, Math.min(10, parseInt(d.defaultCount, 10) || 0)) };
            if (d.id) {
                const sh = this.sheets.find(s => s.id === d.id);
                if (sh) Object.assign(sh, payload);
                this.toast('Sheet diperbarui');
            } else {
                const id = 'sh_' + uid();
                const sh = { id, ...payload, fields: [] };
                this.sheets.push(sh);
                this.stores.forEach(s => {
                    if (!this.units[s.id]) this.units[s.id] = [];
                    for (let i = 1; i <= sh.defaultCount; i++) this.units[s.id].push({ id: uid(), sheetId: id, name: sh.unitLabel + ' ' + i });
                });
                this.editSheetId = id;
                this.settingsPage = 'sheetEdit';
                this.toast('Sheet dibuat.');
            }
            this.saveNow(); this.closeModal();
        },
        async deleteSheet(id) {
            if (id === 'server_admin') return this.toast('Sheet Server Admin bawaan sistem tidak dapat dihapus', 'error');
            if (this.sheets.length <= 1) return this.toast('Minimal harus ada 1 sheet', 'error');
            const sh = this.sheets.find(s => s.id === id);
            if (!sh) return;
            const ok = await this.ask('Hapus sheet "' + sh.name + '"?', 'Semua unit sheet ini di semua toko beserta datanya ikut terhapus.', 'Hapus', true);
            if (!ok) return;
            this.stores.forEach(s => {
                (this.units[s.id] || []).filter(u => u.sheetId === id).forEach(u => {
                    this.purgeUnit(s.id, u.id);
                });
                this.units[s.id] = (this.units[s.id] || []).filter(u => u.sheetId !== id);
            });
            this.sheets = this.sheets.filter(s => s.id !== id);
            this.editSheetId = '';
            this.settingsPage = 'sheets';
            this.saveNow(); this.toast('Sheet dihapus');
        },

        openFieldModal(sheetId, f) {
            const sh = this.sheets.find(s => s.id === sheetId);
            const lastSection = sh && sh.fields.length ? sh.fields[sh.fields.length - 1].section : '';
            this.openModal('field', f
                ? { sheetId, id: f.id, label: f.label, placeholder: f.placeholder || '', type: f.type, section: f.section || '', optionsText: (f.options || []).join(', '), scan: !!f.scan }
                : { sheetId, id: null, label: '', placeholder: '', type: 'text', section: lastSection || '', optionsText: '', scan: false });
        },
        saveFieldModal() {
            const d = this.modal.data;
            const sh = this.sheets.find(s => s.id === d.sheetId);
            if (!sh) return;
            if (!(d.label || '').trim()) return this.toast('Teks pertanyaan wajib diisi', 'error');
            const options = [...new Set(String(d.optionsText || '').split(/[,\n]/).map(s => s.trim()).filter(Boolean))];
            if (d.type === 'choice' && options.length < 2) return this.toast('Jenis Pilihan butuh minimal 2 opsi', 'error');
            const payload = {
                label: d.label.trim(), placeholder: (d.placeholder || '').trim(), type: d.type, section: (d.section || '').trim(),
                options: ['text', 'number', 'choice', 'mac'].includes(d.type) ? options : [],
                scan: ['text', 'mac'].includes(d.type) ? !!d.scan : false
            };
            if (d.id) {
                const f = sh.fields.find(x => x.id === d.id);
                if (f) Object.assign(f, payload);
                this.toast('Pertanyaan diperbarui');
            } else {
                sh.fields.push({ id: 'f_' + uid(), ...payload });
                this.toast('Pertanyaan ditambahkan');
            }
            this.saveNow(); this.closeModal();
        },
        async deleteField(sheetId, id) {
            const sh = this.sheets.find(s => s.id === sheetId);
            if (!sh) return;
            const f = sh.fields.find(x => x.id === id);
            if (!f) return;
            const ok = await this.ask('Hapus pertanyaan?', '"' + f.label + '" dihapus.', 'Hapus', true);
            if (!ok) return;
            sh.fields = sh.fields.filter(x => x.id !== id);
            this.saveNow(); this.closeModal(); this.toast('Pertanyaan dihapus');
        },
        moveField(sheetId, index, dir) {
            const sh = this.sheets.find(s => s.id === sheetId);
            if (!sh) return;
            const j = index + dir;
            if (j < 0 || j >= sh.fields.length) return;
            const [it] = sh.fields.splice(index, 1);
            sh.fields.splice(j, 0, it);
            this.saveNow();
        },

        csvCell(v) {
            let s = String(v == null ? '' : v);
            const formulaLike = /^\s*[=+\-@]/.test(s);
            const numericValue = /^\s*-?\d+([.,]\d+)?\s*$/.test(s);
            if (formulaLike && !numericValue) s = "'" + s;
            return '"' + s.replace(/"/g, '""') + '"';
        },
        download(name, mime, text) {
            const a = document.createElement('a');
            const url = URL.createObjectURL(new Blob([text], { type: mime }));
            a.href = url; a.download = name;
            document.body.appendChild(a); a.click(); a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 4000);
        },
        today() {
            const now = new Date();
            return now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0');
        },
        statusOf(s, u) { return this.isUnitDone(s, u) ? 'Selesai' : (this.drafts[this.key(s, u)] ? 'Draft' : 'Belum'); },
        valuesOf(s, u) {
            const k = this.key(s, u);
            return this.drafts[k] || (this.records[k] && this.records[k].values) || {};
        },
        exportSheetCsv(sheetId) {
            const sh = this.sheets.find(s => s.id === sheetId);
            if (!sh) return;
            const rows = [];
            this.regions.forEach(r => this.stores.filter(s => s.regionId === r.id).forEach(s => {
                (this.units[s.id] || []).filter(u => u.sheetId === sh.id).forEach(u => {
                    const rec = this.records[this.key(s.id, u.id)];
                    const vals = this.valuesOf(s.id, u.id);
                    rows.push([this.monthLabel, r.name, s.code, s.nama, s.alamat, u.name, this.statusOf(s.id, u.id), rec && rec.at ? new Date(rec.at).toLocaleString('id-ID') : '', ...sh.fields.map(f => vals[f.id] || '')]);
                });
            }));
            if (!rows.length) return this.toast('Belum ada unit untuk sheet ini', 'error');
            const head = ['Periode', 'Wilayah', 'Kode Toko', 'Toko', 'Alamat', 'Unit', 'Status', 'Terakhir disimpan', ...sh.fields.map(f => f.label)];
            const csv = '\ufeff' + [head, ...rows].map(r => r.map(c => this.csvCell(c)).join(',')).join('\r\n');
            this.download('alfamidi-' + sh.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-' + this.activeMonth + '.csv', 'text/csv;charset=utf-8;', csv);
            this.toast('CSV ' + sh.name + ' diunduh');
        },
        exportAllCsv() {
            const rows = [];
            this.regions.forEach(r => this.stores.filter(s => s.regionId === r.id).forEach(s => {
                (this.units[s.id] || []).forEach(u => {
                    const sh = this.sheetOf(u);
                    if (!sh) return;
                    const vals = this.valuesOf(s.id, u.id);
                    sh.fields.forEach(f => rows.push([this.monthLabel, r.name, s.code, s.nama, s.alamat, sh.name, u.name, this.statusOf(s.id, u.id), f.section, f.label, vals[f.id] || '']));
                });
            }));
            if (!rows.length) return this.toast('Belum ada data untuk diekspor', 'error');
            const head = ['Periode', 'Wilayah', 'Kode Toko', 'Toko', 'Alamat', 'Jenis pemeriksaan', 'Unit', 'Status', 'Bagian', 'Pertanyaan', 'Jawaban'];
            const csv = '\ufeff' + [head, ...rows].map(r => r.map(c => this.csvCell(c)).join(',')).join('\r\n');
            this.download('alfamidi-semua-data-' + this.activeMonth + '.csv', 'text/csv;charset=utf-8;', csv);
            this.toast('CSV semua data berhasil diunduh');
        },
        backupJson() {
            this.flush();
            this.download('alfamidi-backup-' + this.today() + '.json', 'application/json', JSON.stringify(this.snapshot(), null, 2));
            this.toast('Backup diunduh');
        },
        async restoreJson(ev) {
            const file = ev.target.files && ev.target.files[0];
            ev.target.value = '';
            if (!file) return;
            let st;
            try {
                const parsed = JSON.parse(await file.text());
                if (!parsed || parsed.v !== 2 || !Array.isArray(parsed.stores) || !Array.isArray(parsed.sheets)) throw new Error('format');
                st = sanitizeState(parsed);
            } catch (e) { return this.toast('File backup tidak valid', 'error'); }
            const ok = await this.ask('Pulihkan backup?', 'Data saat ini diganti dengan backup.', 'Pulihkan', true);
            if (!ok) return;
            this.applyState(st);
            this.activeToko = {}; this.activeUnit = {}; this.formData = {}; this.draftDirty = false;
            this.readerUnitId = 'all';
            this.saveNow();
            this.settingsPage = 'menu';
            this.go('dashboard');
            this.toast('Backup dipulihkan');
        },
        async resetProgress() {
            const ok = await this.ask('Reset progress?', 'Semua isian dan status selesai dihapus.', 'Reset', true);
            if (!ok) return;
            Object.keys(this.records).forEach(key => { if (key.startsWith(this.activeMonth + '|')) delete this.records[key]; });
            Object.keys(this.drafts).forEach(key => { if (key.startsWith(this.activeMonth + '|')) delete this.drafts[key]; });
            this.formData = {}; this.draftDirty = false; this.activeUnit = {};
            this.saveNow();
            this.toast('Progress direset');
        },
        async factoryReset() {
            const ok = await this.ask('Kembalikan ke bawaan?', 'Pengaturan awal dan PIN default akan diterapkan kembali.', 'Kembalikan', true);
            if (!ok) return;
            store.del('custom_pin_hash');
            store.del('pin_security');
            this.correctPinHash = DEFAULT_PIN_HASH;
            this.pinSecurity = { failures: 0, lockedUntil: 0 };
            this.applyState(sanitizeState(buildDefaultState()));
            this.activeToko = {}; this.activeUnit = {}; this.formData = {}; this.draftDirty = false;
            this.readerUnitId = 'all';
            this.filterRegion = 'all'; this.storeRegion = 'all'; this.search = ''; this.filterStatus = 'all';
            this.saveNow();
            this.settingsPage = 'menu';
            this.go('dashboard');
            this.toast('Dikembalikan ke pengaturan awal');
        }
    };
}
