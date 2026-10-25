"""Normalise heterogeneous evidence (SQL snapshots, JSON, TXT, logs, PDF, PNG) into flat Records."""
import os, re, json, sqlite3, csv
from dataclasses import dataclass, field
from ident import D, rd

EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"\+\d[\d \-]{7,17}\d")
HASH = re.compile(r"\b[0-9a-f]{64}\b")
UREF = re.compile(r"\buser_\d+\b")
PREFIX_CAT = [('account_', 'USER_PROFILE'), ('search_', 'SEARCH_INDEX_ENTRY'), ('support_', 'SUPPORT_MESSAGE'),
    ('object_', 'SUPPORT_ATTACHMENT'), ('analytics_', 'ANALYTICS_PROFILE'), ('telemetry_', 'PRODUCT_TELEMETRY'),
    ('export_', 'USER_EXPORT'), ('marketing_', 'MARKETING_PROFILE'), ('cache_', 'CACHE_ENTRY'),
    ('email_delivery_', 'EMAIL_DELIVERY_LOG'), ('audit_record_', 'SECURITY_AUDIT_LOG'),
    ('legal_hold_', 'LEGAL_HOLD_RECORD'), ('backup_', 'BACKUP_ARCHIVE'), ('data_flow_', 'DATA_FLOW'),
    ('tombstone_', 'ACCOUNT_TOMBSTONE')]
def category(rid):
    for p, c in PREFIX_CAT:
        if rid.startswith(p): return c
SYSTEM_OF = {'USER_PROFILE': 'account_service', 'SEARCH_INDEX_ENTRY': 'search_service', 'SUPPORT_MESSAGE': 'support_platform',
    'SUPPORT_ATTACHMENT': 'object_storage', 'ANALYTICS_PROFILE': 'analytics_platform', 'USER_EXPORT': 'export_service',
    'MARKETING_PROFILE': 'marketing_platform', 'CACHE_ENTRY': 'cache_service', 'EMAIL_DELIVERY_LOG': 'email_delivery_service',
    'SECURITY_AUDIT_LOG': 'security_service', 'LEGAL_HOLD_RECORD': 'legal_service', 'BACKUP_ARCHIVE': 'backup_service',
    'DATA_FLOW': 'integration_service', 'ACCOUNT_TOMBSTONE': 'identity_service'}

# Explicit record_type override map: evidence can declare the real category
# regardless of the resource_id prefix.
RECTYPE_CAT = {
    'USER_PROFILE': 'USER_PROFILE',
    'SECONDARY_IDENTIFIER': 'SECONDARY_IDENTIFIER',
    'SEARCH_INDEX_ENTRY': 'SEARCH_INDEX_ENTRY',
    'SUPPORT_MESSAGE': 'SUPPORT_MESSAGE',
    'SUPPORT_ATTACHMENT': 'SUPPORT_ATTACHMENT',
    'ANALYTICS_PROFILE': 'ANALYTICS_PROFILE',
    'MARKETING_PROFILE': 'MARKETING_PROFILE',
    'PRODUCT_TELEMETRY': 'PRODUCT_TELEMETRY',
    'USER_EXPORT': 'USER_EXPORT',
    'EMAIL_DELIVERY_LOG': 'EMAIL_DELIVERY_LOG',
    'SECURITY_AUDIT_LOG': 'SECURITY_AUDIT_LOG',
    'LEGAL_HOLD_RECORD': 'LEGAL_HOLD_RECORD',
    'BACKUP_ARCHIVE': 'BACKUP_ARCHIVE',
    'DATA_FLOW': 'DATA_FLOW',
    'ACCOUNT_TOMBSTONE': 'ACCOUNT_TOMBSTONE',
    'CACHE_ENTRY': 'CACHE_ENTRY',
}
# Also add these to SYSTEM_OF
SYSTEM_OF['SECONDARY_IDENTIFIER'] = 'support_platform'

@dataclass
class Rec:
    file_id: str; captured_at: str; resource_id: str; system: str = ''; state: str = 'PRESENT'
    emails: set = field(default_factory=set); phones: set = field(default_factory=set)
    hashes: set = field(default_factory=set); urefs: set = field(default_factory=set); names: set = field(default_factory=set)
    flags: dict = field(default_factory=dict); raw: object = None; where: str = ''
    explicit_cat: str = ''   # overrides prefix-based category when set
    file_captured_at: str = ''  # evidence file's captured_at (for scope filtering)

    @property
    def cat(self):
        if self.explicit_cat:
            return self.explicit_cat
        return category(self.resource_id)

def harvest(obj, rec):
    """Pull identifiers out of any nested structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and k in ('full_name','display_name','requester_name','name'): rec.names.add(v)
            harvest(v, rec)
    elif isinstance(obj, list):
        for v in obj: harvest(v, rec)
    elif isinstance(obj, str):
        rec.emails |= {e.lower() for e in EMAIL.findall(obj)}; rec.phones |= set(PHONE.findall(obj))
        rec.hashes |= set(HASH.findall(obj)); rec.urefs |= set(UREF.findall(obj))

def manifest(): return {r['file_id']: r for r in rd('evidence_files.csv')}

def load_sql(fid, path, cap):
    txt = open(path, encoding='utf-8').read()
    con = sqlite3.connect(':memory:'); con.executescript(txt); cur = con.cursor()
    out = []
    tabs = [r[0] for r in cur.execute("select name from sqlite_master where type='table'")]
    for t in tabs:
        cols = [r[1] for r in cur.execute(f'pragma table_info("{t}")')]
        for row in cur.execute(f'select * from "{t}"'):
            d = dict(zip(cols, row))
            if 'resource_id' not in d: continue
            if 'record_json' in d:
                try: payload = json.loads(d['record_json'])
                except Exception: payload = {}
                d2 = dict(d); d2.update(payload); d = d2
            rec = Rec(fid, cap, d['resource_id'], d.get('origin_system') or '', raw=d, where=t,
                      file_captured_at=cap)
            # Check for explicit record_type in the data
            rt = d.get('record_type') or d.get('data_category')
            if rt and rt in RECTYPE_CAT:
                rec.explicit_cat = RECTYPE_CAT[rt]
            harvest({k: v for k, v in d.items() if k != 'record_json'}, rec); out.append(rec)
    return out

def load_json(fid, path, cap):
    """Generic walk: every dict carrying a resource_id is an observation; ancestors give system/time context."""
    j = json.load(open(path, encoding='utf-8')); out = []
    top_ts = j.get('captured_at') or j.get('exported_at') or cap
    def walk(o, ctx):
        if isinstance(o, dict):
            c = dict(ctx)
            for k in ('data_store', 'service', 'origin_system', 'system'):
                if isinstance(o.get(k), str): c['system'] = o[k]
            if isinstance(o.get('collection'), str): c['collection'] = o['collection']
            if isinstance(o.get('captured_at'), str): c['ts'] = o['captured_at']
            if 'resource_id' in o and isinstance(o['resource_id'], str):
                ts = o.get('observed_at') or o.get('recorded_at') or c.get('ts') or top_ts
                rec = Rec(fid, ts, o['resource_id'], c.get('system', ''), raw=o,
                          where=c.get('collection', c.get('key', '')), file_captured_at=cap)
                # Pick up explicit record type from JSON fields
                rt = o.get('record_type') or o.get('data_category')
                if rt and rt in RECTYPE_CAT:
                    rec.explicit_cat = RECTYPE_CAT[rt]
                harvest(o, rec); out.append(rec); return
            for k, v in o.items():
                c2 = dict(c)
                if isinstance(v, (list, dict)) and k in ('account_service','analytics_platform','search_service','support_platform','export_service','backup_service','integration_service','security_service','cache_service','email_delivery_service','marketing_platform','identity_service','object_storage','legal_service'): c2['system'] = k
                c2['key'] = k
                walk(v, c2)
        elif isinstance(o, list):
            for v in o: walk(v, ctx)
    walk(j, {})
    return out

# ---------- log dialects: key=value, JSON-in-line, [bracket], pipe, syslog, record_lookup ----------
KV = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
TS = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s+(.*)$')
def parse_line(line):
    m = TS.match(line.strip())
    if not m: return None
    ts, rest = m.groups(); f = {}
    if rest.startswith('{'):
        try: f = {k: ('' if v is None else str(v)) for k, v in json.loads(rest).items()}
        except Exception: pass
    else:
        for k, a, b in KV.findall(rest): f[k] = a if a != '' or b == '' else b
        if 'event' not in f:
            m2 = re.search(r'\]\s+(\w+):\s', rest) or re.match(r'\S+ \| \w+ \| \w+ \| \S+ \| (\w+) \|', rest)
            if m2: f['event'] = m2.group(1)
        t = re.search(r'\b(tr-\d+|rb-[\d-]+)\b', rest)
        if t and 'trace_id' not in f: f['trace_id'] = t.group(1)
    f['_ts'] = ts; f['_raw'] = rest
    return f

def nz(v): return None if v in (None, '', 'null', 'None') else v

def load_log(fid, path, cap):
    """Parse any dialect; attach every identifier seen anywhere in a trace to the resources touched by that trace."""
    lines = [parse_line(l) for l in open(path, encoding='utf-8', errors='ignore')]
    lines = [l for l in lines if l]
    trace_ids = {}   # trace -> Rec-like holder of identifiers
    trace_cats = {}  # trace -> explicit_cat
    for l in lines:
        t = l.get('trace_id')
        src = l.get('source', '').lower()
        ev = l.get('event', '')
        rt = l.get('record_type') or l.get('data_category')
        if not rt:
            if 'contact_index' in src or 'contact_query' in ev:
                rt = 'SECONDARY_IDENTIFIER'
            elif l.get('email_opt_in') or 'marketing' in src or (ev == 'contact_lookup_completed' and (l.get('resource_id', '').startswith('analytics_') or 'analytics' in l.get('service', ''))):
                rt = 'MARKETING_PROFILE'
        if rt and t:
            trace_cats[t] = rt
        if not t: continue
        h = trace_ids.setdefault(t, Rec(fid, cap, ''))
        blob = ' '.join(str(v) for k, v in l.items() if k not in ('_raw', 'trace_id', 'resource_id'))
        harvest(blob, h)
    out = []
    for l in lines:
        rid = nz(l.get('resource_id')); ev = l.get('event', '')
        if not rid or category(rid) is None: continue
        if ev.endswith('_started') or ev in ('connection_acquired',): continue
        rec = Rec(fid, l['_ts'], rid, l.get('service') or l.get('system') or '', raw=l, where=ev,
                  file_captured_at=cap)
        t = l.get('trace_id')
        rt = l.get('record_type') or l.get('data_category')
        if not rt and t and t in trace_cats:
            rt = trace_cats[t]
        if not rt:
            src = l.get('source', '').lower()
            if 'contact_index' in src or 'contact_query' in ev:
                rt = 'SECONDARY_IDENTIFIER'
            elif l.get('email_opt_in') or 'marketing' in src or (ev == 'contact_lookup_completed' and rid.startswith('analytics_')):
                rt = 'MARKETING_PROFILE'
        if rt and rt in RECTYPE_CAT:
            rec.explicit_cat = RECTYPE_CAT[rt]
        h = trace_ids.get(t)
        blob = ' '.join(str(v) for k, v in l.items() if k not in ('_raw', 'trace_id', 'resource_id'))
        harvest(blob, rec)
        if h:
            rec.emails |= h.emails; rec.phones |= h.phones; rec.hashes |= h.hashes; rec.urefs |= h.urefs
        out.append(rec)
    return out

def load_txt(fid, path, cap):
    """Parse handover TXT files. The 4th pipe-field is the explicit record_type."""
    out = []
    for l in open(path, encoding='utf-8'):
        m = re.match(r'- (\S+) \| (\S+) \| (\S+) \| (\S+) \| (\S+) \| (.*)$', l.strip())
        if m:
            ts, sysid, rid, cat_, res, subj = m.groups()
            ecat = RECTYPE_CAT.get(cat_, '')
            rec = Rec(fid, ts, rid, sysid, raw={'record_type': cat_, 'result': res, 'subject': subj},
                      where='handover', explicit_cat=ecat, file_captured_at=cap)
            harvest(subj, rec); out.append(rec)
    return out

# ---------- PDF text extraction ----------
def _extract_pdf_text(path):
    """Extract text from a PDF using pypdf. Returns concatenated page text."""
    try:
        import pypdf
        reader = pypdf.PdfReader(path)
        parts = []
        for page in reader.pages:
            t = page.extract_text()
            if t:
                parts.append(t)
        return '\n'.join(parts)
    except Exception:
        return ''

# Regex to find resource_id-like strings in text
_RID_RE = re.compile(r'\b((?:account|search|support|object|analytics|telemetry|export|marketing|cache|'
                     r'email_delivery|audit_record|legal_hold|backup|data_flow|tombstone)_\w+)\b')

def load_pdf(fid, path, cap):
    """Extract records from PDF documents by scanning extracted text for resource_ids and identifiers."""
    text = _extract_pdf_text(path)
    if not text:
        return []
    out = []
    is_attachment = 'attachment' in path.lower() or 'attachment' in text.lower() or 'address correction' in text.lower()
    # Find all resource_ids mentioned in the text
    rids = list(dict.fromkeys(_RID_RE.findall(text)))  # deduplicate preserving order
    if not rids:
        return []
    # Create one Rec per resource_id found
    for rid in rids:
        if category(rid) is None:
            continue
        rec = Rec(fid, cap, rid, '', raw={'_pdf_text': text[:500], '_source': path},
                  where='pdf', file_captured_at=cap)
        if is_attachment and rid.startswith(('support_', 'object_')):
            rec.explicit_cat = 'SUPPORT_ATTACHMENT'
        harvest(text, rec)
        out.append(rec)
    return out

_OCR_ENGINE = None
_PNG_CACHE = {}
_CACHE_FILE = os.path.join(os.path.dirname(__file__), 'ocr_cache.json')
if os.path.exists(_CACHE_FILE):
    try:
        _PNG_CACHE = json.load(open(_CACHE_FILE, encoding='utf-8'))
    except Exception:
        pass

def _get_ocr_engine():
    global _OCR_ENGINE
    if _OCR_ENGINE is None:
        try:
            from rapidocr_onnxruntime import RapidOCR
            _OCR_ENGINE = RapidOCR()
        except Exception:
            pass
    return _OCR_ENGINE

def load_png(fid, path, cap):
    """Extract records from PNG screenshots using RapidOCR with caching."""
    # Check relative path in cache
    rel = os.path.relpath(path, D).replace('\\', '/')
    if rel in _PNG_CACHE:
        text = _PNG_CACHE[rel]
    elif path in _PNG_CACHE:
        text = _PNG_CACHE[path]
    else:
        try:
            eng = _get_ocr_engine()
            if eng is None:
                return []
            result, _ = eng(path)
            text = '\n'.join([line[1] for line in result]) if result else ''
            _PNG_CACHE[rel] = text
        except Exception:
            return []
    if not text:
        return []
    rids = list(dict.fromkeys(_RID_RE.findall(text)))
    lines = text.splitlines()
    out = []
    for rid in rids:
        if category(rid) is None:
            continue
        rec = Rec(fid, cap, rid, '', raw={'_png_text': text[:500]},
                  where='png', file_captured_at=cap)
        # Find lines matching rid and harvest their local neighborhood
        loc = []
        for i, l in enumerate(lines):
            if rid in l:
                loc.extend(lines[max(0, i - 4):min(len(lines), i + 5)])
        block = '\n'.join(loc) if loc else text
        harvest(block, rec)
        out.append(rec)
    return out

def load_all():
    man = manifest(); recs = []
    for fid, m in man.items():
        p = os.path.join(D, m['file_path']); cap = m['captured_at']
        try:
            if p.endswith('.sql'): r = load_sql(fid, p, cap)
            elif p.endswith('.json'): r = load_json(fid, p, cap)
            elif p.endswith('.log'): r = load_log(fid, p, cap)
            elif p.endswith('.txt'): r = load_txt(fid, p, cap)
            elif p.endswith('.pdf'): r = load_pdf(fid, p, cap)
            elif p.endswith('.png'): r = load_png(fid, p, cap)
            else: r = []
        except Exception as e:
            print('LOADERR', fid, p, e); r = []
        recs += r
    return recs
