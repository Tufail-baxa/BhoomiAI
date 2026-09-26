import json, os, re, secrets, sqlite3, hashlib, hmac, base64, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / 'bhoomiai.db'

HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5500))

SESSION_TTL = 8 * 60 * 60
OTP_TTL = 5 * 60

def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310000)
    return base64.b64encode(salt).decode() + '$' + base64.b64encode(digest).decode()


def verify_password(password, stored):
    try:
        salt_b64, digest_b64 = stored.split('$', 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def init_db():
    c = db()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      full_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('citizen','verifier','admin')),
      active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      csrf TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS otp_challenges (
      challenge TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      otp_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      used INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS records (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      owner TEXT,
      survey TEXT,
      area TEXT,
      village TEXT,
      district TEXT,
      confidence INTEGER,
      status TEXT,
      issues_json TEXT,
      raw_text TEXT,
      language TEXT,
      doc_type TEXT,
      created_at TEXT,
      updated_at TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      record_id TEXT,
      created_at TEXT NOT NULL
    );
    ''')
    users = [
      ('citizen1','Demo Citizen','Citizen@123','citizen'),
      ('verifier1','Demo Verifier','Verify@123','verifier'),
      ('admin1','System Administrator','Admin@123','admin')
    ]
    for u in users:
        if not c.execute('SELECT 1 FROM users WHERE username=?',(u[0],)).fetchone():
            c.execute('INSERT INTO users(username,full_name,password_hash,role) VALUES(?,?,?,?)',(u[0],u[1],hash_password(u[2]),u[3]))
    c.commit(); c.close()


def now(): return int(time.time())


def clean_user(row):
    return {'id': row['id'], 'username': row['username'], 'fullName': row['full_name'], 'role': row['role']}


def parse_cookie(header):
    out={}
    for part in (header or '').split(';'):
        if '=' in part:
            k,v=part.strip().split('=',1); out[k]=v
    return out


def get_session(handler):
    token=parse_cookie(handler.headers.get('Cookie')).get('bhoomi_session')
    if not token: return None
    c=db(); row=c.execute('''SELECT s.token,s.csrf,s.expires_at,u.id,u.username,u.full_name,u.role,u.active
                             FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?''',(token,)).fetchone()
    if not row or not row['active'] or row['expires_at'] < now():
        if token: c.execute('DELETE FROM sessions WHERE token=?',(token,)); c.commit()
        c.close(); return None
    c.close(); return row


def json_body(handler):
    n=int(handler.headers.get('Content-Length','0'))
    if n>2_000_000: raise ValueError('Request too large')
    raw=handler.rfile.read(n)
    return json.loads(raw.decode() or '{}')


def send_json(handler, code, data, extra_headers=None):
    raw=json.dumps(data, ensure_ascii=False).encode()
    handler.send_response(code)
    handler.send_header('Content-Type','application/json; charset=utf-8')
    handler.send_header('Cache-Control','no-store')
    if extra_headers:
        for k,v in extra_headers.items(): handler.send_header(k,v)
    handler.end_headers(); handler.wfile.write(raw)


def cookie_header(token, max_age=SESSION_TTL):
    # Secure should be added when deployed behind HTTPS.
    return f'bhoomi_session={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age={max_age}'


def require_auth(handler, roles=None, csrf=False):
    s=get_session(handler)
    if not s:
        send_json(handler,401,{'error':'Authentication required'}); return None
    if roles and s['role'] not in roles:
        send_json(handler,403,{'error':'You are not authorized for this action'}); return None
    if csrf and handler.headers.get('X-CSRF-Token') != s['csrf']:
        send_json(handler,403,{'error':'Invalid CSRF token'}); return None
    return s


def audit(user_id, action, record_id=None):
    c=db(); c.execute('INSERT INTO audit_log(user_id,action,record_id,created_at) VALUES(?,?,?,datetime(\'now\'))',(user_id,action,record_id)); c.commit(); c.close()


def row_record(r):
    d=dict(r); d['issues']=json.loads(d.pop('issues_json') or '[]'); return d

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print('[server]', fmt % args)

    def end_headers(self):
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','same-origin')
        super().end_headers()

    def do_GET(self):
        p=urlparse(self.path).path
        if p.startswith('/api/'):
            return self.api_get(p)
        return self.static(p)

    def do_POST(self):
        p=urlparse(self.path).path
        if p.startswith('/api/'):
            return self.api_post(p)
        self.send_error(405)

    def static(self,p):
        if p=='/': p='/index.html'
        rel=p.lstrip('/')
        if '..' in Path(rel).parts: self.send_error(400); return
        f=(ROOT/rel)
        if not f.is_file(): self.send_error(404); return
        import mimetypes
        typ=mimetypes.guess_type(str(f))[0] or 'application/octet-stream'
        data=f.read_bytes(); self.send_response(200); self.send_header('Content-Type',typ); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)

    def api_get(self,p):
        if p=='/api/me':
            s=get_session(self)
            if not s: return send_json(self,401,{'authenticated':False})
            return send_json(self,200,{'authenticated':True,'user':{'id':s['id'],'username':s['username'],'fullName':s['full_name'],'role':s['role']},'csrf':s['csrf']})
        if p=='/api/records':
            s=require_auth(self); 
            if not s:return
            c=db()
            if s['role']=='citizen': rows=c.execute('SELECT * FROM records WHERE user_id=? ORDER BY created_at DESC',(s['id'],)).fetchall()
            else: rows=c.execute('SELECT * FROM records ORDER BY created_at DESC').fetchall()
            c.close(); return send_json(self,200,[row_record(r) for r in rows])
        if p=='/api/audit':
            s=require_auth(self,['admin']);
            if not s:return
            c=db(); rows=c.execute('SELECT a.*,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 100').fetchall(); c.close()
            return send_json(self,200,[dict(r) for r in rows])
        self.send_error(404)

    def api_post(self,p):
        try: body=json_body(self)
        except Exception as e: return send_json(self,400,{'error':str(e)})
        if p=='/api/login': return self.login(body)
        if p=='/api/verify-otp': return self.verify_otp(body)
        if p=='/api/logout':
            s=require_auth(self,csrf=True)
            if not s:return
            c=db(); c.execute('DELETE FROM sessions WHERE token=?',(s['token'],)); c.commit(); c.close()
            return send_json(self,200,{'ok':True}, {'Set-Cookie':cookie_header('',0)})
        if p=='/api/records': return self.create_record(body)
        m=re.match(r'^/api/records/([^/]+)/(verify|issue)$',p)
        if m: return self.update_record(m.group(1),m.group(2))
        self.send_error(404)

    def login(self,b):
        username=str(b.get('username','')).strip(); password=str(b.get('password',''))
        if not username or not password: return send_json(self,400,{'error':'Username and password are required'})
        c=db(); u=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        if not u or not verify_password(password,u['password_hash']):
            c.close(); return send_json(self,401,{'error':'Invalid username or password'})
        if u['role'] in ('verifier','admin'):
            challenge=secrets.token_urlsafe(24); otp=f'{secrets.randbelow(1_000_000):06d}'; oh=hashlib.sha256(otp.encode()).hexdigest()
            c.execute('INSERT INTO otp_challenges(challenge,user_id,otp_hash,expires_at) VALUES(?,?,?,?)',(challenge,u['id'],oh,now()+OTP_TTL)); c.commit(); c.close()
            print(f'\n[BhoomiAI DEMO OTP] username={username} OTP={otp} valid_for=5_minutes\n')
            return send_json(self,200,{'otpRequired':True,'challenge':challenge,'message':'OTP generated. In this local demo, check the server terminal for the OTP.'})
        token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(24)
        c.execute('INSERT INTO sessions(token,user_id,expires_at,csrf) VALUES(?,?,?,?)',(token,u['id'],now()+SESSION_TTL,csrf)); c.commit(); c.close(); audit(u['id'],'LOGIN')
        return send_json(self,200,{'authenticated':True,'user':clean_user(u),'csrf':csrf},{'Set-Cookie':cookie_header(token)})

    def verify_otp(self,b):
        challenge=str(b.get('challenge','')); otp=str(b.get('otp','')).strip()
        if not challenge or not re.fullmatch(r'\d{6}',otp): return send_json(self,400,{'error':'Enter the 6-digit OTP'})
        c=db(); row=c.execute('SELECT * FROM otp_challenges WHERE challenge=?',(challenge,)).fetchone()
        if not row or row['used'] or row['expires_at']<now() or row['attempts']>=5:
            c.close(); return send_json(self,401,{'error':'OTP is invalid or expired'})
        expected=hashlib.sha256(otp.encode()).hexdigest()
        if not hmac.compare_digest(expected,row['otp_hash']):
            c.execute('UPDATE otp_challenges SET attempts=attempts+1 WHERE challenge=?',(challenge,)); c.commit(); c.close(); return send_json(self,401,{'error':'Invalid OTP'})
        c.execute('UPDATE otp_challenges SET used=1 WHERE challenge=?',(challenge,)); u=c.execute('SELECT * FROM users WHERE id=?',(row['user_id'],)).fetchone(); token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(24); c.execute('INSERT INTO sessions(token,user_id,expires_at,csrf) VALUES(?,?,?,?)',(token,u['id'],now()+SESSION_TTL,csrf)); c.commit(); c.close(); audit(u['id'],'LOGIN_OTP')
        return send_json(self,200,{'authenticated':True,'user':clean_user(u),'csrf':csrf},{'Set-Cookie':cookie_header(token)})

    def create_record(self,b):
        s=require_auth(self,['citizen','verifier','admin'],csrf=True)
        if not s:return
        required=['id','name']
        if any(not b.get(k) for k in required): return send_json(self,400,{'error':'Record id and document name are required'})
        # Citizen records belong to the authenticated citizen; officials can create records only for demo workflow.
        rid=str(b['id'])
        c=db(); existing=c.execute('SELECT 1 FROM records WHERE id=?',(rid,)).fetchone()
        if existing: c.close(); return send_json(self,409,{'error':'Record already exists'})
        c.execute('INSERT INTO records(id,user_id,name,owner,survey,area,village,district,confidence,status,issues_json,raw_text,language,doc_type,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime(\'now\'),datetime(\'now\'))',(
            rid,s['id'],str(b.get('name','')),str(b.get('owner','')),str(b.get('survey','')),str(b.get('area','')),str(b.get('village','')),str(b.get('district','')),int(b.get('confidence') or 0),str(b.get('status') or 'Pending'),json.dumps(b.get('issues') or []),str(b.get('rawText','')),str(b.get('language','eng')),str(b.get('docType','Land Record / 7-12'))))
        c.commit(); c.close(); audit(s['id'],'CREATE_RECORD',rid)
        return send_json(self,201,{'ok':True,'id':rid})

    def update_record(self,rid,action):
        s=require_auth(self,['verifier','admin'],csrf=True)
        if not s:return
        c=db(); r=c.execute('SELECT * FROM records WHERE id=?',(rid,)).fetchone()
        if not r: c.close(); return send_json(self,404,{'error':'Record not found'})
        status='Verified' if action=='verify' else 'Issue'; issues=[] if action=='verify' else ['Verifier marked this record for correction']
        c.execute('UPDATE records SET status=?,issues_json=?,updated_at=datetime(\'now\') WHERE id=?',(status,json.dumps(issues),rid)); c.commit(); c.close(); audit(s['id'],action.upper()+'_RECORD',rid)
        return send_json(self,200,{'ok':True})

if __name__=='__main__':
    init_db()
    print(f'BhoomiAI secure demo running at http://{HOST}:{PORT}')
    print('Demo accounts: citizen1/Citizen@123 | verifier1/Verify@123 + OTP | admin1/Admin@123 + OTP')
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
