# -*- coding: utf-8 -*-
"""Запускает server.py, прогоняет E2E-тесты, пишет результат в test_results.log.

ВАЖНО: тест изменяет БД (пароль admin, список пользователей). Чтобы НЕ портить
реальные данные, перед запуском db.json копируется в .bak-test, а после
завершения (в finally) оригинал восстанавливается.
"""
import http.cookiejar
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
B = 'http://127.0.0.1:8090'
DB = os.path.join(ROOT, 'data', 'db.json')
DB_BAK = os.path.join(ROOT, 'data', 'db.json.bak-test')
LOG = os.path.join(ROOT, 'test_results.log')

lines = []

def log(msg='', *args):
    lines.append(str(msg) + (' ' + ' '.join(str(a) for a in args) if args else ''))
    sys.stdout.write(str(msg) + '\n')

def flush():
    with io.open(LOG, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

env = dict(os.environ)
env['PHONEBOOK_DEBUG'] = '1'
env['PORT'] = '8090'

# --- Backup/restore: don't touch real data ---
if os.path.exists(DB):
    shutil.copy2(DB, DB_BAK)
    log('data backup saved ->', os.path.basename(DB_BAK))

def restore_db():
    """Restore the original db.json from the test backup."""
    if os.path.exists(DB_BAK):
        shutil.copy2(DB_BAK, DB)
        try:
            os.remove(DB_BAK)
        except OSError:
            pass
        log('data restored from backup')

proc = subprocess.Popen([sys.executable, 'server.py'], cwd=ROOT, env=env,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, encoding='utf-8', errors='replace')
try:
    started = False
    for _ in range(40):
        time.sleep(0.5)
        try:
            urllib.request.urlopen(B + '/api/verify', timeout=2)
            started = True
            break
        except urllib.error.HTTPError:
            started = True
            break
        except Exception:
            pass
    if not started:
        log('SERVER DID NOT START')
        flush()
        sys.exit(1)
    log('server started, pid', proc.pid)

    # 1) migration check (verify уже вызвал _load_db)
    d = json.load(io.open(DB, encoding='utf-8'))
    log('users:', [(u['username'], u['role'], u['pass'][:35]) for u in d['users']])
    c = d.get('contacts')
    log('contacts type:', type(c).__name__)
    log('history len:', len(d.get('history', [])))
    assert all(re.match(r'^(pbkdf2|scrypt)', u['pass']) for u in d['users']), 'passwords not hashed!'
    assert isinstance(c, list) and len(c) == 252, f'contacts wrong: {type(c).__name__}'
    log('MIGRATION OK')

    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def post(path, body=None):
        req = urllib.request.Request(B + path,
                                     data=json.dumps(body).encode() if body is not None else b'{}',
                                     headers={'Content-Type': 'application/json'}, method='POST')
        try:
            return op.open(req, timeout=5)
        except urllib.error.HTTPError as e:
            return e

    def get(path):
        try:
            return op.open(B + path, timeout=5)
        except urllib.error.HTTPError as e:
            return e

    r = post('/api/contacts', {'contacts': [], 'history': []})
    log('anon contacts:', r.code)
    assert r.code == 403

    r = post('/api/login', {'username': 'admin', 'password': 'wrong'})
    log('bad login:', r.code)
    assert r.code == 401

    r = post('/api/login', {'username': 'admin', 'password': 'admin123'})
    log('admin login:', r.code)
    assert r.code == 200

    v = json.load(get('/api/verify'))
    log('verify:', v)
    assert v['authenticated'] and v['role'] == 'admin'

    h = get('/').headers
    log('CSP:', 'Content-Security-Policy' in h, '| XFO:', h.get('X-Frame-Options'),
        '| nosniff:', h.get('X-Content-Type-Options'))
    assert 'Content-Security-Policy' in h and h.get('X-Frame-Options') == 'DENY'

    data = json.load(get('/api/data'))
    log('users in data:', data['users'])
    assert all('pass' not in u for u in data['users'])
    assert len(data['contacts']) == 252

    payload = {'contacts': data['contacts'],
               'history': [{'user': 'x"><img src=x onerror=alert(1)>',
                            'action': '<script>alert(1)</script>', 'time': 't'}]}
    r = post('/api/contacts', payload)
    log('xss data save:', r.code)
    assert r.code == 200

    r = post('/api/login', {'username': 'secretar', 'password': '12345'})
    log('editor login:', r.code)
    assert r.code == 200
    r = post('/api/users', [{'username': 'admin', 'role': 'admin'}])
    log('editor users POST:', r.code)
    assert r.code == 403
    r = post('/api/contacts', payload)
    log('editor contacts POST:', r.code)
    assert r.code == 200

    r = post('/api/login', {'username': 'admin', 'password': 'admin123'})
    log('admin relogin:', r.code)
    assert r.code == 200
    r = post('/api/users', [{'username': 'admin', 'role': 'editor'}])
    log('self-demote:', r.code)
    assert r.code == 400
    r = post('/api/users', [{'username': 'admin', 'role': 'admin', 'pass': 'newpass123'},
                            {'username': 'nobody', 'role': 'viewer', 'pass': 'abcd'}])
    log('add users:', r.code)
    assert r.code == 200
    r = post('/api/users', [{'username': 'admin', 'role': 'admin', 'pass': 'x'},
                            {'username': 'nobody', 'role': 'viewer', 'pass': 'abcd'}])
    log('short pass rejected:', r.code)
    assert r.code == 400
    r = post('/api/users', [{'username': 'nobody', 'role': 'viewer', 'pass': 'abcd'}])
    log('no-admin rejected:', r.code)
    assert r.code == 400
    r = post('/api/users', [{'username': 'admin', 'role': 'admin'},
                            {'username': 'admin', 'role': 'admin'}])
    log('dup rejected:', r.code)
    assert r.code == 400
    r = post('/api/users', [{'username': 'bad name!', 'role': 'admin', 'pass': 'abcd'}])
    log('bad username rejected:', r.code)
    assert r.code == 400

    for i in range(6):
        rr = post('/api/login', {'username': 'rateuser', 'password': 'nope'})
        log('fail', i + 1, rr.code)
    assert rr.code == 429

    r = post('/api/login', {'username': 'admin', 'password': 'admin123'})
    log('old pass after change:', r.code)
    assert r.code == 401
    r = post('/api/login', {'username': 'admin', 'password': 'newpass123'})
    log('new pass:', r.code)
    assert r.code == 200

    r = post('/api/logout')
    v = json.load(get('/api/verify'))
    log('after logout:', v)
    assert not v['authenticated']

    log('ALL TESTS PASSED')
    # --- Restore real data: test modified db.json (admin password, users) ---
    restore_db()
    # --- After restore, the running server's session is stale, but we kill it next.
finally:
    # Убиваем всё дерево процессов (PyManager-shim порождает дочерний
    # pythoncore-процесс, terminate() только shim -> orphan держал порт)
    try:
        subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                       capture_output=True, timeout=10)
    except Exception:
        proc.kill()
    try:
        out = proc.communicate(timeout=5)
    except Exception:
        out = ('', '')
    # Финальное восстановление данных (гарантия даже при сбое теста)
    try:
        restore_db()
    except Exception as e:
        log('RESTORE FAILED:', e)
    if out and out[0]:
        log('--- server stdout (last 2000 chars) ---')
        log(out[0][-2000:])
    flush()
