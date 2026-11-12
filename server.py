# -*- coding: utf-8 -*-
"""
SA Narva Haigla — Телефонный справочник (Flask API)

Безопасность:
- Пароли хранятся только в виде PBKDF2-хэшей (werkzeug.security)
- Аутентификация на сервере через сессию (HttpOnly cookie)
- Все операции записи требуют роль editor/admin
- Валидация входящих данных, атомарная запись, блокировка,
  ограничение частоты логина, заголовки безопасности
- Автоматическая миграция старого db.json (плоский пар -> хэш,
  вложенный contacts -> плоский список)
"""
import json
import os
import re
import secrets
import socket
import tempfile
import threading
import time
import webbrowser

from flask import Flask, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__, static_folder='.')
app.config.update(
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10 MB — защита от перегрузки
    SESSION_COOKIE_HTTPONLY=True,          # cookie недоступен из JS (XSS)
    SESSION_COOKIE_SAMESITE='Lax',         # защита от CSRF
    SESSION_COOKIE_SECURE=os.environ.get('PHONEBOOK_COOKIE_SECURE', '') == '1',  # True только если явно задано
)

# Секретный ключ сессии: из переменной окружения, иначе генерируется
app.secret_key = os.environ.get('PHONEBOOK_SECRET_KEY') or secrets.token_hex(32)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
DATA_FILE = os.path.join(DATA_DIR, 'db.json')
DATA_LOCK = threading.RLock()

FIELD_MAX_LEN = 500
CONTACT_STR_FIELDS = ('name', 'role', 'short', 'phone', 'cabinet', 'department')

# Ограничение частоты логина: 5 неудачных попыток -> блокировка 60 секунд
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 60
_login_attempts = {}
_login_lock = threading.Lock()


def _default_data():
    return {
        'users': [{'username': 'admin', 'role': 'admin',
                   'pass': generate_password_hash('admin123')}],
        'contacts': [],
        'history': [],
    }


def _migrate_users(users):
    """Плоские пароли -> хэши; удаление неизвестных полей."""
    migrated = []
    for u in users or []:
        if not isinstance(u, dict):
            continue
        username = str(u.get('username', '')).strip()
        if not username:
            continue
        role = u.get('role') if u.get('role') in ('admin', 'editor', 'viewer') else 'viewer'
        raw = u.get('pass', '')
        if isinstance(raw, str) and re.match(r'^(pbkdf2|scrypt|md5|sha1|sha512)', raw):
            pass_hash = raw
        else:
            pass_hash = generate_password_hash(str(raw))
        migrated.append({'username': username, 'role': role, 'pass': pass_hash})
    if not migrated:
        return _default_data()['users']
    if not any(u['role'] == 'admin' for u in migrated):
        for u in migrated:
            if u['username'] == 'admin':
                u['role'] = 'admin'
                break
        else:
            migrated[0]['role'] = 'admin'
    return migrated


def _migrate_contacts(raw):
    """Исправление вложенной структуры {'contacts': [...]} и валидация списка."""
    items = raw
    if isinstance(items, dict):
        items = items.get('contacts')
    if not isinstance(items, list):
        return []
    contacts = []
    for i, c in enumerate(items):
        if not isinstance(c, dict):
            continue
        contact = {'id': i + 1, 'name': '', 'role': '', 'short': '',
                   'phone': '', 'cabinet': '', 'department': ''}
        try:
            contact['id'] = int(c.get('id'))
        except (TypeError, ValueError):
            contact['id'] = i + 1
        for key in CONTACT_STR_FIELDS:
            val = c.get(key, '')
            if not isinstance(val, str):
                val = '' if val is None else str(val)
            contact[key] = val[:FIELD_MAX_LEN]
        contacts.append(contact)
    return contacts


def _sanitize_contact(c, fallback_id):
    """Валидация одного контакта из POST. Возвращает чистый dict или None."""
    if not isinstance(c, dict):
        return None
    try:
        cid = int(c.get('id'))
        if cid <= 0:
            cid = fallback_id
    except (TypeError, ValueError):
        cid = fallback_id
    out = {'id': cid}
    for key in CONTACT_STR_FIELDS:
        val = c.get(key, '')
        if not isinstance(val, str):
            val = '' if val is None else str(val)
        out[key] = val[:FIELD_MAX_LEN]
    return out


def _sanitize_history(raw, limit=200):
    if not isinstance(raw, list):
        return []
    entries = []
    for h in raw:
        if not isinstance(h, dict):
            continue
        action = str(h.get('action', ''))[:1000]
        if not action:
            continue
        entries.append({
            'user': str(h.get('user', ''))[:100],
            'action': action,
            'time': str(h.get('time', ''))[:60],
        })
    return entries[-limit:]


def _public_user(u):
    """Пользователь без пароля/хэша — то, что может видеть клиент."""
    return {'username': u['username'], 'role': u['role']}


def _is_login_blocked(username):
    now = time.time()
    with _login_lock:
        entries = [t for t in _login_attempts.get(username, []) if now - t < LOGIN_WINDOW]
        _login_attempts[username] = entries
        return len(entries) >= LOGIN_MAX_ATTEMPTS


def _record_login_failure(username):
    now = time.time()
    with _login_lock:
        entries = [t for t in _login_attempts.get(username, []) if now - t < LOGIN_WINDOW]
        entries.append(now)
        _login_attempts[username] = entries


def _clear_login_failures(username):
    with _login_lock:
        _login_attempts.pop(username, None)

def _load_db():
    """Чтение и миграция БД (вызывать под DATA_LOCK)."""
    if not os.path.exists(DATA_FILE):
        data = _default_data()
        try:
            _save_db(data)
        except OSError:
            pass
        return data
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError):
        try:
            os.replace(DATA_FILE, DATA_FILE + '.corrupt')
        except OSError:
            pass
        return _default_data()

    if not isinstance(raw, dict):
        raw = {}
    raw_contacts = raw.get('contacts')
    if isinstance(raw_contacts, dict):
        # Старая битая структура: contacts и history были вложены внутрь
        contacts = raw_contacts.get('contacts')
        history = raw.get('history', raw_contacts.get('history'))
    else:
        contacts = raw_contacts
        history = raw.get('history')
    data = {
        'users': _migrate_users(raw.get('users')),
        'contacts': _migrate_contacts(contacts),
        'history': _sanitize_history(history),
    }

    # Если данные были в легаси-формате — сразу сохраняем смигрированные
    raw_users = raw.get('users')
    plain_pw = isinstance(raw_users, list) and any(
        not (isinstance(u, dict) and isinstance(u.get('pass'), str)
             and re.match(r'^(pbkdf2|scrypt|md5|sha1|sha512)', u.get('pass', '')))
        for u in raw_users)
    if isinstance(raw_contacts, dict) or plain_pw:
        try:
            _save_db(data)
        except OSError:
            pass
    return data


def _save_db(data):
    """Атомарная запись: временный файл -> os.replace (вызывать под DATA_LOCK)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=DATA_DIR, prefix='db.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, DATA_FILE)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _require_role(*roles):
    user = session.get('user')
    if not user or user.get('role') not in roles:
        return None
    return user


@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/fonts/<path:filename>')
def font_file(filename):
    """Локальные шрифты (Arial с кириллицей) для корректного PDF-экспорта."""
    resp = send_from_directory('fonts', filename)
    resp.headers.setdefault('Cache-Control', 'public, max-age=604800')
    return resp


@app.route('/vendor/<path:filename>')
def vendor_file(filename):
    """Локальные библиотеки (Tailwind, XLSX, jsPDF, Lucide и др.) для работы офлайн."""
    return send_from_directory('vendor', filename)


@app.route('/api/login', methods=['POST'])
def login():
    body = request.get_json(silent=True) or {}
    username = str(body.get('username', '')).strip()[:100]
    password = str(body.get('password', ''))[:200]
    if not username or not password:
        return jsonify({'error': 'Введите логин и пароль'}), 400
    if _is_login_blocked(username):
        return jsonify({'error': 'Слишком много попыток. Попробуйте через минуту.'}), 429

    with DATA_LOCK:
        data = _load_db()
        user = next((u for u in data['users'] if u['username'] == username), None)
        if user is None or not check_password_hash(user['pass'], password):
            _record_login_failure(username)
            return jsonify({'error': 'Vale kasutajanimi või parool / Неверный логин или пароль'}), 401

    _clear_login_failures(username)
    session['user'] = {'username': user['username'], 'role': user['role']}
    return jsonify({'ok': True, 'username': user['username'], 'role': user['role']})


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/verify', methods=['GET'])
def verify():
    user = session.get('user')
    if not user:
        return jsonify({'authenticated': False})
    with DATA_LOCK:
        data = _load_db()
        db_user = next((u for u in data['users'] if u['username'] == user['username']), None)
    if db_user and db_user['role'] == user['role']:
        return jsonify({'authenticated': True, 'username': user['username'], 'role': user['role']})
    session.clear()
    return jsonify({'authenticated': False})


@app.route('/api/data', methods=['GET'])
def get_data():
    with DATA_LOCK:
        data = _load_db()
    return jsonify({
        'contacts': data['contacts'],
        'history': data['history'],
        'users': [_public_user(u) for u in data['users']],  # без паролей!
    })

@app.route('/api/contacts', methods=['POST'])
def update_contacts():
    user = _require_role('editor', 'admin')
    if not user:
        return jsonify({'error': 'Недостаточно прав (требуется роль редактор)'}), 403

    body = request.get_json(silent=True) or {}
    raw_contacts = body.get('contacts')
    if not isinstance(raw_contacts, list) or len(raw_contacts) > 10000:
        return jsonify({'error': 'Неверный формат контактов'}), 400

    contacts = []
    seen_ids = set()
    next_id = 1
    for c in raw_contacts:
        sc = _sanitize_contact(c, len(contacts) + 1)
        if sc is None:
            continue
        if sc['id'] in seen_ids:  # дубликаты ID — перегенерируем
            next_id = max(next_id, max(seen_ids) + 1) if seen_ids else next_id
            sc['id'] = next_id
            next_id += 1
        seen_ids.add(sc['id'])
        if sc['id'] >= next_id:
            next_id = sc['id'] + 1
        contacts.append(sc)

    history = _sanitize_history(body.get('history'))

    with DATA_LOCK:
        data = _load_db()
        data['contacts'] = contacts
        if history:
            data['history'] = history
        _save_db(data)
    return jsonify({'status': 'ok', 'count': len(contacts)})


@app.route('/api/users', methods=['POST'])
def update_users():
    if not _require_role('admin'):
        return jsonify({'error': 'Доступно только администратору'}), 403

    raw_users = request.get_json(silent=True)
    if not isinstance(raw_users, list) or not (1 <= len(raw_users) <= 200):
        return jsonify({'error': 'Неверный формат списка пользователей'}), 400

    with DATA_LOCK:
        data = _load_db()
        old = {u['username']: u for u in data['users']}

    users = []
    seen = set()
    for u in raw_users:
        if not isinstance(u, dict):
            continue
        username = str(u.get('username', '')).strip()[:100]
        if not re.fullmatch(r'[A-Za-z0-9_.-]{2,50}', username):
            return jsonify({'error': f'Недопустимое имя пользователя: {username[:50]}'}), 400
        if username in seen:
            return jsonify({'error': f'Повторяющийся пользователь: {username}'}), 400
        role = u.get('role') if u.get('role') in ('admin', 'editor', 'viewer') else 'viewer'
        password = u.get('pass')
        existing = old.get(username)
        if existing and not password:
            users.append({'username': username, 'role': role, 'pass': existing['pass']})
        else:
            if not isinstance(password, str) or not (4 <= len(password) <= 200):
                return jsonify({'error': f'Пароль для {username}: 4-200 символов'}), 400
            users.append({'username': username, 'role': role, 'pass': generate_password_hash(password)})
        seen.add(username)

    if not users:
        return jsonify({'error': 'Список пользователей пуст'}), 400
    if not any(u['role'] == 'admin' for u in users):
        return jsonify({'error': 'Нужен хотя бы один администратор'}), 400
    me = session['user']['username']
    me_new = next((u for u in users if u['username'] == me), None)
    if me_new is None or me_new['role'] != 'admin':
        return jsonify({'error': 'Нельзя удалить или понизить собственную учётную запись'}), 400

    with DATA_LOCK:
        data = _load_db()
        data['users'] = users
        _save_db(data)
    return jsonify({'status': 'ok', 'count': len(users)})


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.after_request
def security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    resp.headers.setdefault('Content-Security-Policy',
                            "default-src 'self'; "
                            "script-src 'self' 'unsafe-inline'; "
                            "style-src 'self' 'unsafe-inline'; "
                            "font-src 'self'; "
                            "img-src 'self' data:; "
                            "connect-src 'self'")
    return resp


def _port_free(port):
    """Быстрая проверка: можно ли занять нужный порт."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('0.0.0.0', port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _start_server():
    """Запуск сервера с понятным сообщением, фолбэком на 8080 и автооткрытием браузера."""
    import sys

    debug = os.environ.get('PHONEBOOK_DEBUG', '') == '1'
    port = int(os.environ.get('PORT', 80))

    # If the chosen port is busy — silently fall back to 8080
    if not _port_free(port) and port != 8080:
        sys.stdout.write('Port %d is busy, falling back to 8080...\n' % port)
        port = 8080

    # Проброс в поток waitress/app.run для автооткрытия браузера
    opened = {'done': False}

    def _open_browser():
        if opened['done']:
            return
        # Даём серверу подняться
        for _ in range(40):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.3):
                    break
            except OSError:
                time.sleep(0.25)
        else:
            return
        opened['done'] = True
        url = 'http://127.0.0.1:%d/' % port
        try:
            webbrowser.open(url)
        except Exception:
            pass

    # Clear ASCII banner
    line = '=' * 58
    sys.stdout.write(line + '\n')
    sys.stdout.write('  Phonebook server started!\n')
    sys.stdout.write('  Open in browser:\n')
    sys.stdout.write('      http://127.0.0.1:%d/\n' % port)
    sys.stdout.write('  (for LAN colleagues: http://<your-IP>:%d/)\n' % port)
    sys.stdout.write('  Stop: Ctrl+C\n')
    sys.stdout.write(line + '\n')
    sys.stdout.flush()

    # Автотест: подождали лишний раз, чтобы не открыть браузер на мертвом порту
    # Автооткрытие браузера только в интерактивном терминале
    # (не при запуске из скриптов/тестов, где stdout не является TTY)
    if sys.stdout.isatty():
        threading.Thread(target=_open_browser, daemon=True).start()

    try:
        from waitress import serve
        serve(app, host='0.0.0.0', port=port, threads=8)
    except ImportError:
        app.run(host='0.0.0.0', port=port, debug=debug, use_reloader=False)


if __name__ == '__main__':
    # Миграция легаси db.json при старте (идемпотентна: для актуальной
    # структуры файл не переписывается)
    with DATA_LOCK:
        _load_db()
    _start_server()
