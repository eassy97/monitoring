from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit
import requests
import time
import threading
import os
import uuid
import json
from datetime import datetime
import smtplib
from email.message import EmailMessage

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tajny_klic_123'
socketio = SocketIO(app, cors_allowed_origins="*")

# Konfigurace souborů
USERS_FILE = "users.txt"
PINGS_FILE = "pings.txt"
STATUS_LOG = "monitoring_status.log"
ACTIVE_CHECKS_FILE = "active_checks.json"

# Globální data structures
# {check_id: {url, interval, user, stop_event, thread,
#             error_threshold, notify_email, error_count}}
active_checks = {}

# Inicializace souborů
for file in [USERS_FILE, PINGS_FILE, STATUS_LOG]:
    if not os.path.exists(file):
        open(file, "w").close()

# Inicializace JSON souboru
if not os.path.exists(ACTIVE_CHECKS_FILE):
    with open(ACTIVE_CHECKS_FILE, "w") as f:
        json.dump({}, f)

def load_active_checks():
    """Načte aktivní checky ze souboru a spustí je"""
    global active_checks
    try:
        with open(ACTIVE_CHECKS_FILE, "r") as f:
            content = f.read().strip()
            if content:
                checks = json.loads(content)
                for check_id, data in checks.items():
                    start_check(
                        data['url'],
                        data['interval'],
                        data['user'],
                        check_id,
                        data.get('error_threshold', 3),
                        data.get('notify_email', '')
                    )
    except Exception as e:
        print(f"Chyba při načítání aktivních checků: {e}")

def save_active_checks():
    """Uloží aktivní checky do souboru"""
    checks_to_save = {}
    for check_id, data in active_checks.items():
        checks_to_save[check_id] = {
            "url": data["url"],
            "interval": data["interval"],
            "user": data["user"],
            "error_threshold": data.get("error_threshold", 3),
            "notify_email": data.get("notify_email", "")
        }
    with open(ACTIVE_CHECKS_FILE, "w") as f:
        json.dump(checks_to_save, f)

def log_action(action: str, url: str, interval: int, user: str):
    """Zaloguje akci do souboru"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(STATUS_LOG, "a") as f:
        f.write(f"[{timestamp}] {user} {action} {url} (interval: {interval}s)\n")

def save_ping_result(user: str, check_id: str, url: str, status: str,
                     response_time: float = 0, message: str = ""):
    """Uloží výsledek pingu do souboru"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(PINGS_FILE, "a", encoding="utf-8") as f:
        f.write(
            f"{user}|{check_id}|{timestamp}|{url}|{status}|{response_time}|{message}\n"
        )

def load_user_history(username: str):
    """Načte historii pingů pro konkrétního uživatele"""
    history = []
    if os.path.exists(PINGS_FILE):
        with open(PINGS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 7:
                    user, _check_id, timestamp, url, status, resp, msg = parts
                elif len(parts) == 6:
                    user, timestamp, url, status, resp, msg = parts
                else:
                    continue
                if user == username:
                    history.append({
                        "timestamp": timestamp,
                        "url": url,
                        "status": status,
                        "response_time": resp,
                        "message": msg
                    })
    return sorted(history, key=lambda x: x["timestamp"], reverse=True)[:20]

def load_check_history(check_id: str):
    """Načte historii pro konkrétní check"""
    history = []
    if os.path.exists(PINGS_FILE):
        with open(PINGS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 7 and parts[1] == check_id:
                    _, _cid, timestamp, url, status, resp, msg = parts
                    history.append({
                        "timestamp": timestamp,
                        "url": url,
                        "status": status,
                        "response_time": resp,
                        "message": msg
                    })
    return sorted(history, key=lambda x: x["timestamp"], reverse=True)

def check_user(username: str, password: str) -> bool:
    """Ověří přihlašovací údaje"""
    if not os.path.exists(USERS_FILE):
        return False
    with open(USERS_FILE, "r") as f:
        for line in f:
            if ":" in line:
                user, pwd = line.strip().split(":", 1)
                if user == username and pwd == password:
                    return True
    return False

def send_notification(email: str, url: str, message: str):
    """Odešle notifikační e-mail"""
    try:
        msg = EmailMessage()
        msg["Subject"] = f"Monitorovací alert pro {url}"
        msg["From"] = "monitor@example.com"
        msg["To"] = email
        msg.set_content(message)
        with smtplib.SMTP("localhost") as smtp:
            smtp.send_message(msg)
    except Exception as e:
        print(f"Nepodařilo se odeslat e-mail: {e}")


def ping_worker(
    url: str,
    interval: int,
    user: str,
    check_id: str,
    stop_event: threading.Event,
    error_threshold: int,
    notify_email: str,
):
    """Hlavní pracovní funkce pro pingování"""
    error_count = 0
    while not stop_event.is_set():
        try:
            start_time = time.time()
            response = requests.get(url, timeout=5)
            response_time = round((time.time() - start_time) * 1000, 2)

            result = {
                "check_id": check_id,
                "url": url,
                "status": "success",
                "code": response.status_code,
                "time": response_time,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }

            save_ping_result(user, check_id, url, "success", response_time, f"Status {response.status_code}")
            if response.status_code != 200:
                error_count += 1
            else:
                error_count = 0

            socketio.emit("ping_update", result)

        except Exception as e:
            result = {
                "check_id": check_id,
                "url": url,
                "status": "error",
                "message": str(e),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }

            save_ping_result(user, check_id, url, "error", 0, str(e))
            error_count += 1
            socketio.emit("ping_update", result)

        if error_count >= error_threshold and notify_email:
            send_notification(notify_email, url, f"URL vrací chybu {error_count}x za sebou")
            error_count = 0

        time.sleep(interval)

def start_check(
    url: str,
    interval: int,
    user: str,
    check_id: str = None,
    error_threshold: int = 3,
    notify_email: str = "",
):
    """Spustí nový check"""
    if check_id is None:
        check_id = str(uuid.uuid4())

    stop_event = threading.Event()
    thread = threading.Thread(
        target=ping_worker,
        args=(url, interval, user, check_id, stop_event, error_threshold, notify_email),
    )
    thread.daemon = True

    active_checks[check_id] = {
        "url": url,
        "interval": interval,
        "user": user,
        "error_threshold": error_threshold,
        "notify_email": notify_email,
        "error_count": 0,
        "stop_event": stop_event,
        "thread": thread
    }
    
    thread.start()
    save_active_checks()
    log_action("spustil monitoring", url, interval, user)
    return check_id

def stop_check(check_id: str):
    """Zastaví konkrétní check"""
    if check_id in active_checks:
        check_data = active_checks[check_id]
        check_data["stop_event"].set()
        check_data["thread"].join(timeout=1)
        
        log_action("zastavil monitoring", check_data["url"], check_data["interval"], check_data["user"])
        del active_checks[check_id]
        save_active_checks()

# Flask routes
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_checks = {k: v for k, v in active_checks.items() if v['user'] == session['username']}
    history = load_user_history(session['username'])
    
    return render_template('index.html', 
                         username=session['username'],
                         active_checks=user_checks,
                         history=history)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if check_user(username, password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Neplatné přihlašovací údaje', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Byl jste odhlášen', 'info')
    return redirect(url_for('login'))


@app.route('/check/<check_id>', methods=['GET', 'POST'])
def check_settings(check_id):
    if check_id not in active_checks:
        flash('Check neexistuje', 'danger')
        return redirect(url_for('index'))

    check = active_checks[check_id]

    if request.method == 'POST':
        interval = int(request.form.get('interval', check['interval']))
        threshold = int(request.form.get('threshold', check.get('error_threshold', 3)))
        email = request.form.get('email', check.get('notify_email', ''))

        stop_check(check_id)
        start_check(check['url'], interval, check['user'], check_id, threshold, email)
        flash('Nastavení uloženo', 'info')
        return redirect(url_for('check_settings', check_id=check_id))

    history = load_check_history(check_id)
    return render_template('check_settings.html', check_id=check_id, check=check, history=history)

# SocketIO handlers
@socketio.on('start_monitoring')
def handle_start_monitoring(data):
    if 'username' not in session:
        return
    
    url = data['url']
    interval = int(data['interval'])
    threshold = int(data.get('threshold', 3))
    email = data.get('email', '')
    user = session['username']

    check_id = start_check(url, interval, user, None, threshold, email)
    
    emit('check_started', {
        'check_id': check_id,
        'url': url,
        'interval': interval
    })

@socketio.on('stop_monitoring')
def handle_stop_monitoring(data):
    check_id = data['check_id']
    stop_check(check_id)
    emit('check_stopped', {'check_id': check_id})

@socketio.on('get_history')
def handle_get_history():
    if 'username' in session:
        history = load_user_history(session['username'])
        emit('history_update', history)

@socketio.on('get_active_checks')
def handle_get_active_checks():
    if 'username' in session:
        user_checks = {k: v for k, v in active_checks.items() if v['user'] == session['username']}
        emit('active_checks_update', user_checks)

if __name__ == '__main__':
    # Načti aktivní checky při startu
    load_active_checks()
    socketio.run(app, host='127.0.0.1', port=5050, debug=True)
