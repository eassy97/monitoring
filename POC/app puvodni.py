from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit
import requests
import time
import threading
import os
import traceback
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tajny_klic_12345'
socketio = SocketIO(app, cors_allowed_origins="*")

# Globální stavové proměnné
monitoring_active = False
current_url = ""
current_interval = 1
current_user = ""

# Souborové konstanty
USERS_FILE = "users.txt"
PINGS_FILE = "pings.txt"
STATUS_LOG = "monitoring_status.log"
STATE_FILE = "monitoring_state.txt"

# Inicializace souborů
for file in [USERS_FILE, PINGS_FILE, STATUS_LOG, STATE_FILE]:
    if not os.path.exists(file):
        open(file, "w").close()

def save_monitoring_state():
    """Uloží aktuální stav monitoringu do souboru"""
    with open(STATE_FILE, "w") as f:
        state = "on" if monitoring_active else "off"
        f.write(f"{state}|{current_url}|{current_interval}|{current_user}")

def load_monitoring_state():
    """Načte poslední stav monitoringu ze souboru"""
    global monitoring_active, current_url, current_interval, current_user
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            content = f.read().strip()
            if content:
                parts = content.split("|")
                if len(parts) == 4:
                    monitoring_active = (parts[0] == "on")
                    current_url = parts[1]
                    current_interval = int(parts[2])
                    current_user = parts[3]

def log_action(action: str):
    """Zaloguje akci do souboru s časovou značkou"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(STATUS_LOG, "a") as f:
        f.write(f"[{timestamp}] {current_user} {action} {current_url} (interval: {current_interval}s)\n")

def save_ping_result(status: str, response_time: float = 0, message: str = ""):
    """Uloží výsledek pingování"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(PINGS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{current_user}|{timestamp}|{current_url}|{status}|{response_time}|{message}\n")

def load_user_history(username: str) -> list:
    """Načte historii pro konkrétního uživatele"""
    history = []
    if os.path.exists(PINGS_FILE):
        with open(PINGS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 6 and parts[0] == username:
                    history.append({
                        "timestamp": parts[1],
                        "url": parts[2],
                        "status": parts[3],
                        "response_time": parts[4],
                        "message": parts[5]
                    })
    return sorted(history, key=lambda x: x["timestamp"], reverse=True)

def check_credentials(username: str, password: str) -> bool:
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

def ping_worker():
    """Hlavní pracovní smyčka pro monitorování"""
    global monitoring_active
    while monitoring_active:
        try:
            start_time = time.time()
            response = requests.get(current_url, timeout=5)
            response_time = round((time.time() - start_time) * 1000, 2)
            
            result = {
                "status": "success",
                "code": response.status_code,
                "time": response_time,
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }
            save_ping_result("success", response_time, f"Status {response.status_code}")
            
        except Exception as e:
            result = {
                "status": "error",
                "message": str(e),
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }
            save_ping_result("error", 0, str(e))
        
        socketio.emit("ping_update", result)
        time.sleep(current_interval)
    
    # Ukončení monitorování
    monitoring_active = False
    save_monitoring_state()
    log_action("Zastaveno")
    socketio.emit("status_update", {"status": "inactive"})

@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", 
                         username=session["username"],
                         history=load_user_history(session["username"]))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if check_credentials(username, password):
            session["username"] = username
            return redirect(url_for("index"))
        flash("Neplatné přihlašovací údaje", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

@socketio.on("start_monitoring")
def handle_start(data):
    global monitoring_active, current_url, current_interval, current_user
    if not monitoring_active:
        current_url = data["url"]
        current_interval = int(data["interval"])
        current_user = session.get("username", "anonymous")
        monitoring_active = True
        
        log_action("Spuštěno")
        save_monitoring_state()
        
        threading.Thread(target=ping_worker).start()
        socketio.emit("status_update", {
            "status": "active",
            "url": current_url,
            "interval": current_interval
        })

@socketio.on("stop_monitoring")
def handle_stop():
    global monitoring_active
    if monitoring_active:
        monitoring_active = False
        socketio.emit("status_update", {"status": "inactive"})

@socketio.on("get_history")
def handle_history_request():
    if "username" in session:
        emit("history_update", load_user_history(session["username"]))

if __name__ == "__main__":
    load_monitoring_state()
    if monitoring_active:
        threading.Thread(target=ping_worker).start()
    socketio.run(app, host="127.0.0.1", port=5050, debug=True)
