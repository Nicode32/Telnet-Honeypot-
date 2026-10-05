import socket
import json
from datetime import datetime, timezone

HOST = '0.0.0.0'
PORT = 2323
LOG_FILE = "attack_log.jsonl"

IAC = 255
WILL = 251
ECHO = 1

# ---------- Logging Layer (Layer 4) ----------
def log_event(event_type, ip, **kwargs):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "ip": ip,
        **kwargs
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

# ---------- Fake filesystem (Layer 2) ----------
fake_files = {
    "/home/user": ["notes.txt", "backup.sh", "passwords.txt"],
}
current_dir = "/home/user"

# ---------- Command Emulation Layer (Layer 3) ----------
def handle_command(cmd):
    global current_dir

    parts = cmd.strip().split()
    if not parts:
        return ""

    base = parts[0]

    if base == "whoami":
        return "user"
    elif base == "pwd":
        return current_dir
    elif base == "ls":
        files = fake_files.get(current_dir, [])
        return "  ".join(files)
    elif base == "id":
        return "uid=1000(user) gid=1000(user) groups=1000(user)"
    elif base == "uname":
        if len(parts) > 1 and parts[1] == "-a":
            return "Linux ubuntu 5.15.0-91-generic x86_64 GNU/Linux"
        return "Linux"
    elif base == "cat":
        if len(parts) < 2:
            return "cat: missing operand"
        filename = parts[1]
        if filename in fake_files.get(current_dir, []):
            return f"cat: {filename}: Permission denied"
        return f"cat: {filename}: No such file or directory"
    else:
        return f"{base}: command not found"


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
print(f"[*] Honeypot listening on port {PORT}")

conn, addr = server.accept()
ip = addr[0]
print(f"[+] Connection from {ip}:{addr[1]}")
log_event("connection", ip, port=addr[1])

conn.send(bytes([IAC, WILL, ECHO]))
conn.send(b"Ubuntu 20.04.3 LTS\r\n\r\n")
conn.send(b"login: ")

buffer = ""
state = "username"
username = ""
session_start = datetime.now(timezone.utc)

while True:
    data = conn.recv(1024)

    if not data:
        print(f"[-] Connection closed by {ip}")
        duration = (datetime.now(timezone.utc) - session_start).total_seconds()
        log_event("session_end", ip, duration_seconds=duration)
        break

    chunk = data.decode(errors="ignore")

    for char in chunk:
        if char in ("\r", "\n"):
            line = buffer.strip()
            buffer = ""

            if line == "" and state != "shell":
                continue

            if state == "username":
                username = line
                print(f"[login attempt] {ip} username: {username}")
                conn.send(b"\r\nPassword: ")
                state = "password"

            elif state == "password":
                password = line
                print(f"[login attempt] {ip} username: {username} password: {password}")
                log_event("login_attempt", ip, username=username, password=password)
                conn.send(b"\r\nWelcome to Ubuntu 20.04.3 LTS\r\n\r\n$ ")
                state = "shell"

            elif state == "shell":
                print(f"[recv] {ip} sent: {line}")

                if line.lower() == "exit":
                    conn.send(b"\r\nGoodbye!\r\n")
                    duration = (datetime.now(timezone.utc) - session_start).total_seconds()
                    log_event("session_end", ip, duration_seconds=duration, reason="exit_command")
                    conn.close()
                    server.close()
                    exit()

                log_event("command", ip, command=line)
                output = handle_command(line)
                conn.send(f"\r\n{output}\r\n$ ".encode())

        elif char in ("\x7f", "\b"):  # Backspace
            if buffer:
                buffer = buffer[:-1]
                if state != "password":
                    conn.send(b"\x08 \x08")  # cursor peeche, space se overwrite, cursor phir peeche

        elif char.isprintable():  # sirf normal characters accept karo, control chars ignore
            buffer += char
            if state != "password":
                conn.send(char.encode())

        # else: koi aur non-printable/control character ho toh chup-chaap ignore karo

conn.close()
server.close()