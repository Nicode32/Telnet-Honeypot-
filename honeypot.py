import socket

HOST = '0.0.0.0'
PORT = 2323

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
print(f"[*] Honeypot listening on port {PORT}")
conn, addr = server.accept()
print(f"[+] Connection from {addr[0]}:{addr[1]}")

conn.close()