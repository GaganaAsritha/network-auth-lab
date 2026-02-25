import socket
import hashlib
import time

HOST = "127.0.0.1"
PORT = 5000


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


users={
    "alice": hash_password("alice123"),
    "bob": hash_password("bob123")
}

failed_login_user = {}
failed_login_ip = {}

MAX_ATTEMPTS = 3
WINDOW_SECONDS = 10


def handle_client(conn, client_ip):
    conn.settimeout(5)

    try:
        data = conn.recv(1024).decode().strip()
    except socket.timeout:
        print("Connection timed out.")
        return

    parts = data.split()

    if len(parts) != 3 or parts[0] != "LOGIN":
        conn.sendall("FAIL\n".encode())
        return
    
    _,username,password = parts

    if is_rate_limited(username, failed_login_user) or \
       is_rate_limited(client_ip,failed_login_ip):
        conn.sendall("FAIL\n".encode())
        return
    
    if username in users:
        hashed_input = hash_password(password)
        if hashed_input == users[username]:
            conn.sendall("SUCCESS\n".encode())
            return 
        
    record_failure(username,failed_login_user)
    record_failure(client_ip,failed_login_ip)

    conn.sendall("FAIL\n".encode())


#erase old timestamps
def clean_old_attempts(attempt_list):
    current_time = time.time()
    return [t for t in attempt_list if current_time - t <= WINDOW_SECONDS]


#count timestamps
def is_rate_limited(key,store):
    if key not in store:
        return False
    
    store[key] = clean_old_attempts(store[key])

    return len(store[key]) >= MAX_ATTEMPTS


#add timestamps
def record_failure(key,store):
    current_time = time.time()
    if key not in store:
        store[key] = []
    store[key].append(current_time)


def start_server():
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.bind((HOST,PORT))
        s.listen()

        print(f"server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            client_ip = addr[0]
            with conn:
                handle_client(conn, client_ip)

if __name__ == "__main__":
    start_server() 