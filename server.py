import threading
import bcrypt
import socket
import time

HOST = "127.0.0.1"
PORT = 5000

lock = threading.Lock()
active_connections = 0
connection_lock = threading.Lock()
MAX_CONNECTIONS = 5
BLOCK_DURATION = 30


def hash_password(password: str) -> bytes:
    salt=bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)


users={
    "alice": hash_password("alice123"),
    "bob": hash_password("bob123")
}

failed_login_user = {}
failed_login_ip = {}
blocked_ips = {}

MAX_ATTEMPTS = 3
WINDOW_SECONDS = 10


def handle_client(conn, client_ip):
    global active_connections
    conn.settimeout(5)

    try:

        with connection_lock:
             if is_ip_blocked(client_ip):
                  log_attempt(client_ip, "-", "BLOCKED")
                  conn.sendall("BLOCKED\n".encode())
                  return
             
        try:
              data = conn.recv(1024).decode().strip()
        except socket.timeout:
              print("Connection timed out.")
              return

        parts = data.split()

        if len(parts) != 3 or parts[0] != "LOGIN":
               log_attempt(client_ip, "-", "FAIL")
               conn.sendall("FAIL\n".encode())
               return
    
        _,username,password = parts

        with lock:
               if is_rate_limited(username, failed_login_user) or \
                 is_rate_limited(client_ip,failed_login_ip):
                       log_attempt(client_ip, username, "BLOCKED")
                       conn.sendall("FAIL\n".encode())
                       return
        
        auth_success = False

        if username in users:
                if bcrypt.checkpw(password.encode(), users[username]):
                       auth_success = True

        if not auth_success:
                with lock:
                       record_failure(username, failed_login_user)
                       record_failure(client_ip, failed_login_ip)

                       if len(failed_login_ip.get(client_ip,[])) >= MAX_ATTEMPTS:
                            blocked_ips[client_ip] = time.time()

                log_attempt(client_ip, username, "FAIL")
                conn.sendall("FAIL\n".encode())
                return
    
        log_attempt(client_ip, username, "SUCCESS")
        conn.sendall("SUCCESS\n".encode())

    finally:
        with connection_lock:
              active_connections -= 1

        conn.close()
        


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


def log_attempt(ip, username, result):
     timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

     log_line = f"[{timestamp}] | IP: {ip} | USER: {username} | RESULT: {result}\n"

     with open("auth.log", "a") as f:
          f.write(log_line)


def is_ip_blocked(ip):
     current_time = time.time()

     if ip in blocked_ips:
          if current_time - blocked_ips[ip] <= BLOCK_DURATION:
               return True
          else:
               del blocked_ips[ip] 
     return False


def start_server():
    global active_connections
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.bind((HOST,PORT))
        s.listen()

        print(f"server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            with connection_lock:
                if active_connections >= MAX_CONNECTIONS:
                    conn.close()
                    continue
                active_connections += 1
            client_ip = addr[0]
            
            thread = threading.Thread(target=handle_client,args=(conn, client_ip))
            thread.start()

if __name__ == "__main__":
    start_server() 