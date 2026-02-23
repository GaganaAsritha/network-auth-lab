import socket
import hashlib

HOST = "127.0.0.1"
PORT = 5000


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


users={
    "alice": hash_password("alice123"),
    "bob": hash_password("bob123")
}


def handle_client(conn):
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

    if username in users:
        hashed_input = hash_password(password)
        if hashed_input == users[username]:
            conn.sendall("SUCCESS\n".encode())
            return 
        
    conn.sendall("FAIL\n".encode())


def start_server():
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.bind((HOST,PORT))
        s.listen()

        print(f"server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            with conn:
                handle_client(conn)

if __name__ == "__main__":
    start_server()