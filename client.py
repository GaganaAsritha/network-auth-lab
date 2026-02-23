import socket

HOST = "127.0.0.1"
PORT = 5000

def send_login(username: str,password: str):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.connect((HOST,PORT))

        message = f"LOGIN  {username} {password}\n"
        s.sendall(message.encode())

        response = s.recv(1024).decode().strip()
        print("Server response:", response)


if __name__ == "__main__":
    username = input("Username: ")
    password = input("Password: ")

    send_login(username,password)