import socket
import threading
import json

HOST = '127.0.0.1'
PORT = 5555

clients = {}  # username -> socket


def send_json(sock, data):
    message = json.dumps(data) + "\n"
    sock.sendall(message.encode("utf-8"))


def broadcast_peer_update(new_user):
    for username, client in clients.items():
        if username != new_user:
            send_json(client, {
                "type": "peer_joined",
                "username": new_user
            })


def handle_client(client_socket):
    username = None

    try:
        reader = client_socket.makefile("r")

        for line in reader:
            data = json.loads(line.strip())
            msg_type = data.get("type")

            # ---------------- REGISTER ----------------
            if msg_type == "register":
                username = data.get("username")

                if not username or username in clients:
                    send_json(client_socket, {
                        "type": "error",
                        "message": "Invalid or duplicate username"
                    })
                    return

                clients[username] = client_socket

                # send confirmation
                send_json(client_socket, {
                    "type": "register_ok",
                    "message": f"Registered as {username}",
                    "peers": [u for u in clients if u != username]
                })

                broadcast_peer_update(username)

                print(f"{username} connected")

            # ---------------- PUBLIC KEY ----------------
            elif msg_type == "public_key":
                target = data.get("to")

                if target in clients:
                    send_json(clients[target], {
                        "type": "public_key",
                        "from": username,
                        "public_key": data.get("public_key")
                    })

            # ---------------- ENCRYPTED MESSAGE ----------------
            elif msg_type == "encrypted_message":
                target = data.get("to")

                if target in clients:
                    send_json(clients[target], {
                        "type": "encrypted_message",
                        "from": username,
                        "encrypted_message": data.get("encrypted_message")
                    })

            # ---------------- DISCONNECT ----------------
            elif msg_type == "disconnect":
                break

    except Exception as e:
        print(f"Error: {e}")

    finally:
        if username and username in clients:
            del clients[username]

            for client in clients.values():
                send_json(client, {
                    "type": "peer_left",
                    "username": username
                })

        client_socket.close()
        print(f"{username} disconnected")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"Server running on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"New connection from {addr}")

        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()


start_server()
