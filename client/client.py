import json
import secrets
import socket
import threading
from typing import Dict, List, Optional

from encryption import encrypt_message, decrypt_message


# Connection settings
HOST = "127.0.0.1"
PORT = 5555
BUFFER_SIZE = 4096


#Diffie-Hellman implementation


DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
DH_GENERATOR = 2


try:
    from key_exchange import (
        generate_private_key as _generate_private_key,
        generate_public_key as _generate_public_key,
        compute_shared_secret as _compute_shared_secret,
    )
except Exception:
    _generate_private_key = None
    _generate_public_key = None
    _compute_shared_secret = None


def generate_private_key() -> int:
    if callable(_generate_private_key):
        return int(_generate_private_key())
    return secrets.randbelow(DH_PRIME - 2) + 2


def generate_public_key(private_key: int) -> int:
    if callable(_generate_public_key):
        return int(_generate_public_key(private_key))
    return pow(DH_GENERATOR, private_key, DH_PRIME)


def compute_shared_secret(peer_public_key: int, private_key: int) -> int:
    if callable(_compute_shared_secret):
        return int(_compute_shared_secret(peer_public_key, private_key))
    return pow(int(peer_public_key), private_key, DH_PRIME)


class SecureChatClient:
    def __init__(self, username: str, host: str = HOST, port: int = PORT) -> None:
        self.username = username.strip()
        self.host = host
        self.port = port

        self.sock: Optional[socket.socket] = None
        self.reader = None
        self.running = False

        self.send_lock = threading.Lock()
        self.registered_event = threading.Event()

        self.connected_users = set()
        self.active_peer: Optional[str] = None

        self.sessions: Dict[str, Dict[str, Optional[int]]] = {}
        self.pending_messages: Dict[str, List[str]] = {}

    # ---------------------------------------------
    # Socket helpers
    # ---------------------------------------------
    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.reader = self.sock.makefile("r", encoding="utf-8")
        self.running = True

        self._send_json({"type": "register", "username": self.username})

        receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        receive_thread.start()

        if not self.registered_event.wait(timeout=5):
            raise RuntimeError("Did not receive registration confirmation from server")

    def close(self) -> None:
        if not self.running and not self.sock:
            return

        self.running = False

        try:
            self._send_json({"type": "disconnect"})
        except Exception:
            pass

        try:
            if self.reader:
                self.reader.close()
        except Exception:
            pass

        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

        self.sock = None
        self.reader = None

    def _send_json(self, payload: dict) -> None:
        if not self.sock:
            raise RuntimeError("Socket is not connected")

        data = json.dumps(payload) + "\n"
        with self.send_lock:
            self.sock.sendall(data.encode("utf-8"))

    # Key exchange helpers
    def _ensure_session(self, peer: str) -> Dict[str, Optional[int]]:
        if peer not in self.sessions:
            private_key = generate_private_key()
            public_key = generate_public_key(private_key)
            self.sessions[peer] = {
                "private_key": private_key,
                "public_key": public_key,
                "shared_secret": None,
                "public_key_sent": 0,
            }
        return self.sessions[peer]

    def _send_public_key(self, peer: str, force: bool = False) -> None:
        session = self._ensure_session(peer)

        if session["public_key_sent"] and not force:
            return

        self._send_json(
            {
                "type": "public_key",
                "to": peer,
                "public_key": session["public_key"],
            }
        )
        session["public_key_sent"] = 1
        print(f"[key exchange] Sent public key to {peer}")

    def start_key_exchange(self, peer: str, force_resend: bool = False) -> None:
        if peer == self.username:
            print("You cannot start a chat with yourself.")
            return

        self._ensure_session(peer)
        self._send_public_key(peer, force=force_resend)


    # Message sending/receiving
    def send_encrypted_message(self, peer: str, message: str) -> None:
        if not message.strip():
            return

        if peer == self.username:
            print("You cannot send messages to yourself.")
            return

        session = self._ensure_session(peer)
        shared_secret = session.get("shared_secret")

        if shared_secret is None:
            self.pending_messages.setdefault(peer, []).append(message)
            self.start_key_exchange(peer)
            print(f"[key exchange] Waiting for shared secret with {peer}. Message queued.")
            return

        # compatibility with Member 3's encryption module
        encrypted = encrypt_message(message, shared_secret)

        self._send_json(
            {
                "type": "encrypted_message",
                "to": peer,
                "encrypted_message": encrypted,
            }
        )
        print(f"[you -> {peer}] {message}")

    def _flush_pending_messages(self, peer: str) -> None:
        queued = self.pending_messages.get(peer, [])
        if not queued:
            return

        self.pending_messages[peer] = []
        for message in queued:
            self.send_encrypted_message(peer, message)

    def _receive_loop(self) -> None:
        try:
            for line in self.reader:
                line = line.strip()
                if not line:
                    continue

                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    print(f"[server] Received invalid JSON: {line}")
                    continue

                self._handle_server_message(payload)
        except Exception as exc:
            if self.running:
                print(f"[connection] Receive error: {exc}")
        finally:
            self.running = False
            print("[connection] Disconnected from server.")

    def _handle_server_message(self, payload: dict) -> None:
        message_type = payload.get("type")

        if message_type == "register_ok":
            peers = payload.get("peers", [])
            self.connected_users = set(peers)
            print(payload.get("message", f"Connected as {self.username}"))
            if peers:
                print("Connected peers:", ", ".join(sorted(peers)))
            else:
                print("No other peers connected yet.")
            self.registered_event.set()

        elif message_type == "peer_joined":
            username = payload.get("username")
            if username and username != self.username:
                self.connected_users.add(username)
                print(f"[server] {username} joined the chat.")

        elif message_type == "peer_left":
            username = payload.get("username")
            if username:
                self.connected_users.discard(username)
                if self.active_peer == username:
                    print(f"[server] {username} disconnected. Active peer cleared.")
                    self.active_peer = None
                else:
                    print(f"[server] {username} disconnected.")

        elif message_type == "public_key":
            sender = payload.get("from")
            peer_public_key = payload.get("public_key")
            if not sender or peer_public_key is None:
                print("[server] Invalid public key message received.")
                return

            session = self._ensure_session(sender)

            if not session["public_key_sent"]:
                self._send_public_key(sender)

            session["shared_secret"] = compute_shared_secret(int(peer_public_key), int(session["private_key"]))
            print(f"[key exchange] Shared secret established with {sender}")
            self._flush_pending_messages(sender)

        elif message_type == "encrypted_message":
            sender = payload.get("from")
            encrypted = payload.get("encrypted_message")
            if not sender or encrypted is None:
                print("[server] Invalid encrypted message received.")
                return

            session = self._ensure_session(sender)
            shared_secret = session.get("shared_secret")

            if shared_secret is None:
                print(f"[warning] Encrypted message received from {sender} before key exchange finished.")
                return

            try:
                # Required compatibility with Member 3's encryption module
                decrypted = decrypt_message(encrypted, shared_secret)
                print(f"[{sender}] {decrypted}")
            except Exception as exc:
                print(f"[warning] Could not decrypt message from {sender}: {exc}")

        elif message_type == "error":
            print(f"[server error] {payload.get('message', 'Unknown error')}")
            if not self.registered_event.is_set():
                self.registered_event.set()

        else:
            print(f"[server] {payload}")

    # User interface
    def print_help(self) -> None:
        print("\nCommands:")
        print("  /users                Show connected users")
        print("  /chat <username>      Set active peer and begin key exchange")
        print("  /key <username>       Resend your public key to a peer")
        print("  /send <user> <msg>    Send message directly to a peer")
        print("  /quit                 Disconnect and exit")
        print("  /help                 Show commands")
        print("Any normal text will be sent to the active peer.\n")

    def interactive_loop(self) -> None:
        self.print_help()

        while self.running:
            try:
                user_input = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting...")
                break

            if not user_input:
                continue

            if user_input == "/help":
                self.print_help()
                continue

            if user_input == "/users":
                if self.connected_users:
                    print("Connected users:", ", ".join(sorted(self.connected_users)))
                else:
                    print("No other users connected.")
                continue

            if user_input == "/quit":
                break

            if user_input.startswith("/chat "):
                peer = user_input.split(maxsplit=1)[1].strip()
                if not peer:
                    print("Usage: /chat <username>")
                    continue
                self.active_peer = peer
                print(f"Active peer set to {peer}")
                self.start_key_exchange(peer)
                continue

            if user_input.startswith("/key "):
                peer = user_input.split(maxsplit=1)[1].strip()
                if not peer:
                    print("Usage: /key <username>")
                    continue
                self.start_key_exchange(peer, force_resend=True)
                continue

            if user_input.startswith("/send "):
                parts = user_input.split(maxsplit=2)
                if len(parts) < 3:
                    print("Usage: /send <username> <message>")
                    continue
                peer = parts[1].strip()
                message = parts[2]
                self.send_encrypted_message(peer, message)
                continue

            if not self.active_peer:
                print("Choose a peer first with /chat <username>")
                continue

            self.send_encrypted_message(self.active_peer, user_input)

        self.close()


def main() -> None:
    print("Secure Chat Client")
    username = input("Enter your username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    client = SecureChatClient(username=username)

    try:
        client.connect()
        client.interactive_loop()
    except Exception as exc:
        print(f"Failed to start client: {exc}")
        client.close()


if __name__ == "__main__":
    main()
