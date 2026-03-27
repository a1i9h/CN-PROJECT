import socket
import ssl
import threading
import subprocess
import logging
import hashlib
import re
import os

# ─── Configuration ────────────────────────────────────────────────────────────
HOST       = '0.0.0.0'
PORT       = 8443
MAX_CLIENTS = 10
CERTFILE   = 'server.crt'
KEYFILE    = 'server.key'

# ─── Password Hashing ─────────────────────────────────────────────────────────
def hash_password(password):
    """SHA-256 hash a password."""
    return hashlib.sha256(password.encode()).hexdigest()

# ─── Hardcoded Users (passwords stored as SHA-256 hashes) ────────────────────
# To generate a hash: hashlib.sha256(b"yourpassword").hexdigest()
USERS = {
    'admin': hash_password('Admin@1234'),   # Must meet complexity rules
    'user1': hash_password('User1@5678'),
    'user2': hash_password('User2@9999'),
}

# ─── Password Complexity Checker ──────────────────────────────────────────────
def is_password_complex(password):
    """
    Rules:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, "OK"

# ─── Logging Setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    filename='server.log',
    level=logging.INFO,
    format='%(asctime)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log(msg):
    logging.info(msg)
    print(f"[LOG] {msg}")

# ─── Client Handler ───────────────────────────────────────────────────────────
def handle_client(conn, addr):
    log(f"New connection from {addr[0]}:{addr[1]}")

    try:
        # ── Step 1: Authentication ──────────────────────────────────────────
        conn.sendall(b"USERNAME: ")
        username = conn.recv(1024).decode().strip()

        conn.sendall(b"PASSWORD: ")
        password = conn.recv(1024).decode().strip()

        # Check password complexity before even checking credentials
        valid, reason = is_password_complex(password)
        if not valid:
            conn.sendall(f"AUTH_FAIL: {reason}\n".encode())
            log(f"AUTH FAILED (complexity) for user '{username}' from {addr[0]}: {reason}")
            conn.close()
            return

        # Hash the incoming password and compare against stored hash
        hashed_input = hash_password(password)
        if USERS.get(username) != hashed_input:
            conn.sendall(b"AUTH_FAIL: Invalid credentials. Disconnecting.\n")
            log(f"AUTH FAILED (wrong credentials) for user '{username}' from {addr[0]}")
            conn.close()
            return

        conn.sendall(b"AUTH_OK: Authentication successful. You may now send commands.\n")
        log(f"AUTH SUCCESS for user '{username}' from {addr[0]}")

        # ── Step 2: Command Loop ────────────────────────────────────────────
        while True:
            try:
                conn.sendall(b"CMD> ")
                data = conn.recv(4096)

                # Handle abrupt disconnection
                if not data:
                    log(f"Client {addr[0]} disconnected abruptly (no data)")
                    break

                command = data.decode().strip()

                if command.lower() == 'exit':
                    conn.sendall(b"Goodbye.\n")
                    log(f"User '{username}' from {addr[0]} sent EXIT")
                    break

                # Handle empty command
                if not command:
                    conn.sendall(b"0\n")
                    continue

                log(f"User '{username}' from {addr[0]} executed: {command}")

                # ── Step 3: Execute Command ─────────────────────────────────
                try:
                    result = subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    output = result.stdout + result.stderr
                    if not output:
                        output = "(no output)\n"

                except subprocess.TimeoutExpired:
                    output = "ERROR: Command timed out (10s limit).\n"
                    log(f"Command timeout for user '{username}': {command}")

                except Exception as e:
                    output = f"ERROR executing command: {str(e)}\n"
                    log(f"Command error for user '{username}': {e}")

                # ── Step 4: Send length-prefixed output ─────────────────────
                output_bytes = output.encode()
                length_prefix = f"{len(output_bytes)}\n".encode()
                conn.sendall(length_prefix + output_bytes)

            except (ConnectionResetError, BrokenPipeError):
                log(f"Client {addr[0]} disconnected abruptly during command loop")
                break

            except UnicodeDecodeError:
                log(f"Invalid input received from {addr[0]}")
                conn.sendall(b"ERROR: Invalid input encoding.\n")
                continue

    except ssl.SSLError as e:
        log(f"SSL error with {addr[0]}: {e}")

    except (ConnectionResetError, BrokenPipeError):
        log(f"Client {addr[0]} disconnected abruptly during auth")

    except Exception as e:
        log(f"Unexpected error with {addr[0]}: {e}")

    finally:
        try:
            conn.close()
        except:
            pass
        log(f"Connection closed for {addr[0]}")

# ─── Main Server ──────────────────────────────────────────────────────────────
def main():
    if not os.path.exists(CERTFILE) or not os.path.exists(KEYFILE):
        print(f"ERROR: Certificate files not found.")
        print(f"Run: openssl req -x509 -newkey rsa:2048 -keyout {KEYFILE} -out {CERTFILE} -days 365 -nodes -subj \"/CN=localhost\"")
        return

    # Create raw TCP socket
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((HOST, PORT))
    raw_sock.listen(MAX_CLIENTS)

    # Wrap with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    ssl_sock = context.wrap_socket(raw_sock, server_side=True)

    print(f"[SERVER] Listening on {HOST}:{PORT} (SSL enabled)")
    log(f"Server started on {HOST}:{PORT}")

    active_threads = []

    while True:
        try:
            conn, addr = ssl_sock.accept()

            # Clean up finished threads
            active_threads = [t for t in active_threads if t.is_alive()]

            if len(active_threads) >= MAX_CLIENTS:
                conn.sendall(b"SERVER FULL. Try again later.\n")
                conn.close()
                log(f"Rejected connection from {addr[0]} — server full")
                continue

            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
            active_threads.append(t)

        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down.")
            log("Server shut down by admin.")
            break

        except ssl.SSLError as e:
            log(f"SSL handshake failed for incoming connection: {e}")
            continue

        except Exception as e:
            log(f"Accept error: {e}")
            continue

    ssl_sock.close()

if __name__ == '__main__':
    main()