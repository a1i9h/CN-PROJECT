import socket
import ssl
import threading
import subprocess
import logging
import datetime
import os

# ─── Configuration ────────────────────────────────────────────────────────────
HOST = '0.0.0.0'       # Listen on all interfaces
PORT = 8443            # Port to listen on
MAX_CLIENTS = 10       # Maximum simultaneous clients
CERTFILE = 'server.crt'
KEYFILE  = 'server.key'

# Hardcoded credentials
USERS = {
    'admin': 'admin123',
    'user1': 'pass1',
    'user2': 'pass2',
}

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

        if USERS.get(username) != password:
            conn.sendall(b"AUTH_FAIL: Invalid credentials. Disconnecting.\n")
            log(f"AUTH FAILED for user '{username}' from {addr[0]}")
            conn.close()
            return

        conn.sendall(b"AUTH_OK: Authentication successful. You may now send commands.\n")
        log(f"AUTH SUCCESS for user '{username}' from {addr[0]}")

        # ── Step 2: Command Loop ────────────────────────────────────────────
        while True:
            conn.sendall(b"CMD> ")
            data = conn.recv(4096)

            if not data:
                log(f"Client {addr[0]} disconnected (no data)")
                break

            command = data.decode().strip()

            if command.lower() == 'exit':
                conn.sendall(b"Goodbye.\n")
                log(f"User '{username}' from {addr[0]} sent EXIT")
                break

            if not command:
                continue

            log(f"User '{username}' from {addr[0]} executed: {command}")

            # ── Step 3: Execute Command ─────────────────────────────────────
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
                output = "ERROR: Command timed out.\n"
            except Exception as e:
                output = f"ERROR: {str(e)}\n"

            # ── Step 4: Send Output ─────────────────────────────────────────
            # Send length-prefixed so client knows when output ends
            output_bytes = output.encode()
            length_prefix = f"{len(output_bytes)}\n".encode()
            conn.sendall(length_prefix + output_bytes)

    except (ConnectionResetError, BrokenPipeError, ssl.SSLError) as e:
        log(f"Connection error with {addr[0]}: {e}")
    finally:
        conn.close()
        log(f"Connection closed for {addr[0]}")

# ─── Main Server ──────────────────────────────────────────────────────────────
def main():
    # Check certificates exist
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
        except Exception as e:
            log(f"Accept error: {e}")

    ssl_sock.close()

if __name__ == '__main__':
    main()
