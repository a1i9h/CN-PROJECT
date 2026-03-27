import socket
import ssl

# ─── Configuration ────────────────────────────────────────────────────────────
SERVER_IP   = '127.0.0.1'   # Change this to server's IP when running on separate machines
SERVER_PORT = 8443

# ─── Step 1: Create raw TCP socket ───────────────────────────────────────────
raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# ─── Step 2: Wrap with SSL ────────────────────────────────────────────────────
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False          # Self-signed cert, no hostname verification
context.verify_mode = ssl.CERT_NONE    # Accept self-signed certificate

ssl_sock = context.wrap_socket(raw_sock, server_hostname=SERVER_IP)

# ─── Step 3: Connect to server ───────────────────────────────────────────────
ssl_sock.connect((SERVER_IP, SERVER_PORT))
print(f"[CLIENT] Connected to {SERVER_IP}:{SERVER_PORT} (SSL enabled)")
print(f"[CLIENT] Cipher in use: {ssl_sock.cipher()[0]}")

try:
    # ── Step 4: Authentication ────────────────────────────────────────────────
    prompt = ssl_sock.recv(1024).decode()
    print(prompt, end='')
    username = input()
    ssl_sock.sendall(username.encode())

    prompt = ssl_sock.recv(1024).decode()
    print(prompt, end='')
    password = input()
    ssl_sock.sendall(password.encode())

    response = ssl_sock.recv(1024).decode()
    print(response, end='')

    if response.startswith("AUTH_FAIL"):
        print("[CLIENT] Exiting.")
        ssl_sock.close()
        exit()

    # ── Step 5: Command Loop ──────────────────────────────────────────────────
    while True:
        prompt = ssl_sock.recv(1024).decode()
        print(prompt, end='')

        command = input()
        ssl_sock.sendall(command.encode())

        if command.lower() == 'exit':
            response = ssl_sock.recv(1024).decode()
            print(response)
            break

        if not command.strip():
            continue

        # ── Step 6: Receive length-prefixed output ────────────────────────────
        # First line is the byte count
        length_line = b''
        while not length_line.endswith(b'\n'):
            length_line += ssl_sock.recv(1)
        output_len = int(length_line.decode().strip())

        # Receive exactly output_len bytes
        output = b''
        while len(output) < output_len:
            chunk = ssl_sock.recv(output_len - len(output))
            if not chunk:
                break
            output += chunk

        print("--- Output ---")
        print(output.decode())
        print("--------------")

except (ConnectionResetError, BrokenPipeError) as e:
    print(f"[CLIENT] Connection error: {e}")
except KeyboardInterrupt:
    print("\n[CLIENT] Disconnected.")
finally:
    ssl_sock.close()
