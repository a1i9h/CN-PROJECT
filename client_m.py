import socket
import ssl

# ─── Configuration ────────────────────────────────────────────────────────────
SERVER_IP   = '127.0.0.1'   # Change to server's IP when running on separate machines
SERVER_PORT = 8443

def main():
    # ── Step 1: Create raw TCP socket ────────────────────────────────────────
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # ── Step 2: Wrap with SSL ─────────────────────────────────────────────────
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode    = ssl.CERT_NONE      # Accept self-signed certificate

    ssl_sock = context.wrap_socket(raw_sock, server_hostname=SERVER_IP)

    # ── Step 3: Connect ───────────────────────────────────────────────────────
    try:
        ssl_sock.connect((SERVER_IP, SERVER_PORT))
    except ConnectionRefusedError:
        print(f"ERROR: Could not connect to {SERVER_IP}:{SERVER_PORT}. Is the server running?")
        return
    except ssl.SSLError as e:
        print(f"ERROR: SSL handshake failed: {e}")
        return
    except OSError as e:
        print(f"ERROR: Network error: {e}")
        return

    print(f"[CLIENT] Connected to {SERVER_IP}:{SERVER_PORT} (SSL enabled)")
    print(f"[CLIENT] Cipher in use: {ssl_sock.cipher()[0]}")
    print()

    try:
        # ── Step 4: Authentication ────────────────────────────────────────────
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
            return

        # ── Step 5: Command Loop ──────────────────────────────────────────────
        while True:
            try:
                prompt = ssl_sock.recv(1024).decode()
                if not prompt:
                    print("[CLIENT] Server closed the connection.")
                    break
                print(prompt, end='')

                command = input()
                ssl_sock.sendall(command.encode())

                if command.lower() == 'exit':
                    response = ssl_sock.recv(1024).decode()
                    print(response)
                    break

                if not command.strip():
                    continue

                # ── Step 6: Receive length-prefixed output ────────────────────
                length_line = b''
                while not length_line.endswith(b'\n'):
                    chunk = ssl_sock.recv(1)
                    if not chunk:
                        raise ConnectionResetError("Server disconnected")
                    length_line += chunk

                output_len = int(length_line.decode().strip())

                if output_len == 0:
                    continue

                output = b''
                while len(output) < output_len:
                    chunk = ssl_sock.recv(output_len - len(output))
                    if not chunk:
                        raise ConnectionResetError("Server disconnected mid-transfer")
                    output += chunk

                print("--- Output ---")
                print(output.decode())
                print("--------------")

            except (ConnectionResetError, BrokenPipeError):
                print("[CLIENT] Server disconnected abruptly.")
                break

            except UnicodeDecodeError:
                print("[CLIENT] Received unreadable data from server.")
                continue

            except ValueError:
                print("[CLIENT] Received malformed response from server.")
                break

    except ssl.SSLError as e:
        print(f"[CLIENT] SSL error: {e}")

    except (ConnectionResetError, BrokenPipeError):
        print("[CLIENT] Connection lost.")

    except KeyboardInterrupt:
        print("\n[CLIENT] Disconnected by user.")

    finally:
        try:
            ssl_sock.close()
        except:
            pass
        print("[CLIENT] Connection closed.")

if __name__ == '__main__':
    main()