"""
Performance Evaluation Script
Secure Remote Command Execution System

Tests:
1. Response time per command
2. Latency (connection + auth time)
3. Throughput (commands per second)
4. Concurrent client handling (scalability)

Run this AFTER server.py is running.
"""

import socket
import ssl
import time
import threading
import statistics

SERVER_IP   = '127.0.0.1'
SERVER_PORT = 8443
USERNAME    = 'admin'
PASSWORD    = 'Admin@1234'

# ─── Helper: Create SSL connection ───────────────────────────────────────────
def create_connection():
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    ssl_sock = context.wrap_socket(raw_sock, server_hostname=SERVER_IP)
    ssl_sock.connect((SERVER_IP, SERVER_PORT))
    return ssl_sock

# ─── Helper: Authenticate ────────────────────────────────────────────────────
def authenticate(ssl_sock):
    ssl_sock.recv(1024)  # USERNAME prompt
    ssl_sock.sendall(USERNAME.encode())
    ssl_sock.recv(1024)  # PASSWORD prompt
    ssl_sock.sendall(PASSWORD.encode())
    response = ssl_sock.recv(1024).decode()
    return response.startswith("AUTH_OK")

# ─── Helper: Send one command and get output ─────────────────────────────────
def send_command(ssl_sock, command):
    ssl_sock.recv(1024)  # CMD> prompt
    ssl_sock.sendall(command.encode())

    length_line = b''
    while not length_line.endswith(b'\n'):
        length_line += ssl_sock.recv(1)
    output_len = int(length_line.decode().strip())

    output = b''
    while len(output) < output_len:
        chunk = ssl_sock.recv(output_len - len(output))
        if not chunk:
            break
        output += chunk
    return output.decode()

# ─── Test 1: Connection + Auth Latency ───────────────────────────────────────
def test_connection_latency(runs=5):
    print("\n" + "="*50)
    print("TEST 1: Connection + Authentication Latency")
    print("="*50)
    times = []
    for i in range(runs):
        start = time.time()
        ssl_sock = create_connection()
        auth_ok = authenticate(ssl_sock)
        end = time.time()
        latency = (end - start) * 1000  # ms
        times.append(latency)
        ssl_sock.recv(1024)  # CMD> prompt
        ssl_sock.sendall(b'exit')
        ssl_sock.recv(1024)
        ssl_sock.close()
        print(f"  Run {i+1}: {latency:.2f} ms — Auth: {'OK' if auth_ok else 'FAIL'}")

    print(f"\n  Min:    {min(times):.2f} ms")
    print(f"  Max:    {max(times):.2f} ms")
    print(f"  Avg:    {statistics.mean(times):.2f} ms")
    print(f"  StdDev: {statistics.stdev(times):.2f} ms")
    return times

# ─── Test 2: Command Response Time ───────────────────────────────────────────
def test_response_time(commands=None, runs=5):
    print("\n" + "="*50)
    print("TEST 2: Command Response Time")
    print("="*50)

    if commands is None:
        commands = ['echo hello', 'whoami', 'hostname']

    ssl_sock = create_connection()
    authenticate(ssl_sock)

    for cmd in commands:
        times = []
        for _ in range(runs):
            ssl_sock.recv(1024)  # CMD> prompt
            start = time.time()
            ssl_sock.sendall(cmd.encode())

            length_line = b''
            while not length_line.endswith(b'\n'):
                length_line += ssl_sock.recv(1)
            output_len = int(length_line.decode().strip())

            output = b''
            while len(output) < output_len:
                chunk = ssl_sock.recv(output_len - len(output))
                if not chunk:
                    break
                output += chunk
            end = time.time()
            times.append((end - start) * 1000)

        print(f"\n  Command: '{cmd}'")
        print(f"  Avg response time: {statistics.mean(times):.2f} ms")
        print(f"  Min: {min(times):.2f} ms | Max: {max(times):.2f} ms")

    ssl_sock.recv(1024)
    ssl_sock.sendall(b'exit')
    ssl_sock.close()

# ─── Test 3: Throughput ───────────────────────────────────────────────────────
def test_throughput(duration_seconds=10):
    print("\n" + "="*50)
    print(f"TEST 3: Throughput (commands over {duration_seconds}s)")
    print("="*50)

    ssl_sock = create_connection()
    authenticate(ssl_sock)

    count = 0
    start = time.time()
    while time.time() - start < duration_seconds:
        ssl_sock.recv(1024)  # CMD> prompt
        ssl_sock.sendall(b'echo test')
        length_line = b''
        while not length_line.endswith(b'\n'):
            length_line += ssl_sock.recv(1)
        output_len = int(length_line.decode().strip())
        output = b''
        while len(output) < output_len:
            output += ssl_sock.recv(output_len - len(output))
        count += 1

    elapsed = time.time() - start
    throughput = count / elapsed

    ssl_sock.recv(1024)
    ssl_sock.sendall(b'exit')
    ssl_sock.close()

    print(f"  Commands executed: {count}")
    print(f"  Time elapsed:      {elapsed:.2f}s")
    print(f"  Throughput:        {throughput:.2f} commands/second")
    return throughput

# ─── Test 4: Concurrent Clients ──────────────────────────────────────────────
def test_concurrent_clients(num_clients=5):
    print("\n" + "="*50)
    print(f"TEST 4: Concurrent Clients ({num_clients} simultaneous)")
    print("="*50)

    results = []
    lock = threading.Lock()

    def client_task(client_id):
        try:
            start = time.time()
            ssl_sock = create_connection()
            authenticate(ssl_sock)
            ssl_sock.recv(1024)  # CMD> prompt
            ssl_sock.sendall(b'whoami')

            length_line = b''
            while not length_line.endswith(b'\n'):
                length_line += ssl_sock.recv(1)
            output_len = int(length_line.decode().strip())
            output = b''
            while len(output) < output_len:
                output += ssl_sock.recv(output_len - len(output))

            ssl_sock.recv(1024)
            ssl_sock.sendall(b'exit')
            ssl_sock.recv(1024)
            ssl_sock.close()
            end = time.time()

            with lock:
                results.append((client_id, (end - start) * 1000, True))
                print(f"  Client {client_id}: completed in {(end-start)*1000:.2f} ms")

        except Exception as e:
            with lock:
                results.append((client_id, 0, False))
                print(f"  Client {client_id}: FAILED — {e}")

    threads = []
    overall_start = time.time()
    for i in range(1, num_clients + 1):
        t = threading.Thread(target=client_task, args=(i,))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    overall_end = time.time()
    successful = sum(1 for _, _, ok in results if ok)
    print(f"\n  Successful: {successful}/{num_clients}")
    print(f"  Total wall time: {(overall_end - overall_start)*1000:.2f} ms")

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("Secure Remote Command Execution System")
    print("Performance Evaluation")
    print("Make sure server.py is running before proceeding.\n")

    test_connection_latency(runs=5)
    test_response_time(runs=5)
    test_throughput(duration_seconds=10)
    test_concurrent_clients(num_clients=5)

    print("\n" + "="*50)
    print("Performance evaluation complete.")
    print("Record these results for your report.")
    print("="*50)
