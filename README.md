Secure Remote Command Execution System
A multi-client client-server system that allows secure remote command execution over an encrypted SSL/TLS connection.
Team: K C Nandan (AM072), Asha (AM030), Aishwarya A (AM001)  
Section: A (AIML)  
Subject: Computer Networks
---
Overview
This system allows authenticated clients to send shell commands to a remote server and receive the output securely. It addresses three core problems in remote execution systems:
Unauthorized access — handled via credential-based authentication with hashed passwords
Data interception — handled via SSL/TLS encryption over TCP
Lack of monitoring — handled via server-side activity logging
---
Architecture
Multi-client Client-Server architecture
Protocol: TCP (reliable, ordered, error-checked delivery)
Encryption: SSL/TLS with self-signed certificate
Server: Python — handles up to 10 concurrent clients via threading
Client: Python — raw socket + SSL connection
---
Project Structure
```
CN-Project/
├── server.py            # Server — socket, SSL, threading, auth, logging
├── client.py            # Client — socket, SSL, auth, command loop
├── performance_test.py  # Performance evaluation script
├── server.crt           # SSL certificate (generate locally, see setup)
├── server.key           # SSL private key (generate locally, see setup)
├── server.log           # Activity log (auto-created on first run)
└── README.md            # This file
```
---
Setup Instructions
Prerequisites
Python 3.x (standard library only, no pip installs needed)
OpenSSL (for generating SSL certificate)
Step 1: Generate SSL Certificate
Run this once in the project folder using the OpenSSL command prompt:
```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
```
Step 2: Run the Server
```bash
python server.py
```
Expected output:
```
[SERVER] Listening on 0.0.0.0:8443 (SSL enabled)
[LOG] Server started on 0.0.0.0:8443
```
Step 3: Run the Client
For same machine:
```bash
python client.py
```
For different machine on same network:
Open `client.py`
Change `SERVER_IP = '127.0.0.1'` to the server's IPv4 address
Run `python client.py`
---
Valid Credentials
Username	Password
admin	Admin@1234
user1	User1@5678
user2	User2@9999
Passwords are stored as SHA-256 hashes on the server. Plaintext passwords are never stored.
---
Password Complexity Rules
All passwords must meet these requirements:
Minimum 8 characters
At least one uppercase letter
At least one lowercase letter
At least one digit
At least one special character (`!@#$%^&*` etc.)
---
Security Features
Feature	Implementation
Encryption	SSL/TLS wrapping raw TCP socket
Authentication	Username + password verified against SHA-256 hashes
Password security	Complexity rules enforced + hashed storage
Activity logging	All connections, auth attempts, commands logged to server.log
Connection limit	Max 10 concurrent clients enforced
Timeout	Commands timeout after 10 seconds
---
Log Format
All activity is written to `server.log`:
```
2026-03-12 10:00:01 | Server started on 0.0.0.0:8443
2026-03-12 10:00:03 | New connection from 192.168.1.5:54321
2026-03-12 10:00:05 | AUTH SUCCESS for user 'admin' from 192.168.1.5
2026-03-12 10:00:07 | User 'admin' from 192.168.1.5 executed: whoami
2026-03-12 10:00:10 | Connection closed for 192.168.1.5
```
---
Performance Evaluation
Run the performance test script (server must be running):
```bash
python performance_test.py
```
Tests conducted:
Connection + authentication latency
Command response time
Throughput (commands per second)
Concurrent client handling
---
Error Handling
Scenario	Handling
Wrong credentials	AUTH_FAIL sent, connection closed
Weak password	Rejected before credential check
Abrupt client disconnect	Caught, logged, thread exits cleanly
SSL handshake failure	Caught, logged, server continues
Command timeout	Error message returned to client
Invalid input encoding	Caught, client notified
Server full	New connection rejected with message
