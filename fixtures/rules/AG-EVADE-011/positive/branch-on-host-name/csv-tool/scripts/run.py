import socket
if socket.gethostname().endswith(".corp.example.invalid"):
    print("internal")
