import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 4443))
print("fake-dest listening on 127.0.0.1:4443", flush=True)
while True:
    data, addr = s.recvfrom(65536)
    print(f"RELAYED {len(data)} bytes from {addr}", flush=True)
