import sys
import socket
import time

HOST = sys.argv[1]
PORT = int(sys.argv[2])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    print("Connected to ", (HOST, PORT))
    print()

    data = b''
    for i in range(2):
        print("................. Round ", i + 1, " .................")
        print()
        p = int(input("Enter prime number, p: "))
        q = int(input("Enter prime number, q: "))
        n = p * q

        r = int(input("Enter random number, r: "))
        if r < 0 or r >= n - 1:
            print("Error: r not in range.\n")
            sock.send("Not in range".encode())
            exit()

        s = int(input("Enter private key, s: "))
        if s < 1 or s > n - 1:
            print("Error: s not in range.\n")
            sock.send("Not in range".encode())
            exit()

        v = (s * s) % n

        print("Sending public key...")
        sock.send(str(n).encode())
        print("Sent n: ", n)
        time.sleep(1)
        sock.send(str(v).encode())
        print("Sent v: ", v)
        time.sleep(1)

        print()

        x = (r * r) % n
        sock.send(str(x).encode())
        print("Sent x: ", x)
        time.sleep(1)

        print()

        c = int(sock.recv(1024).decode())
        print("Received c: ", c)
        print()

        y = ((r % n) * ((s ** c) % n)) % n
        sock.send(str(y).encode())
        print("Sent y: ", y)
        time.sleep(1)

        print()
        print("Round ", i + 1, "Done")
        print()

