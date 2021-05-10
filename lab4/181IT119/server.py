import sys
import socket
import time

HOST = sys.argv[1]
PORT = int(sys.argv[2])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('', PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        print()
        for i in range(2):
            print("................. Round ", i + 1, " .................")
            print()
            print("Receiving public key...")
            n = conn.recv(1024).decode()
            if n == "Not in range":
                print("Secret not verified!")
                exit()
            n = int(n)
            print("Received n: ", n)
            v = int(conn.recv(1024).decode())
            print("Received v: ", v)

            print()

            c = int(input("Enter challenge, c: "))
            if c < 0 or c > 1:
                print("Error: c not 0 or 1.")
                exit()

            print()

            x = int(conn.recv(1024).decode())
            print("Received x: ", x)

            print()

            conn.send(str(c).encode())
            print("Sent c: ", c)
            time.sleep(1)

            print()

            y = int(conn.recv(1024).decode())
            print("Received y: ", y)

            print()

            print("Verifying secret...")

            temp1 = (y * y) % n
            temp2 = ((x % n) * ((v ** c) % n)) % n

            print("y^2 mod n = ", temp1)
            print("xv^c mod n = ", temp2)

            if temp1 == temp2:
                print("Since y^2 mod n = xv^c mod n, secret is verified!")
            else:
                print("Since y^2 mod n != xv^c mod n, secret cannot be verified!")

            print()
            print("Round ", i + 1, "Done")
            print()
