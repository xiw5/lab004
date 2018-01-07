import socket
import logging
import struct
import select
import threading
import base64

def encryption(data):
    return base64.b64encode(data)

def decryption(data):
    return base64.b64decode(data)

def send_all(sock,data):
    send_bytes = 0
    while True:
        n = sock.send(data[send_bytes:])
        if n < 0:
            return n
        send_bytes += n
        if send_bytes == len(data):
            return send_bytes

def handle(client,remote):
    try:
        fdset = [client, remote]
        while True:
            r,w,e = select.select(fdset,[],[])

            if client in r:
                data = client.recv(1024)
                if len(data) <= 0:
                    break
                #data = decryption(data)
                result = send_all(remote,data)
                if result < len(data):
                    raise Exception('fail to send all data')

            if remote in r:
                data = remote.recv(1024)
                if len(data) <= 0:
                    break
                #data = encryption(data)
                result = send_all(client,data)
                if result < len(data):
                    raise Exception('fail to send all data')

    except Exception as e:
        raise(e)
    finally:
        client.close()
        remote.close()


def handle_connect(client,client_addr):
    data = client.recv(4)
    if data[1] != 1:
        client.close()
        return
    if data[3] == 1:
        addr_ip = client.recv(4)
        remote_addr = socket.inet_ntop(socket.AF_INET, addr_ip)
    elif data[3] == 3:
        blen = client.recv(1)
        addr_len = int.from_bytes(blen, byteorder = 'big')
        remote_addr = client.recv(addr_len)
    elif data[3] == 4:
        addr_ip = client.recv(16)
        remote_addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
    else:
        client.close()
        return
    bport = client.recv(2)
    remote_addr_port = struct.unpack('>H',bport)
    try:
        remote = socket.create_connection((remote_addr,remote_addr_port[0]))
        print("connect form ",remote_addr,remote_addr_port[0])
    except socket.error as e:
        client.close()
        logging.error(e)
        return

    handle(client,remote)

def main():
    agency_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    agency_server.bind(('',1234))
    agency_server.listen(15)
    agency_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        while True:
            c, addr = agency_server.accept()
            t = threading.Thread(target = handle_connect,args =(c,addr))
            t.start()
    except socket.error as e:
        logging.error(e)
    except KeyboardInterrupt:
        agency_server.close()

main()
