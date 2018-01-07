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
        if n <= 0:
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
                #data = encryption(data)
                result = send_all(remote,data)
                if result < len(data):
                    raise Exception('fail to send all data')

            if remote in r:
                data = remote.recv(1024)
                if len(data) <= 0:
                    break
                #print(data)
               # data = decryption(data)
                result = send_all(client,data)
                if result < len(data):
                    raise Exception('fail to send all data')

    except Exception as e:
        raise(e)
    finally:
        client.close()
        remote.close()


def handle_connect(client,client_addr):
    client.recv(256)
    client.send(b"\x05\x00")
    data = client.recv(4)
    try:
        server = socket.create_connection(('165.227.51.232',1234))
    except socket.error as e:
        client.close()
        print('remote fuck')
        logging.error(e)
        return
    #encode = encryption(data)
    #send_all(server,encode)
    print('remote success')
    send_all(server,data)
    if data[1] != 1:
        client.close()
        return
    if data[3] == 1:
        addr_ip = client.recv(4)
        #encode = encryption(addr_ip)
        #send_all(server,encode)
        send_all(server,addr_ip)
        remote_addr = socket.inet_ntop(socket.AF_INET, addr_ip)
    elif data[3] == 3:
        blen = client.recv(1)
        addr_len = int.from_bytes(blen, byteorder = 'big')
        #encode = encryption(blen)
        #send_all(server,encode)
        send_all(server,blen)
        remote_addr = client.recv(addr_len)
        #encode = encryption(remote_addr)
        #send_all(server,encode)
        send_all(server,remote_addr)

    elif data[3] == 4:
        addr_ip = client.recv(16)
        #encode = encryption(addr_ip)
        #send_all(server,encode)
        send_all(server,addr_ip)
        remote_addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
    else:
        client.close()
        return
    remote_addr_port = client.recv(2)
    #encode = encryption(remote_addr_port)
    #send_all(server,encode)
    send_all(server,remote_addr_port)
    reply = b'\x05\x00\x00\x01'
    reply += socket.inet_pton(socket.AF_INET,'0.0.0.0')+struct.pack('>H',7777)
    client.send(reply)
    handle(client,server)
    print('end')

def main():
    agency_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    agency_server.bind(('127.0.0.1',7777))
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
