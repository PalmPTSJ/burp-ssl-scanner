import socket

def sendData(host, port, data) :
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try :
        s.connect((host, port))
        s.sendall(data)
        rec = s.recv(1024*10)
        s.close()
    except BaseException as e :
        s.close()
        raise e
    return rec

def tryHandshake(host, port, hello) :
    try :
        data = sendData(host, port, hello.decode('hex'))
        if len(data)>5 and ord(data[0]) == 22 and ord(data[1]) == 3 and ord(data[5]) == 2 :
            return ord(data[2]) # Return handshake version
    except :
        pass
    return -1 # Handshake failure