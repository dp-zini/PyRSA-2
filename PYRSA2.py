import socket, threading, PySimpleGUI as sg, base64
from os import path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def gen_keys():
    priv = rsa.generate_private_key(65537, 2048, default_backend())
    return priv.public_key(), priv

def save_keys(pub, priv, pwd):
    open("public_key.pem", "wb").write(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    open("private_key.pem", "wb").write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(pwd.encode())))

def load_keys(pwd):
    pub = serialization.load_pem_public_key(open("public_key.pem", "rb").read(), default_backend())
    priv = serialization.load_pem_private_key(open("private_key.pem", "rb").read(), pwd.encode(), default_backend())
    return pub, priv

def encrypt_decrypt(key, msg, enc=True):
    pad = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    if enc:
        return b"".join([key.encrypt(msg[i:i+190].encode(), pad) for i in range(0, len(msg), 190)])
    return b"".join([key.decrypt(msg[i:i+256], pad) for i in range(0, len(msg), 256)]).decode()

def handle_client(sock, priv, win):
    while True:
        try:
            data = sock.recv(1024)
            if data: win.write_event_value('MSG', encrypt_decrypt(priv, data, enc=False))
        except: break

def start_server(port, pub, priv, win):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", port)); s.listen(1)
    win.write_event_value('SRV', f"listening on {port}")
    conn, addr = s.accept()
    peer_key = serialization.load_pem_public_key(conn.recv(1024), default_backend())
    conn.send(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    win.write_event_value('CON', f"connected to {addr}")
    threading.Thread(target=handle_client, args=(conn, priv, win), daemon=True).start()
    return conn, peer_key

def connect_peer(host, port, pub, win):
    s = socket.socket(); s.connect((host, port))
    s.send(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    peer_key = serialization.load_pem_public_key(s.recv(1024), default_backend())
    win.write_event_value('PEER', f"connected to {host}:{port}")
    return s, peer_key

def main():
    sg.theme('DarkBlack')
    layout = [[sg.Text('key stuff:'), sg.Combo(['generate', 'save', 'load'], key='OPT', readonly=True), sg.Button('execute')],
              [sg.Text('host port:'), sg.Input(key='PORT', size=(15, 1)), sg.Button('listen')],
              [sg.Text('peer IP:'), sg.Input(key='IP', size=(15, 1)), sg.Text('port:'), sg.Input(key='PPORT', size=(15, 1)), sg.Button('connect')],
              [sg.Output(size=(70, 10), key='OUT')], [sg.Input(key='MSG', size=(60, 1)), sg.Button('Send')]]
    win = sg.Window('PyRSA 2: Electric Boogaloo', layout, resizable=True, finalize=True)
    pub, priv, peer_key, conn = None, None, None, None

    while True:
        evt, vals = win.read()
        if evt == sg.WINDOW_CLOSED: break
        if evt == 'execute':
            opt = vals['OPT']
            if opt == 'generate': pub, priv = gen_keys(); print("keys generated")
            elif opt == 'save' and pub and priv: save_keys(pub, priv, sg.popup_get_text('passphrase:', password_char='*'))
            elif opt == 'load':
                try: pub, priv = load_keys(sg.popup_get_text('passphrase:', password_char='*')); print("keys loaded")
                except: print("error loading keys, start over man idk what to tell ya")
        if evt == 'listen' and pub and priv:
            threading.Thread(target=start_server, args=(int(vals['PORT']), pub, priv, win), daemon=True).start()
        if evt == 'connect' and pub:
            conn, peer_key = connect_peer(vals['IP'], int(vals['PPORT']), pub, win)
        if evt == 'send' and conn and peer_key:
            msg = vals['MSG']; conn.send(encrypt_decrypt(peer_key, msg)); print(f"you: {msg}"); win['MSG'].update("")
        if evt in ['MSG', 'SRV', 'CON', 'PEER']: print(vals[evt])

    win.close()

if __name__ == "__main__": main()
