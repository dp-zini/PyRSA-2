import socket, threading, kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.clock import Clock
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup
from kivy.graphics import Color, RoundedRectangle
from kivy.metrics import dp
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def gen_keys():
    p = rsa.generate_private_key(65537, 2048, default_backend())
    return p.public_key(), p

def save_keys(pu, pr, pw):
    open("public_key.pem", "wb").write(pu.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    open("private_key.pem", "wb").write(pr.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(pw.encode())))

def load_keys(pw):
    pu = serialization.load_pem_public_key(
        open("public_key.pem", "rb").read(), default_backend())
    pr = serialization.load_pem_private_key(
        open("private_key.pem", "rb").read(), pw.encode(), default_backend())
    return pu, pr

def encrypt_decrypt(k, m, e=1):
    p = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    return b"".join([
        k.encrypt(m[i:i+190].encode(), p) if e else k.decrypt(m[i:i+256], p)
        for i in range(0, len(m), 190 if e else 256)]).decode() if not e else b"".join([
        k.encrypt(m[i:i+190].encode(), p) for i in range(0, len(m), 190)])

def handle_client(s, p, a):
    while True:
        try:
            d = s.recv(1024)
            Clock.schedule_once(lambda dt: a.add_message(encrypt_decrypt(p, d, 0), 1)) if d else None
        except:
            break

def start_server(port, pub, priv, app):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        port = int(port)
    except ValueError:
        return
    s.bind(("", port))
    s.listen(1)
    Clock.schedule_once(lambda dt: app.add_system_message(f"Listening on {port}"))
    c, a = s.accept()
    pk = serialization.load_pem_public_key(c.recv(1024), default_backend())
    c.send(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    Clock.schedule_once(lambda dt: app.add_system_message(f"Connected to {a}"))
    threading.Thread(target=handle_client, args=(c, priv, app), daemon=1).start()
    return c, pk

def connect_peer(h, p, pu, a):
    s = socket.socket()
    try:
        p = int(p)
    except ValueError:
        return
    s.connect((h, p))
    s.send(pu.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    pk = serialization.load_pem_public_key(s.recv(1024), default_backend())
    Clock.schedule_once(lambda dt: a.add_system_message(f"Connected to {h}:{p}"))
    return s, pk

class MessageBubble(BoxLayout):
    def __init__(s, t, ip=0, is_=0, **k):
        super().__init__(**k)
        s.size_hint_y = None
        s.padding = dp(10)
        s.spacing = dp(5)
        w = dp(250)
        s.size_hint_x = None
        s.pos_hint = {"center_x": 0.5} if is_ else {"x": 0} if ip else {"right": 1}
        with s.canvas.before:
            Color(*(0.6, 0.6, 0.6, 0.25) if is_ else (0.9, 0.9, 0.9, 0.5) if ip else (0.4157, 0, 0.5333, 0.5))
            s.rect = RoundedRectangle(size=s.size, pos=s.pos, radius=[dp(10)])
        s.bind(pos=s.update_rect, size=s.update_rect)
        s.label = Label(
            text=t, size_hint=(None, None), halign="left", valign="middle",
            text_size=(w-dp(20), None), color=(1, 1, 1, 1))
        s.label.bind(texture_size=s._adjust_bubble_size)
        s.add_widget(s.label)

    def _adjust_bubble_size(s, *_):
        s.label.size = s.label.texture_size
        s.width = min(s.label.texture_size[0]+dp(20), dp(250))
        s.height = s.label.texture_size[1]+dp(20)

    def update_rect(s, *_):
        s.rect.size = s.size
        s.rect.pos = s.pos

class PassphrasePopup(Popup):
    def __init__(s, t, cb, **k):
        super().__init__(**k)
        s.title = t
        s.size_hint = (0.8, 0.4)
        l = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(10))
        s.input = TextInput(hint_text="Enter passphrase", multiline=0, password=1)
        l.add_widget(s.input)
        b = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        b.add_widget(Button(text="OK", on_press=lambda x: s._on_submit(cb)))
        b.add_widget(Button(text="Cancel", on_press=s.dismiss))
        l.add_widget(b)
        s.content = l

    def _on_submit(s, cb):
        cb(s.input.text)
        s.dismiss()

class PyRSAApp(App):
    def build(s):
        s.pub, s.priv, s.peer_key, s.conn = None, None, None, None
        l = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(10))
        kl = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        [kl.add_widget(Button(text=i, size_hint_x=0.33, on_press=s.show_save_passphrase if "Save" in i else s.show_load_passphrase if "Load" in i else s.generate_keys)) for i in ("Generate Keys", "Save Keys", "Load Keys")]
        l.add_widget(kl)
        cl = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        s.port_input, s.ip_input, s.peer_port_input = [TextInput(hint_text=i, multiline=0, size_hint_x=(0.2 if "Port" in i else 0.3)) for i in ("Port", "IP", "Port")]
        cl.add_widget(s.port_input)
        cl.add_widget(Button(text="Listen", size_hint_x=0.3, on_press=s.listen_server))
        cl.add_widget(s.ip_input)
        cl.add_widget(s.peer_port_input)
        cl.add_widget(Button(text="Connect", size_hint_x=0.3, on_press=s.connect_peer))
        l.add_widget(cl)
        s.message_area = ScrollView(size_hint=(1, 0.6))
        s.message_layout = BoxLayout(orientation="vertical", size_hint_y=None, padding=dp(10), spacing=dp(5))
        s.message_layout.bind(minimum_height=s.message_layout.setter("height"))
        s.message_area.add_widget(s.message_layout)
        l.add_widget(s.message_area)
        ml = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        s.msg_input = TextInput(hint_text="Message", multiline=0, size_hint_x=0.7)
        s.msg_input.bind(on_text_validate=s.send_message)
        ml.add_widget(s.msg_input)
        ml.add_widget(Button(text="Send", size_hint_x=0.3, on_press=s.send_message))
        l.add_widget(ml)
        return l

    def show_save_passphrase(s, _): PassphrasePopup("Save Keys", s.save_keys).open()
    def show_load_passphrase(s, _): PassphrasePopup("Load Keys", s.load_keys).open()
    def generate_keys(s, _): s.pub, s.priv = gen_keys(); s.add_system_message("Keys generated.")
    def save_keys(s, p): save_keys(s.pub, s.priv, p); s.add_system_message("Keys saved.")
    def load_keys(s, p):
        try: s.pub, s.priv = load_keys(p); s.add_system_message("Keys loaded.")
        except: s.add_system_message("Error loading keys.")
    def listen_server(s, _):
        try:
            port = int(s.port_input.text)
            threading.Thread(target=start_server, args=(port, s.pub, s.priv, s), daemon=1).start()
        except ValueError:
            s.add_system_message("Use a number.")

    def connect_peer(s, _):
        try:
            port = int(s.peer_port_input.text)
            s.conn, s.peer_key = connect_peer(s.ip_input.text, port, s.pub, s)
        except ValueError:
            s.add_system_message("Use a number.")

    def send_message(s, _): s.conn.send(encrypt_decrypt(s.peer_key, s.msg_input.text)); s.add_message(s.msg_input.text, 0); s.msg_input.text=""
    def add_message(s, t, ip=0): s.message_layout.add_widget(MessageBubble(t, ip))
    def add_system_message(s, t): s.message_layout.add_widget(MessageBubble(t, 0, 1))

PyRSAApp().run()
