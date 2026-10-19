#!/usr/bin/env python3
"""lanchat - tiny encrypted 1:1 chat for two machines on the same network.

  host:  python3 lanchat.py -p "shared password"
  join:  python3 lanchat.py -p "shared password" -c <host-ip>
"""
import argparse
import getpass
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit import print_formatted_text as pft

DEFAULT_PORT = 5757
MAX_FRAME = 1 << 16
KDF_ITERS = 300_000
HOST_DIR, JOIN_DIR = b"H", b"J"

DIM, ME, PEER, WARN, OK = "#6c7086", "#89dceb bold", "#f5c2e7 bold", "#f9e2af", "#a6e3a1"


class Closed(Exception):
    pass


def out(*parts):
    pft(FormattedText(list(parts)))


def system(text, color=DIM):
    out((DIM, f"  {time.strftime('%H:%M')}  "), (color, f"· {text}"))


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise Closed
        buf += chunk
    return buf


def send_frame(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock):
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise Closed
    return recv_exact(sock, n)


class Channel:
    """AES-256-GCM channel. Key = PBKDF2(password, hostsalt+joinsalt), so every
    session gets a fresh key; direction byte is bound as AAD and a sequence
    number rejects replays/reordering."""

    def __init__(self, sock, password, is_host):
        self.sock, self.lock = sock, threading.Lock()
        mine = os.urandom(16)
        if is_host:
            send_frame(sock, mine)
            theirs = recv_frame(sock)
            salt = mine + theirs
        else:
            theirs = recv_frame(sock)
            send_frame(sock, mine)
            salt = theirs + mine
        if len(theirs) != 16:
            raise Closed
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, KDF_ITERS, 32)
        self.aes = AESGCM(key)
        self.send_dir, self.recv_dir = (HOST_DIR, JOIN_DIR) if is_host else (JOIN_DIR, HOST_DIR)
        self.send_seq = self.recv_seq = 0

    def send(self, obj):
        with self.lock:
            obj["q"] = self.send_seq
            self.send_seq += 1
            nonce = os.urandom(12)
            ct = self.aes.encrypt(nonce, json.dumps(obj).encode(), self.send_dir)
            send_frame(self.sock, nonce + ct)

    def recv(self):
        data = recv_frame(self.sock)
        try:
            obj = json.loads(self.aes.decrypt(data[:12], data[12:], self.recv_dir))
        except (InvalidTag, ValueError):
            raise ValueError("bad-auth")
        if obj.get("q") != self.recv_seq:
            raise ValueError("bad-seq")
        self.recv_seq += 1
        return obj


def connect(args):
    if args.connect:
        system(f"connecting to {args.connect}:{args.port} ...", WARN)
        sock = socket.create_connection((args.connect, args.port), timeout=10)
        sock.settimeout(None)
        return sock, False
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)
    system(f"waiting for your friend — tell them: -c {local_ip()}" + (f" --port {args.port}" if args.port != DEFAULT_PORT else ""), WARN)
    sock, addr = srv.accept()
    srv.close()
    return sock, True


def reader(ch, peer):
    try:
        while True:
            m = ch.recv()
            if m.get("t") == "msg":
                text = str(m.get("x", ""))
                out((DIM, f"  {time.strftime('%H:%M')}  "), (PEER, f"{peer['name']:<8} "), ("", text))
    except Closed:
        system(f"{peer['name']} disconnected")
    except ValueError:
        system("message failed authentication — wrong password or tampering. closing.", "#f38ba8")
    except OSError:
        system("connection lost")
    finally:
        os._exit(0)


def main():
    ap = argparse.ArgumentParser(description="Encrypted LAN chat for two people.")
    ap.add_argument("-p", "--password", default=os.environ.get("LANCHAT_PASSWORD"),
                    help="shared password (or env LANCHAT_PASSWORD; prompted if omitted)")
    ap.add_argument("-c", "--connect", metavar="IP", help="join a host at this IP (omit to host)")
    ap.add_argument("-n", "--name", default=os.environ.get("USER") or os.environ.get("USERNAME") or "me")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = ap.parse_args()
    password = args.password or getpass.getpass("password: ")
    name = args.name[:16]

    out((ME, "\n  lanchat"), (DIM, "  ·  end-to-end encrypted  ·  ctrl+c to quit\n"))
    try:
        sock, is_host = connect(args)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ch = Channel(sock, password, is_host)
        ch.send({"t": "hello", "n": name})
        hello = ch.recv()
        if hello.get("t") != "hello":
            raise ValueError
    except (OSError, Closed) as e:
        system(f"could not connect: {e or 'peer closed connection'}", "#f38ba8")
        sys.exit(1)
    except ValueError:
        system("handshake failed — passwords don't match.", "#f38ba8")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)

    peer = {"name": str(hello.get("n", "friend"))[:16]}
    system(f"connected to {peer['name']}", OK)
    out(("", "\n"))
    threading.Thread(target=reader, args=(ch, peer), daemon=True).start()

    session = PromptSession(erase_when_done=True)
    with patch_stdout(raw=True):
        while True:
            try:
                text = session.prompt(FormattedText([(DIM, "  ❯ ")])).strip()
            except (KeyboardInterrupt, EOFError):
                break
            if not text:
                continue
            try:
                ch.send({"t": "msg", "x": text})
            except OSError:
                system("connection lost")
                break
            out((DIM, f"  {time.strftime('%H:%M')}  "), (ME, f"{name:<8} "), ("", text))
    system("bye")


if __name__ == "__main__":
    main()
