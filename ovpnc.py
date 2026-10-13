#!/usr/bin/env python3
"""
ovpnc - cliente OpenVPN escrito do zero.

Sem dependências externas: usa só a biblioteca padrão do Python e a
CommonCrypto do macOS (via ctypes) para AES.

Implementa:
  * tls-auth (HMAC no canal de controle, key-direction)
  * camada de confiabilidade do canal de controle (ids, ACKs, retransmissão)
  * TLS do canal de controle via ssl.MemoryBIO (cert de cliente, verify-x509-name,
    remote-cert-tls server)
  * key-method 2 + auth-user-pass + derivação de chaves (PRF TLS 1.0 do OpenVPN)
  * PUSH_REQUEST / PUSH_REPLY (NCP: cipher, peer-id, ifconfig, rotas, DNS ...)
  * canal de dados AES-GCM (P_DATA_V1/V2) e AES-CBC + HMAC
  * interface utun, rotas, DNS por domínio (scutil), ping/ping-restart,
    renegociação (soft reset), explicit-exit-notify, reconexão

Uso:
  python3 ovpnc.py config.ovpn --test     # só testa o handshake TLS (sem root)
  sudo python3 ovpnc.py config.ovpn       # conecta
"""

import argparse
import ctypes
import fcntl
import getpass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import select
import shlex
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque

log = logging.getLogger('ovpnc')

# --------------------------------------------------------------------------
# Constantes do protocolo
# --------------------------------------------------------------------------

P_CONTROL_HARD_RESET_CLIENT_V1 = 1
P_CONTROL_HARD_RESET_SERVER_V1 = 2
P_CONTROL_SOFT_RESET_V1 = 3
P_CONTROL_V1 = 4
P_ACK_V1 = 5
P_DATA_V1 = 6
P_CONTROL_HARD_RESET_CLIENT_V2 = 7
P_CONTROL_HARD_RESET_SERVER_V2 = 8
P_DATA_V2 = 9

RESET_OPS = {P_CONTROL_HARD_RESET_CLIENT_V1, P_CONTROL_HARD_RESET_SERVER_V1,
             P_CONTROL_SOFT_RESET_V1, P_CONTROL_HARD_RESET_CLIENT_V2,
             P_CONTROL_HARD_RESET_SERVER_V2}

PING_MAGIC = bytes.fromhex('2a187bf3641eb4cb07ed2d0a981fc748')
OCC_MAGIC = bytes.fromhex('287f346bd4ef7a812d56b8d3afc5459c')
OCC_EXIT = 6

CTL_MAX_PAYLOAD = 1100     # fragmento máximo de TLS por pacote de controle
RELIABLE_SEND_WINDOW = 4
RELIABLE_RECV_WINDOW = 8
MAX_ACKS_PER_PACKET = 8
HAND_WINDOW = 60
TRANSITION_WINDOW = 60

SUPPORTED_CIPHERS = ('AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM',
                     'AES-256-CBC', 'AES-192-CBC', 'AES-128-CBC')

VERSION = '0.1'


_json_events = False


def emit(event, **kw):
    """Evento legível por máquina (stdout, uma linha JSON) para o app."""
    if _json_events:
        kw['event'] = event
        sys.stdout.write(json.dumps(kw) + '\n')
        sys.stdout.flush()


class SessionError(Exception):
    """Erro recuperável: derruba a sessão e reconecta."""


class FatalError(Exception):
    """Erro não recuperável (ex.: AUTH_FAILED)."""


# --------------------------------------------------------------------------
# Leitura do .ovpn
# --------------------------------------------------------------------------

class Config:
    def __init__(self, path):
        self.path = path
        self.directives = {}
        self.inline = {}
        with open(path) as f:
            lines = f.read().splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            i += 1
            if not line or line[0] in '#;':
                continue
            m = re.match(r'^<([\w-]+)>$', line)
            if m:
                tag, body = m.group(1), []
                while i < len(lines) and lines[i].strip() != '</%s>' % tag:
                    body.append(lines[i])
                    i += 1
                i += 1
                self.inline[tag] = '\n'.join(body) + '\n'
                continue
            parts = shlex.split(line, comments=False)
            self.directives.setdefault(parts[0], []).append(parts[1:])

    def get(self, name, default=None):
        v = self.directives.get(name)
        return v[-1] if v else default

    def has(self, name):
        return name in self.directives

    def blob(self, name):
        """Conteúdo inline (<ca>...</ca>) ou de arquivo referenciado."""
        if name in self.inline:
            return self.inline[name]
        args = self.get(name)
        if args and args[0] != '[inline]':
            p = os.path.join(os.path.dirname(os.path.abspath(self.path)), args[0])
            with open(p) as f:
                return f.read()
        return None

    @property
    def remote(self):
        args = self.get('remote')
        if not args:
            raise FatalError('diretiva "remote" ausente no .ovpn')
        host = args[0]
        port = int(args[1]) if len(args) > 1 else int((self.get('port') or ['1194'])[0])
        proto = args[2] if len(args) > 2 else (self.get('proto') or ['udp'])[0]
        if not proto.startswith('udp'):
            raise FatalError('apenas UDP é suportado (proto=%s)' % proto)
        return host, port

    @property
    def auth_digest(self):
        return (self.get('auth') or ['SHA1'])[0].lower().replace('-', '')

    @property
    def key_direction(self):
        ta = self.get('tls-auth')
        if ta and len(ta) > 1:
            return int(ta[1])
        kd = self.get('key-direction')
        return int(kd[0]) if kd else None

    @property
    def data_ciphers(self):
        dc = self.get('data-ciphers') or self.get('ncp-ciphers')
        names = dc[0].split(':') if dc else ['AES-256-GCM', 'AES-128-GCM']
        return [c.upper() for c in names if c.upper() in SUPPORTED_CIPHERS]

    @property
    def fallback_cipher(self):
        fb = self.get('data-ciphers-fallback') or self.get('cipher')
        return fb[0].upper() if fb else 'BF-CBC'


# --------------------------------------------------------------------------
# Criptografia
# --------------------------------------------------------------------------

_cc = ctypes.CDLL('/usr/lib/system/libcommonCrypto.dylib')
_vp, _sz = ctypes.c_void_p, ctypes.c_size_t
_cc.CCCryptorGCMOneshotEncrypt.argtypes = [ctypes.c_uint32, _vp, _sz, _vp, _sz, _vp, _sz,
                                           _vp, _sz, _vp, _vp, _sz]
_cc.CCCryptorGCMOneshotEncrypt.restype = ctypes.c_int32
_cc.CCCryptorGCMOneshotDecrypt.argtypes = [ctypes.c_uint32, _vp, _sz, _vp, _sz, _vp, _sz,
                                           _vp, _sz, _vp, _vp, _sz]
_cc.CCCryptorGCMOneshotDecrypt.restype = ctypes.c_int32
_cc.CCCrypt.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, _vp, _sz, _vp,
                        _vp, _sz, _vp, _sz, ctypes.POINTER(_sz)]
_cc.CCCrypt.restype = ctypes.c_int32
kCCAlgorithmAES = 0
kCCEncrypt, kCCDecrypt = 0, 1
kCCOptionPKCS7Padding = 1


def gcm_encrypt(key, iv, aad, pt):
    out = ctypes.create_string_buffer(max(len(pt), 1))
    tag = ctypes.create_string_buffer(16)
    st = _cc.CCCryptorGCMOneshotEncrypt(kCCAlgorithmAES, key, len(key), iv, len(iv),
                                        aad, len(aad), pt, len(pt), out, tag, 16)
    if st != 0:
        raise SessionError('AES-GCM encrypt falhou (%d)' % st)
    return out.raw[:len(pt)], tag.raw


def gcm_decrypt(key, iv, aad, ct, tag):
    out = ctypes.create_string_buffer(max(len(ct), 1))
    st = _cc.CCCryptorGCMOneshotDecrypt(kCCAlgorithmAES, key, len(key), iv, len(iv),
                                        aad, len(aad), ct, len(ct), out, tag, 16)
    return out.raw[:len(ct)] if st == 0 else None


def aes_cbc(op, key, iv, data):
    cap = len(data) + 16
    out = ctypes.create_string_buffer(cap)
    moved = _sz(0)
    st = _cc.CCCrypt(op, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, len(key), iv,
                     data, len(data), out, cap, ctypes.byref(moved))
    return out.raw[:moved.value] if st == 0 else None


def _p_hash(name, secret, seed, n):
    out, a = b'', seed
    while len(out) < n:
        a = hmac.new(secret, a, name).digest()
        out += hmac.new(secret, a + seed, name).digest()
    return out[:n]


def tls1_prf(secret, seed, n):
    """PRF do TLS 1.0 (MD5 xor SHA1), usada pelo OpenVPN sem tls-ekm."""
    half = (len(secret) + 1) // 2
    s1, s2 = secret[:half], secret[len(secret) // 2:len(secret) // 2 + half]
    a, b = _p_hash('md5', s1, seed, n), _p_hash('sha1', s2, seed, n)
    return bytes(x ^ y for x, y in zip(a, b))


def parse_static_key(text):
    hexs, inside = [], False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('-----BEGIN'):
            inside = True
        elif line.startswith('-----END'):
            break
        elif inside and line and not line.startswith('#'):
            hexs.append(line)
    key = bytes.fromhex(''.join(hexs))
    if len(key) != 256:
        raise FatalError('chave estática tls-auth inválida (%d bytes)' % len(key))
    return key


class TlsAuth:
    """HMAC do canal de controle (--tls-auth)."""

    def __init__(self, static_key, direction, digest):
        self.digest = digest
        self.dlen = hashlib.new(digest).digest_size
        # static key = keys[0]{cipher[64], hmac[64]}, keys[1]{cipher[64], hmac[64]}
        hmac0, hmac1 = static_key[64:128], static_key[192:256]
        if direction is None:
            out_k, in_k = hmac0, hmac0
        elif direction == 1:
            out_k, in_k = hmac1, hmac0
        else:
            out_k, in_k = hmac0, hmac1
        self.out_key, self.in_key = out_k[:self.dlen], in_k[:self.dlen]
        self.pid = 0

    def wrap(self, op_byte, sid, body):
        self.pid += 1
        pidtime = struct.pack('>II', self.pid, int(time.time()))
        head = bytes([op_byte]) + sid
        mac = hmac.new(self.out_key, pidtime + head + body, self.digest).digest()
        return head + mac + pidtime + body

    def unwrap(self, pkt):
        d = self.dlen
        if len(pkt) < 9 + d + 8 + 1:
            return None
        head, mac = pkt[:9], pkt[9:9 + d]
        pidtime, body = pkt[9 + d:17 + d], pkt[17 + d:]
        calc = hmac.new(self.in_key, pidtime + head + body, self.digest).digest()
        if not hmac.compare_digest(mac, calc):
            return None
        return pkt[1:9], body


class NoTlsAuth:
    def wrap(self, op_byte, sid, body):
        return bytes([op_byte]) + sid + body

    def unwrap(self, pkt):
        return (pkt[1:9], pkt[9:]) if len(pkt) >= 10 else None


# --------------------------------------------------------------------------
# Canal de dados
# --------------------------------------------------------------------------

class DataChannel:
    def __init__(self, cipher, digest, keyblock, key_id, peer_id, swapped=False):
        m = re.match(r'AES-(\d+)-(GCM|CBC)$', cipher)
        if not m:
            raise FatalError('cipher de dados não suportado: %s' % cipher)
        self.cipher = cipher
        self.klen = int(m.group(1)) // 8
        self.aead = m.group(2) == 'GCM'
        self.digest = digest
        self.dlen = hashlib.new(digest).digest_size
        self.key_id = key_id
        self.peer_id = peer_id
        # key2 = keys[0]{cipher, hmac}, keys[1]{cipher, hmac}; cliente = direção normal
        self.k0 = (keyblock[0:64], keyblock[64:128])
        self.k1 = (keyblock[128:192], keyblock[192:256])
        self.swapped = swapped
        self.confirmed = False
        self._setup()
        self.send_pid = 0
        self.rmax, self.rmask = 0, 0

    def _setup(self):
        out, inn = (self.k1, self.k0) if self.swapped else (self.k0, self.k1)
        if self.aead:
            self.enc_key, self.enc_iv = out[0][:self.klen], out[1][:8]
            self.dec_key, self.dec_iv = inn[0][:self.klen], inn[1][:8]
        else:
            self.enc_key, self.enc_mac = out[0][:self.klen], out[1][:self.dlen]
            self.dec_key, self.dec_mac = inn[0][:self.klen], inn[1][:self.dlen]

    def _header(self):
        if self.peer_id is not None:
            return bytes([(P_DATA_V2 << 3) | self.key_id]) + struct.pack('>I', self.peer_id)[1:]
        return bytes([(P_DATA_V1 << 3) | self.key_id])

    def encrypt(self, payload):
        self.send_pid += 1
        if self.send_pid >= 0xFFFFFFF0:
            raise SessionError('packet-id esgotado')
        pid = struct.pack('>I', self.send_pid)
        hdr = self._header()
        if self.aead:
            aad = (hdr if self.peer_id is not None else b'') + pid
            ct, tag = gcm_encrypt(self.enc_key, pid + self.enc_iv, aad, payload)
            return hdr + pid + tag + ct
        iv = os.urandom(16)
        ct = aes_cbc(kCCEncrypt, self.enc_key, iv, pid + payload)
        mac = hmac.new(self.enc_mac, iv + ct, self.digest).digest()
        return hdr + mac + iv + ct

    def _decrypt_with(self, pkt, op):
        hl = 4 if op == P_DATA_V2 else 1
        if self.aead:
            if len(pkt) < hl + 20:
                return None, 0
            pid = pkt[hl:hl + 4]
            aad = (pkt[:4] if op == P_DATA_V2 else b'') + pid
            pt = gcm_decrypt(self.dec_key, pid + self.dec_iv, aad, pkt[hl + 20:], pkt[hl + 4:hl + 20])
            return pt, struct.unpack('>I', pid)[0]
        if len(pkt) < hl + self.dlen + 32:
            return None, 0
        mac, rest = pkt[hl:hl + self.dlen], pkt[hl + self.dlen:]
        if not hmac.compare_digest(mac, hmac.new(self.dec_mac, rest, self.digest).digest()):
            return None, 0
        pt = aes_cbc(kCCDecrypt, self.dec_key, rest[:16], rest[16:])
        if pt is None or len(pt) < 4:
            return None, 0
        return pt[4:], struct.unpack('>I', pt[:4])[0]

    def decrypt(self, pkt, op):
        pt, pid = self._decrypt_with(pkt, op)
        if pt is None and not self.confirmed:
            # detecta automaticamente a direção das chaves na 1a mensagem
            self.swapped = not self.swapped
            self._setup()
            pt, pid = self._decrypt_with(pkt, op)
            if pt is None:
                self.swapped = not self.swapped
                self._setup()
            else:
                log.debug('direção das chaves de dados invertida')
        if pt is None:
            return None
        self.confirmed = True
        if not self._replay_ok(pid):
            log.debug('pacote repetido descartado (pid %d)', pid)
            return None
        return pt

    def _replay_ok(self, pid):
        if pid > self.rmax:
            shift = pid - self.rmax
            self.rmask = ((self.rmask << shift) | 1) & ((1 << 64) - 1) if shift < 64 else 1
            self.rmax = pid
            return True
        diff = self.rmax - pid
        if diff >= 64 or (self.rmask >> diff) & 1:
            return False
        self.rmask |= 1 << diff
        return True


class Compression:
    """Só o enquadramento de 'sem compressão' (o cliente não comprime)."""

    def __init__(self, mode=None):
        self.mode = mode  # None | 'lzo' | 'stub' | 'v2'

    def frame(self, p):
        if self.mode == 'lzo':
            return b'\xfa' + p
        if self.mode == 'stub':
            return b'\xfb' + p[1:] + p[:1] if p else b'\xfb'
        if self.mode == 'v2' and p[:1] == b'\x50':
            return b'\x50\x00' + p
        return p

    def unframe(self, p):
        if self.mode == 'lzo':
            if p[:1] != b'\xfa':
                return None
            return p[1:]
        if self.mode == 'stub':
            if p[:1] != b'\xfb':
                return None
            return p[-1:] + p[1:-1] if len(p) > 1 else b''
        if self.mode == 'v2' and p[:1] == b'\x50':
            return p[2:] if p[1:2] == b'\x00' else None
        return p


# --------------------------------------------------------------------------
# Estado de chave (uma sessão TLS + camada de confiabilidade)
# --------------------------------------------------------------------------

class KeyState:
    def __init__(self, sess, key_id):
        self.sess = sess
        self.key_id = key_id
        self.created = time.time()
        self.state = 'reset'  # reset -> tls -> km2 -> active
        self.retire_at = None
        # confiabilidade
        self.send_next = 0
        self.unacked = {}  # id -> [op, payload, last_sent, rto]
        self.queue = deque()
        self.recv_next = 0
        self.recv_buf = {}
        self.acks = []
        # TLS
        self.bio_in, self.bio_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = sess.tls_ctx.wrap_bio(self.bio_in, self.bio_out, server_side=False)
        self.pre_master, self.r1, self.r2 = os.urandom(48), os.urandom(32), os.urandom(32)
        self.km2buf = b''
        self.textbuf = b''
        self.keyblock = None
        self.data = None

    # ---- envio confiável ----
    def send_control(self, op, payload):
        self.queue.append((op, payload))
        self.flush()

    def flush(self):
        while self.queue and len(self.unacked) < RELIABLE_SEND_WINDOW:
            op, p = self.queue.popleft()
            mid = self.send_next
            self.send_next += 1
            self.unacked[mid] = [op, p, 0.0, 2.0]
            self._transmit(mid)

    def _ack_block(self):
        take = self.acks[:MAX_ACKS_PER_PACKET]
        del self.acks[:MAX_ACKS_PER_PACKET]
        b = bytes([len(take)]) + b''.join(struct.pack('>I', a) for a in take)
        return b + (self.sess.remote_sid if take else b'')

    def _transmit(self, mid):
        e = self.unacked[mid]
        body = self._ack_block() + struct.pack('>I', mid) + e[1]
        self.sess.send_ctl(e[0], self.key_id, body)
        e[2] = time.time()

    def send_acks(self):
        while self.acks and self.sess.remote_sid:
            self.sess.send_ctl(P_ACK_V1, self.key_id, self._ack_block())

    def timers(self, now):
        for mid, e in list(self.unacked.items()):
            if now - e[2] >= e[3]:
                log.debug('retransmitindo msg %d (key %d)', mid, self.key_id)
                e[3] = min(e[3] * 2, 16.0)
                self._transmit(mid)
        self.flush()
        self.send_acks()

    # ---- recepção confiável ----
    def on_packet(self, op, acks, msgid, payload):
        for a in acks:
            self.unacked.pop(a, None)
        self.flush()
        if op == P_ACK_V1:
            return
        if msgid < self.recv_next:
            self.acks.append(msgid)  # duplicado: reconfirma
            return
        if msgid >= self.recv_next + RELIABLE_RECV_WINDOW:
            return
        if msgid not in self.acks:
            self.acks.append(msgid)
        self.recv_buf[msgid] = (op, payload)
        while self.recv_next in self.recv_buf:
            op, p = self.recv_buf.pop(self.recv_next)
            self.recv_next += 1
            self._on_message(op, p)

    def _on_message(self, op, p):
        if op in RESET_OPS:
            if self.state == 'reset':
                self.state = 'tls'
                self.drive_tls()
        elif op == P_CONTROL_V1:
            self.bio_in.write(p)
            self.drive_tls()

    # ---- TLS ----
    def drive_tls(self):
        try:
            if self.state == 'tls':
                try:
                    self.tls.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                else:
                    self.sess.verify_peer(self.tls)
                    if self.sess.test_only:
                        self.sess.test_done = True
                        return
                    self.state = 'km2'
                    self.tls.write(self._build_km2())
            if self.state in ('km2', 'active'):
                while True:
                    try:
                        d = self.tls.read(65536)
                    except ssl.SSLWantReadError:
                        break
                    if not d:
                        break
                    self._on_tls_data(d)
        except ssl.SSLError as e:
            raise SessionError('erro TLS (key %d): %s' % (self.key_id, e))
        finally:
            self.pump_out()

    def pump_out(self):
        data = self.bio_out.read()
        for i in range(0, len(data), CTL_MAX_PAYLOAD):
            self.send_control(P_CONTROL_V1, data[i:i + CTL_MAX_PAYLOAD])

    def write_tls(self, data):
        self.tls.write(data)
        self.pump_out()

    def _build_km2(self):
        def lstr(s):
            b = s.encode() + b'\0'
            return struct.pack('>H', len(b)) + b
        user, password = self.sess.credentials()
        return (struct.pack('>I', 0) + b'\x02' + self.pre_master + self.r1 + self.r2 +
                lstr(self.sess.options_string()) + lstr(user) + lstr(password) +
                lstr(self.sess.peer_info()))

    def _on_tls_data(self, d):
        if self.state != 'km2':
            self.sess.on_control_text(self, d)
            return
        self.km2buf += d
        b = self.km2buf
        if len(b) < 71:
            return
        if b[:4] != b'\0\0\0\0' or (b[4] & 0x0F) != 2:
            raise SessionError('resposta key-method 2 inválida do servidor')
        olen = struct.unpack('>H', b[69:71])[0]
        if len(b) < 71 + olen:
            return
        s_r1, s_r2 = b[5:37], b[37:69]
        log.debug('opções do servidor: %s', b[71:71 + olen].rstrip(b'\0').decode(errors='replace'))
        sess = self.sess
        master = tls1_prf(self.pre_master, b'OpenVPN master secret' + self.r1 + s_r1, 48)
        self.keyblock = tls1_prf(master, b'OpenVPN key expansion' + self.r2 + s_r2 +
                                 sess.local_sid + sess.remote_sid, 256)
        self.pre_master = None
        self.km2buf = b''
        self.state = 'active'
        sess.on_key_active(self)


# --------------------------------------------------------------------------
# utun
# --------------------------------------------------------------------------

class Utun:
    CTLIOCGINFO = 0xC0644E03
    UTUN_OPT_IFNAME = 2

    def __init__(self):
        s = socket.socket(socket.PF_SYSTEM, socket.SOCK_DGRAM, socket.SYSPROTO_CONTROL)
        info = fcntl.ioctl(s.fileno(), self.CTLIOCGINFO,
                           struct.pack('I96s', 0, b'com.apple.net.utun_control'))
        ctl_id = struct.unpack('I', info[:4])[0]
        s.connect((ctl_id, 0))
        self.name = s.getsockopt(socket.SYSPROTO_CONTROL, self.UTUN_OPT_IFNAME, 32).split(b'\0')[0].decode()
        s.setblocking(False)
        self.sock = s

    def fileno(self):
        return self.sock.fileno()

    def read(self):
        d = self.sock.recv(65536)
        return d[4:]

    def write(self, pkt):
        if not pkt:
            return
        af = 30 if (pkt[0] >> 4) == 6 else 2  # AF_INET6 (darwin) / AF_INET
        try:
            self.sock.send(struct.pack('>I', af) + pkt)
        except OSError as e:
            log.debug('escrita no utun falhou: %s', e)

    def close(self):
        self.sock.close()


# --------------------------------------------------------------------------
# Rede: ifconfig / rotas / DNS
# --------------------------------------------------------------------------

def _run(cmd, check=True, inp=None):
    log.debug('$ %s', ' '.join(cmd))
    r = subprocess.run(cmd, input=inp, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SessionError('comando falhou: %s: %s' % (' '.join(cmd), r.stderr.strip()))
    return r


def default_gateway():
    r = _run(['route', '-n', 'get', 'default'], check=False)
    gw = ifc = None
    for line in r.stdout.splitlines():
        k, _, v = line.strip().partition(':')
        if k == 'gateway':
            gw = v.strip()
        elif k == 'interface':
            ifc = v.strip()
    return gw, ifc


class NetConfig:
    def __init__(self, ifname, server_ip):
        self.ifname = ifname
        self.server_ip = server_ip
        self.undo = []

    def _route(self, args, family='-inet'):
        _run(['route', '-q', '-n', 'add', family] + args)
        self.undo.append(['route', '-q', '-n', 'delete', family] + args)

    def apply(self, p, mtu, dns_domains_override):
        ifn = self.ifname
        if p.get('ifconfig'):
            ip, arg2 = p['ifconfig']
            if p.get('topology') == 'subnet':
                _run(['ifconfig', ifn, 'inet', ip, ip, 'netmask', arg2, 'mtu', str(mtu), 'up'])
                net = ipaddress.IPv4Network('%s/%s' % (ip, arg2), strict=False)
                self._route(['-net', str(net.network_address), '-netmask', str(net.netmask),
                             '-interface', ifn])
            else:
                _run(['ifconfig', ifn, 'inet', ip, arg2, 'netmask', '255.255.255.255',
                      'mtu', str(mtu), 'up'])
        if p.get('ifconfig-ipv6'):
            addr = p['ifconfig-ipv6'][0]
            a, _, plen = addr.partition('/')
            _run(['ifconfig', ifn, 'inet6', a, 'prefixlen', plen or '64', 'up'])

        gw, gw_if = None, None
        if p.get('redirect-gateway') is not None or any(r[2] == 'net_gateway' for r in p['routes']):
            gw, gw_if = default_gateway()

        if p.get('redirect-gateway') is not None:
            if gw:
                self._route(['-host', self.server_ip, gw])
            elif gw_if:
                self._route(['-host', self.server_ip, '-interface', gw_if])
            for half in ('0.0.0.0', '128.0.0.0'):
                self._route(['-net', half, '-netmask', '128.0.0.0', '-interface', ifn])

        for net, mask, via in p['routes']:
            try:
                if via == 'net_gateway' and gw:
                    self._route(['-net', net, '-netmask', mask, gw])
                else:
                    self._route(['-net', net, '-netmask', mask, '-interface', ifn])
            except SessionError as e:
                log.warning('%s', e)
        for net in p['routes6']:
            try:
                self._route(['-net', net, '-interface', ifn], family='-inet6')
            except SessionError as e:
                log.warning('%s', e)

        dns, domains = p['dns'], dns_domains_override or p['domains']
        if dns:
            if domains:
                self._set_dns(dns, domains)
            else:
                log.warning('servidor enviou DNS %s mas nenhum domínio; use --dns-domain '
                            'para resolver nomes internos por ele', ', '.join(dns))

    def _set_dns(self, servers, domains):
        key = 'State:/Network/Service/ovpnc-%d/DNS' % os.getpid()
        script = ('d.init\n'
                  'd.add ServerAddresses * %s\n'
                  'd.add SearchDomains * %s\n'
                  'd.add SupplementalMatchDomains * %s\n'
                  'set %s\nquit\n') % (' '.join(servers), ' '.join(domains), ' '.join(domains), key)
        _run(['scutil'], inp=script)
        self.undo.append(['scutil', '<<', 'remove %s\nquit\n' % key])
        log.info('DNS %s para os domínios: %s', ', '.join(servers), ', '.join(domains))

    def cleanup(self):
        for cmd in reversed(self.undo):
            if cmd[:2] == ['scutil', '<<']:
                _run(['scutil'], check=False, inp=cmd[2])
            else:
                _run(cmd, check=False)
        self.undo = []


# --------------------------------------------------------------------------
# Sessão
# --------------------------------------------------------------------------

class Session:
    def __init__(self, cfg, creds, args, stop):
        self.cfg = cfg
        self.args = args
        self.creds = creds
        self.stop = stop
        self.test_only = args.test
        self.test_done = False

        host, port = cfg.remote
        self.server_ip = socket.gethostbyname(host)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect((self.server_ip, port))
        self.sock.setblocking(False)
        log.info('servidor %s:%d/udp', self.server_ip, port)

        ta = cfg.blob('tls-auth')
        self.tls_auth = (TlsAuth(parse_static_key(ta), cfg.key_direction, cfg.auth_digest)
                         if ta else NoTlsAuth())
        self.tls_ctx = self._make_tls_ctx()

        self.local_sid = os.urandom(8)
        self.remote_sid = None
        self.keys = {}
        self.primary = None
        self.next_key_id = 1

        self.push_items = []
        self.pushed = None
        self.push_sent_at = 0.0
        self.push_started = None
        self.cipher = None
        self.peer_id = None
        self.comp = Compression()
        self.ping = 10
        self.ping_restart = 120
        self.last_recv = time.time()
        self.last_sent = time.time()
        self.tun = None
        self.net = None
        self.bytes_in = 0
        self.bytes_out = 0
        self.last_stats = 0.0

    # ---- TLS ----
    def _make_tls_ctx(self):
        cfg = self.cfg
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except (AttributeError, ValueError):
            pass
        ca = cfg.blob('ca')
        if not ca:
            raise FatalError('certificado <ca> ausente')
        ctx.load_verify_locations(cadata=ca)
        cert, key = cfg.blob('cert'), cfg.blob('key')
        if cert and key:
            with tempfile.TemporaryDirectory() as td:
                cp, kp = os.path.join(td, 'c.pem'), os.path.join(td, 'k.pem')
                for p, data in ((cp, cert), (kp, key)):
                    fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
                    with os.fdopen(fd, 'w') as f:
                        f.write(data)
                ctx.load_cert_chain(cp, kp)
        return ctx

    def verify_peer(self, tls):
        cert = tls.getpeercert()
        subject = dict(x for rdn in cert.get('subject', ()) for x in rdn)
        cn = subject.get('commonName')
        vx = self.cfg.get('verify-x509-name')
        if vx:
            want, kind = vx[0], (vx[1] if len(vx) > 1 else 'subject')
            if kind == 'name' and cn != want:
                raise FatalError('verify-x509-name: CN do servidor é %r, esperado %r' % (cn, want))
            if kind == 'name-prefix' and not (cn or '').startswith(want):
                raise FatalError('verify-x509-name: CN %r não começa com %r' % (cn, want))
        rct = self.cfg.get('remote-cert-tls')
        if rct and rct[0] == 'server':
            der = tls.getpeercert(binary_form=True)
            server_auth_oid = bytes.fromhex('06082b06010505070301')
            if server_auth_oid not in der:
                raise FatalError('remote-cert-tls server: certificado sem EKU serverAuth')
        log.info('TLS ok: %s, servidor CN=%s', tls.version(), cn)
        emit('state', state='tls_ok')

    # ---- canal de controle ----
    def send_ctl(self, op, key_id, body):
        self._send(self.tls_auth.wrap((op << 3) | key_id, self.local_sid, body))

    def _send(self, pkt):
        try:
            self.sock.send(pkt)
            self.last_sent = time.time()
        except (BlockingIOError, OSError) as e:
            log.debug('envio UDP falhou: %s', e)

    def credentials(self):
        return self.creds()

    def options_string(self):
        c = self.cfg
        return ('V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher %s,auth %s,'
                'keysize 128,key-method 2,tls-client' % (c.fallback_cipher, c.auth_digest.upper()))

    def peer_info(self):
        ciphers = self.cfg.data_ciphers
        fb = self.cfg.fallback_cipher
        if fb in SUPPORTED_CIPHERS and fb not in ciphers:
            ciphers.append(fb)
        return ('IV_VER=2.6.12\nIV_PLAT=mac\nIV_PROTO=2\nIV_NCP=2\n'
                'IV_CIPHERS=%s\nIV_GUI_VER=ovpnc_%s\n' % (':'.join(ciphers), VERSION))

    def on_udp(self, pkt):
        if not pkt:
            return
        op, kid = pkt[0] >> 3, pkt[0] & 7
        if op in (P_DATA_V1, P_DATA_V2):
            self.on_data(pkt, op, kid)
            return
        r = self.tls_auth.unwrap(pkt)
        if r is None:
            log.debug('pacote de controle com HMAC inválido descartado')
            return
        sid, body = r
        if self.remote_sid is None:
            if op != P_CONTROL_HARD_RESET_SERVER_V2:
                return
            self.remote_sid = sid
        elif sid != self.remote_sid:
            return
        try:
            n = body[0]
            off = 1
            acks = list(struct.unpack('>%dI' % n, body[off:off + 4 * n]))
            off += 4 * n
            if n:
                if body[off:off + 8] != self.local_sid:
                    return
                off += 8
            msgid = None
            if op != P_ACK_V1:
                msgid = struct.unpack('>I', body[off:off + 4])[0]
                off += 4
        except (IndexError, struct.error):
            return
        payload = body[off:]
        self.last_recv = time.time()

        ks = self.keys.get(kid)
        if op == P_CONTROL_SOFT_RESET_V1 and msgid == 0 and (
                ks is None or (ks.state == 'active' and time.time() - ks.created > 30)):
            log.info('renegociação iniciada pelo servidor (key %d)', kid)
            ks = KeyState(self, kid)
            self.keys[kid] = ks
            ks.send_control(P_CONTROL_SOFT_RESET_V1, b'')
        if ks is None:
            return
        log.debug('<- op=%d key=%d msg=%s acks=%s len=%d', op, kid, msgid, acks, len(payload))
        ks.on_packet(op, acks, msgid, payload)

    def on_key_active(self, ks):
        if self.pushed is None:
            log.info('autenticando...')
            emit('state', state='authenticating')
            self.push_started = time.time()
            self._push_request(ks)
            return
        ks.data = DataChannel(self.cipher, self.cfg.auth_digest, ks.keyblock, ks.key_id,
                              self.peer_id, self.primary.data.swapped if self.primary else False)
        if self.primary and self.primary is not ks:
            self.primary.retire_at = time.time()
        self.primary = ks
        log.info('nova chave de dados ativa (key %d)', ks.key_id)

    def _push_request(self, ks):
        self.push_sent_at = time.time()
        ks.write_tls(b'PUSH_REQUEST\0')

    def on_control_text(self, ks, d):
        ks.textbuf += d
        while b'\0' in ks.textbuf:
            msg, _, ks.textbuf = ks.textbuf.partition(b'\0')
            self._control_msg(ks, msg.decode(errors='replace').strip())

    def _control_msg(self, ks, m):
        log.debug('controle: %s', m)
        if m.startswith('PUSH_REPLY'):
            self._on_push(ks, m)
        elif m.startswith('AUTH_FAILED'):
            raise FatalError('autenticação recusada pelo servidor (%s)' % m)
        elif m.startswith('AUTH_PENDING'):
            log.info('autenticação pendente no servidor (%s)', m)
            self.push_started = time.time()
        elif m.startswith('RESTART'):
            raise SessionError('servidor pediu reinício (%s)' % m)
        elif m.startswith('HALT'):
            raise FatalError('servidor encerrou a conexão (%s)' % m)
        elif m.startswith('INFO'):
            log.info('servidor: %s', m)

    def _on_push(self, ks, m):
        if self.pushed is not None:
            return
        items = [x.strip() for x in m.split(',')[1:] if x.strip()]
        self.push_items += items
        if 'push-continuation 2' in items:
            return
        p = {'routes': [], 'routes6': [], 'dns': [], 'domains': []}
        for item in self.push_items:
            a = item.split()
            k, v = a[0], a[1:]
            if k == 'ifconfig' and len(v) >= 2:
                p['ifconfig'] = (v[0], v[1])
            elif k == 'ifconfig-ipv6' and v:
                p['ifconfig-ipv6'] = v
            elif k == 'topology' and v:
                p['topology'] = v[0]
            elif k == 'route' and v:
                p['routes'].append((v[0], v[1] if len(v) > 1 else '255.255.255.255',
                                    v[2] if len(v) > 2 else None))
            elif k == 'route-ipv6' and v:
                p['routes6'].append(v[0])
            elif k == 'redirect-gateway':
                p['redirect-gateway'] = v
            elif k == 'dhcp-option' and len(v) >= 2:
                if v[0] in ('DNS', 'DNS6'):
                    p['dns'].append(v[1])
                elif v[0] in ('DOMAIN', 'DOMAIN-SEARCH'):
                    p['domains'].append(v[1])
            elif k == 'ping' and v:
                self.ping = int(v[0])
            elif k == 'ping-restart' and v:
                self.ping_restart = int(v[0])
            elif k == 'peer-id' and v:
                self.peer_id = int(v[0])
            elif k == 'cipher' and v:
                self.cipher = v[0].upper()
            elif k == 'tun-mtu' and v:
                p['tun-mtu'] = int(v[0])
            elif k == 'comp-lzo':
                self.comp = Compression('lzo')
            elif k == 'compress':
                self.comp = Compression('v2' if v and v[0] in ('stub-v2', 'lz4-v2') else 'stub')
            elif k == 'auth-token' and v:
                self.creds.token = v[0]
            elif k == 'key-derivation':
                raise FatalError('servidor exige key-derivation %s (não suportado)' % ' '.join(v))
        self.pushed = p
        if not self.cipher:
            self.cipher = self.cfg.fallback_cipher
        log.debug('push: %s', self.push_items)

        ks.data = DataChannel(self.cipher, self.cfg.auth_digest, ks.keyblock, ks.key_id, self.peer_id)
        self.primary = ks

        self.tun = Utun()
        self.net = NetConfig(self.tun.name, self.server_ip)
        self.net.apply(p, p.get('tun-mtu', 1500), self.args.dns_domain)
        ip = p.get('ifconfig', ('?',))[0]
        nroutes = len(p['routes']) + len(p['routes6'])
        log.info('CONECTADO: %s ip=%s cipher=%s rotas=%d%s', self.tun.name, ip, self.cipher,
                 nroutes, ' +redirect-gateway' if p.get('redirect-gateway') is not None else '')
        emit('state', state='connected', ifname=self.tun.name, ip=ip, cipher=self.cipher,
             routes=nroutes, redirect_gateway=p.get('redirect-gateway') is not None)

    # ---- canal de dados ----
    def on_data(self, pkt, op, kid):
        ks = self.keys.get(kid)
        if ks is None or ks.data is None:
            return
        pt = ks.data.decrypt(pkt, op)
        if pt is None:
            log.debug('pacote de dados inválido (key %d)', kid)
            return
        self.last_recv = time.time()
        if pt == PING_MAGIC:
            return
        if pt.startswith(OCC_MAGIC):
            if len(pt) > 16 and pt[16] == OCC_EXIT:
                raise SessionError('servidor sinalizou saída (explicit-exit-notify)')
            return
        pt = self.comp.unframe(pt)
        if pt and self.tun:
            self.bytes_in += len(pt)
            self.tun.write(pt)

    def send_data(self, payload, raw=False):
        if not self.primary or not self.primary.data:
            return
        if not raw:
            payload = self.comp.frame(payload)
        self._send(self.primary.data.encrypt(payload))

    # ---- laço principal ----
    def timers(self):
        now = time.time()
        for kid, ks in list(self.keys.items()):
            ks.timers(now)
            if ks.state != 'active' and now - ks.created > HAND_WINDOW:
                if self.primary is None:
                    raise SessionError('tempo esgotado na negociação TLS (hand-window)')
                log.warning('renegociação da key %d expirou', kid)
                del self.keys[kid]
            elif ks.retire_at and now - ks.retire_at > TRANSITION_WINDOW:
                del self.keys[kid]

        if self.pushed is None and self.push_started:
            ks0 = self.keys.get(0)
            if now - self.push_started > 120:
                raise SessionError('sem PUSH_REPLY do servidor')
            if ks0 and now - self.push_sent_at > 5:
                self._push_request(ks0)

        if self.pushed is not None:
            if now - self.last_recv > self.ping_restart:
                raise SessionError('sem resposta do servidor há %ds (ping-restart)' % self.ping_restart)
            if self.ping and now - self.last_sent >= self.ping:
                self.send_data(PING_MAGIC, raw=True)

    def run(self):
        ks = KeyState(self, 0)
        self.keys[0] = ks
        ks.send_control(P_CONTROL_HARD_RESET_CLIENT_V2, b'')
        log.info('handshake iniciado')
        emit('state', state='connecting', server=self.server_ip)
        try:
            while not self.stop():
                fds = [self.sock] + ([self.tun] if self.tun else [])
                r, _, _ = select.select(fds, [], [], 0.2)
                if self.sock in r:
                    for _ in range(256):
                        try:
                            pkt = self.sock.recv(65536)
                        except BlockingIOError:
                            break
                        except ConnectionRefusedError:
                            log.debug('ICMP port unreachable do servidor')
                            break
                        self.on_udp(pkt)
                        if self.test_done:
                            return
                    for k in self.keys.values():
                        k.send_acks()
                if self.tun and self.tun in r:
                    for _ in range(256):
                        try:
                            pkt = self.tun.read()
                        except BlockingIOError:
                            break
                        self.bytes_out += len(pkt)
                        self.send_data(pkt)
                self.timers()
                if self.pushed is not None and time.time() - self.last_stats >= 2:
                    self.last_stats = time.time()
                    emit('stats', bytes_in=self.bytes_in, bytes_out=self.bytes_out)
        finally:
            self.shutdown()

    def shutdown(self):
        if self.primary and self.primary.data and self.cfg.has('explicit-exit-notify'):
            try:
                self.send_data(OCC_MAGIC + bytes([OCC_EXIT]), raw=True)
            except Exception:
                pass
        if self.net:
            self.net.cleanup()
        if self.tun:
            self.tun.close()
        self.sock.close()


# --------------------------------------------------------------------------
# Credenciais e main
# --------------------------------------------------------------------------

class Credentials:
    def __init__(self, cfg, auth_file):
        self.user = self.password = None
        self.token = None
        aup = cfg.get('auth-user-pass')
        path = auth_file or (aup[0] if aup else None)
        if path:
            with open(path) as f:
                lines = f.read().splitlines()
            self.user = lines[0].strip()
            self.password = lines[1] if len(lines) > 1 else None
        self.needed = aup is not None

    def from_stdin(self):
        self.user = sys.stdin.readline().rstrip('\n')
        self.password = sys.stdin.readline().rstrip('\n')

    def ask(self):
        if not self.needed:
            return
        if not self.user:
            self.user = input('Usuário VPN: ').strip()
        if self.password is None:
            self.password = getpass.getpass('Senha VPN: ')

    def __call__(self):
        if not self.needed:
            return '', ''
        return self.user, (self.token or self.password)


def main():
    ap = argparse.ArgumentParser(description='Cliente OpenVPN escrito do zero (macOS).')
    ap.add_argument('config', help='arquivo .ovpn')
    ap.add_argument('--auth-file', help='arquivo com usuário (linha 1) e senha (linha 2)')
    ap.add_argument('--dns-domain', action='append',
                    help='domínio a resolver pelo DNS da VPN (pode repetir)')
    ap.add_argument('--test', action='store_true',
                    help='só testa conectividade + handshake TLS, sem autenticar')
    ap.add_argument('--no-reconnect', action='store_true', help='não reconecta após queda')
    ap.add_argument('--json', action='store_true', help='eventos JSON no stdout (para o app)')
    ap.add_argument('--auth-stdin', action='store_true',
                    help='lê usuário e senha (uma linha cada) do stdin')
    ap.add_argument('--watch-stdin', action='store_true',
                    help='desconecta quando o stdin fechar (o app encerrou)')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()
    global _json_events
    _json_events = args.json

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(asctime)s %(levelname).1s %(message)s', datefmt='%H:%M:%S')

    try:
        cfg = Config(args.config)
        if not args.test and os.geteuid() != 0:
            raise FatalError('precisa de root para criar a interface utun: use sudo')
        creds = Credentials(cfg, args.auth_file)
        if args.auth_stdin:
            creds.from_stdin()
        elif not args.test:
            creds.ask()
    except (FatalError, OSError) as e:
        log.error('%s', e)
        emit('error', message=str(e), fatal=True)
        emit('state', state='disconnected')
        return 1

    stopping = []

    def on_signal(signum, frame):
        if not stopping:
            log.info('encerrando...')
        stopping.append(signum)
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    if args.watch_stdin:
        def watch():
            while sys.stdin.readline():
                pass
            if not stopping:
                log.info('stdin fechado, encerrando...')
            stopping.append('stdin')
        threading.Thread(target=watch, daemon=True).start()

    rc = main_loop(cfg, creds, args, stopping)
    emit('state', state='disconnected')
    return rc


def main_loop(cfg, creds, args, stopping):
    delay = 2
    while not stopping:
        try:
            sess = Session(cfg, creds, args, lambda: bool(stopping))
            sess.run()
            if args.test:
                if sess.test_done:
                    log.info('teste OK: servidor alcançável e certificado válido')
                    return 0
                return 1
            delay = 2
        except FatalError as e:
            log.error('%s', e)
            emit('error', message=str(e), fatal=True, auth='autenticação' in str(e))
            return 1
        except (SessionError, OSError) as e:
            log.warning('%s', e)
            emit('error', message=str(e), fatal=False)
            if args.test or args.no_reconnect:
                return 1
        if stopping:
            break
        log.info('reconectando em %ds...', delay)
        emit('state', state='reconnecting', delay=delay)
        t_end = time.time() + delay
        while time.time() < t_end and not stopping:
            time.sleep(0.2)
        delay = min(delay * 2, 60)
    return 0


if __name__ == '__main__':
    sys.exit(main())
