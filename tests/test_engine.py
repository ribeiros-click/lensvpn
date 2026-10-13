"""Testes offline do motor (cripto do canal de dados e enquadramento).

Uso: python3 -I tests/test_engine.py   (macOS, usa a CommonCrypto)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import ovpnc as o  # noqa: E402


def test_gcm_nist_vector():
    ct, tag = o.gcm_encrypt(b'\0' * 16, b'\0' * 12, b'', b'\0' * 16)
    assert ct.hex() == '0388dace60b6a392f328c2b971b2fe78'
    assert tag.hex() == 'ab6e47d42cec13bdf53a67b21257bddf'


def test_prf_length():
    assert len(o.tls1_prf(os.urandom(48), b'x', 256)) == 256


def test_data_channel_roundtrip():
    kb = os.urandom(256)
    for cipher in ('AES-256-GCM', 'AES-128-GCM', 'AES-128-CBC', 'AES-256-CBC'):
        for peer_id in (None, 7):
            a = o.DataChannel(cipher, 'sha256', kb, 1, peer_id)
            b = o.DataChannel(cipher, 'sha256', kb, 1, peer_id, swapped=True)
            for msg in (b'hello' * 100, o.PING_MAGIC):
                pkt = a.encrypt(msg)
                assert b.decrypt(pkt, pkt[0] >> 3) == msg
                assert b.decrypt(pkt, pkt[0] >> 3) is None  # replay
            # direção das chaves detectada automaticamente
            c = o.DataChannel(cipher, 'sha256', kb, 1, peer_id)
            pkt = a.encrypt(b'x')
            assert c.decrypt(pkt, pkt[0] >> 3) == b'x' and c.swapped


def test_compression_framing():
    for mode in ('lzo', 'stub', 'v2', None):
        comp = o.Compression(mode)
        for p in (b'\x45abc', b'\x50zz'):
            assert comp.unframe(comp.frame(p)) == p


if __name__ == '__main__':
    for name, fn in list(globals().items()):
        if name.startswith('test_'):
            fn()
            print('ok', name)
