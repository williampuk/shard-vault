#!/usr/bin/env python3
"""Independent, TEST-ONLY B39SSS1 oracle. Never enter real wallet material here.

Uses polynomial multiplication and reduction, deliberately different from the
Go bit-at-a-time field multiplier. Fixed coefficients are PUBLIC test data.
"""
import base64
import hashlib
import itertools
import json
import struct
from pathlib import Path


def mul(a, b):
    product = 0
    for bit in range(8):
        if b & (1 << bit):
            product ^= a << bit
    for bit in range(14, 7, -1):
        if product & (1 << bit):
            product ^= 0x11B << (bit - 8)
    return product


def inv(a):
    return next(b for b in range(1, 256) if mul(a, b) == 1)


def encode(raw):
    return 'B39SSS1:' + base64.urlsafe_b64encode(raw).decode().rstrip('=')


def create_fixture(entropy, password, threshold=3, total=5):
    ident = bytes(range(16))
    p = password.encode()
    payload = b'B39PAY1' + bytes([bool(p), len(entropy)]) + entropy + struct.pack('>H', len(p)) + p
    payload += hashlib.sha256(payload).digest()
    tokens = []
    for x in range(1, total + 1):
        value = bytearray()
        for j, secret in enumerate(payload):
            coeffs = hashlib.sha256(b'public-test-coefficients' + struct.pack('>I', j)).digest()[:threshold-1]
            y, power = secret, 1
            for c in coeffs:
                power = mul(power, x)
                y ^= mul(c, power)
            value.append(y)
        wrapper = b'B39SHR1' + bytes([threshold, total, x]) + ident + struct.pack('>H', len(value)) + value
        wrapper += hashlib.sha256(wrapper).digest()
        tokens.append(encode(wrapper))
    return dict(entropy=entropy.hex(), passphrase=password, threshold=threshold, total=total, tokens=tokens)


def recover(tokens):
    points = []
    for token in tokens:
        raw = base64.urlsafe_b64decode(token.strip().split(':', 1)[1] + '===')
        assert raw[:7] == b'B39SHR1'
        assert hashlib.sha256(raw[:-32]).digest() == raw[-32:]
        assert len(raw) == 60 + int.from_bytes(raw[26:28], 'big')
        points.append((raw[9], raw[28:-32]))
    assert len({x for x, _ in points}) == len(points)
    output = bytearray(len(points[0][1]))
    for x, y in points:
        weight = 1
        for q, _ in points:
            if q != x:
                weight = mul(weight, mul(q, inv(q ^ x)))
        for j, b in enumerate(y):
            output[j] ^= mul(weight, b)
    assert output[:7] == b'B39PAY1'
    assert hashlib.sha256(output[:-32]).digest() == output[-32:]
    length = output[8]
    p_len = int.from_bytes(output[9+length:11+length], 'big')
    assert len(output) == 43 + length + p_len
    return bytes(output[9:9+length]), bytes(output[11+length:-32]).decode()


if __name__ == '__main__':
    fixtures = [create_fixture(bytes(range(16)), '  café \\ " 🔐  '), create_fixture(bytes(range(32)), '')]
    for fixture in fixtures:
        for subset in itertools.combinations(fixture['tokens'], fixture['threshold']):
            assert recover(subset) == (bytes.fromhex(fixture['entropy']), fixture['passphrase'])
    target = Path(__file__).resolve().parents[1] / 'internal/share/testdata/v1-vectors.json'
    target.write_text(json.dumps(fixtures, ensure_ascii=True, indent=2) + '\n')
    print('Generated and independently recovered two public B39SSS1 fixtures (20 subsets).')
