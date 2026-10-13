#!/usr/bin/env python3
"""Real-PTY integration tests using PUBLIC, disposable test material only.
Usage: python3 tests/pty_smoke.py /path/to/shardvault
"""
import fcntl
import itertools
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

from reference_format import recover

BINARY = str(Path(sys.argv[1]).resolve())


class Session:
    def __init__(self, echo=True):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        attrs = termios.tcgetattr(self.slave)
        if not echo:
            attrs[3] &= ~termios.ECHO
            termios.tcsetattr(self.slave, termios.TCSANOW, attrs)
        self.before = termios.tcgetattr(self.slave)
        self.p = subprocess.Popen([BINARY], stdin=self.slave, stdout=self.slave, stderr=self.slave)
        self.pending = b''
        self.log = b''

    def expect(self, text):
        wanted = text.encode()
        deadline = time.monotonic() + 8
        while wanted not in self.pending:
            if time.monotonic() > deadline:
                raise AssertionError(f'timed out waiting for {text!r}; output={self.pending[-1200:]!r}')
            if select.select([self.master], [], [], 0.2)[0]:
                try:
                    data = os.read(self.master, 65536)
                except OSError:
                    data = b''
                if not data:
                    raise AssertionError(f'exited waiting for {text!r}')
                self.pending += data
                self.log += data
        at = self.pending.index(wanted) + len(wanted)
        consumed, self.pending = self.pending[:at], self.pending[at:]
        return consumed

    def send(self, value='', paste=False):
        data = value.encode()
        if paste:
            data = b'\x1b[200~' + data + b'\x1b[201~'
        os.write(self.master, data + b'\r')

    def finish(self, code=0):
        assert self.p.wait(timeout=8) == code
        assert termios.tcgetattr(self.slave) == self.before, 'terminal state was not restored exactly'
        os.close(self.master)
        os.close(self.slave)


def generation_recovery(word_count, password):
    mnemonic = ' '.join(['abandon'] * (word_count - 1) + [('about' if word_count == 12 else 'art')])
    with tempfile.TemporaryDirectory(prefix='public-bip39-test-') as temp:
        folder = Path(temp) / 'shares'
        s = Session()
        s.expect('Choose'); s.send('1')
        s.expect('BIP-39 mnemonic (hidden'); s.send(mnemonic, paste=True)
        s.expect('Include the BIP-39 passphrase'); s.send('y' if password else 'n')
        if password:
            s.expect('BIP-39 passphrase (exact'); s.send(password, paste=True)
            s.expect('Repeat passphrase'); s.send(password, paste=True)
        s.expect('Number of shares'); s.send('5')
        s.expect('Shares required to recover'); s.send('3')
        s.expect('Choose')
        assert mnemonic.encode() not in s.log, 'mnemonic input was echoed'
        if password:
            assert password.encode() not in s.log, 'passphrase input was echoed'
        if len(password) == 512:
            assert b'token page 1/2' in s.log
            s.send(']'); s.expect('token page 2/2'); s.expect('Choose')
        s.send('n'); s.expect('SHARE 2/5'); s.expect('Choose')
        s.send('a'); s.expect('Type EXPORT ALL'); s.send('EXPORT ALL')
        s.expect('Name of NEW private folder'); s.send(str(folder))
        s.expect('Export complete.'); s.expect('Enter to continue'); s.send()
        s.expect('Choose')
        tokens = [(folder / f'share-{i:02}.txt').read_text().strip() for i in range(1, 6)]
        for subset in itertools.combinations(tokens, 3):
            assert recover(subset) == (bytes(16 if word_count == 12 else 32), password)
        s.send('v')
        for i in [5, 2, 4, 1, 3]:
            s.expect('(paste token or @file; q cancels)')
            s.send('@' + str(folder / f'share-{i:02}.txt'))
        s.expect('SUCCESS: all n'); s.expect('Enter to continue'); s.send()
        s.expect('Backup verification: PASSED'); s.expect('Choose'); s.send('q')
        s.expect('Choose'); s.send('2')
        for i in [5, 1, 3]:
            s.expect('(paste token or @file; q cancels)')
            s.send('@' + str(folder / f'share-{i:02}.txt'))
        s.expect('Type REVEAL'); s.send('REVEAL')
        s.expect('BIP-39 mnemonic:')
        if password:
            s.expect('Enter to view the included passphrase'); s.send()
            s.expect('Exact UTF-8 length:')
            s.expect('erase and finish'); s.send()
        else:
            s.expect('BIP-39 passphrase: NOT PRESENT')
            s.expect('Enter to erase the display'); s.send()
        s.expect('Choose'); s.send('q'); s.finish()


def cancellation_and_errors():
    # Start with echo already OFF: cleanup must preserve that state as well.
    s = Session(echo=False); s.expect('Choose'); s.send('q'); s.finish()
    for action in ['ctrl-c', 'term', 'tstp']:
        s = Session(); s.expect('Choose'); s.send('1'); s.expect('BIP-39 mnemonic (hidden')
        if action == 'ctrl-c':
            os.write(s.master, b'\x03'); s.finish()
        else:
            s.p.send_signal(signal.SIGTERM if action == 'term' else signal.SIGTSTP); s.finish(130)
    s = Session(); s.expect('Choose'); s.send('1'); s.expect('BIP-39 mnemonic (hidden')
    typo = 'highly-sensitive-typo'
    s.send(' '.join(['abandon'] * 11 + [typo]))
    s.expect('word 12 is not in the English'); assert typo.encode() not in s.log
    s.expect('Enter to return'); s.send(); s.expect('Choose'); s.send('q'); s.finish()
    s = Session(); s.expect('Choose')
    s.send('X' * 17000, paste=True); s.finish(1)
    with open(os.devnull, 'rb') as devnull:
        result = subprocess.run([BINARY], stdin=devnull, capture_output=True, timeout=5)
        assert result.returncode == 1 and b'interactive TTY' in result.stderr


def word_format_roundtrip():
    # A disposable PUBLIC test vector; no real wallet material is used.
    mnemonic = ' '.join(['abandon'] * 11 + ['about'])
    with tempfile.TemporaryDirectory(prefix='public-word-share-test-') as temp:
        word_dir = Path(temp) / 'words'
        token_dir = Path(temp) / 'tokens'
        single = Path(temp) / 'one-word-share.txt'
        session = Session()
        session.expect('Choose'); session.send('1')
        session.expect('BIP-39 mnemonic (hidden'); session.send(mnemonic, paste=True)
        session.expect('Include the BIP-39 passphrase'); session.send('n')
        session.expect('Number of shares'); session.send('3')
        session.expect('Shares required to recover'); session.send('2')
        session.expect('Choose')
        session.send('t')
        session.expect('B39WORDS1: English words')
        session.expect('Choose')
        session.send('w')
        session.expect('Share index to save'); session.send('1')
        session.expect('Absolute or relative new file path'); session.send(str(single))
        session.expect('Share saved with restrictive permissions.')
        session.expect('Enter to continue'); session.send()
        session.expect('Choose')
        session.send('e')
        session.expect('Type EXPORT ALL'); session.send('EXPORT ALL')
        session.expect('Name of NEW private folder'); session.send(str(word_dir))
        session.expect('Export complete.'); session.expect('Enter to continue'); session.send()
        session.expect('Choose')
        session.send('a')
        session.expect('Type EXPORT ALL'); session.send('EXPORT ALL')
        session.expect('Name of NEW private folder'); session.send(str(token_dir))
        session.expect('Export complete.'); session.expect('Enter to continue'); session.send()
        session.expect('Choose')
        assert single.read_text().startswith('B39WORDS1:')
        assert len(single.read_text().split()) == 88  # prefix + 87 words
        assert (word_dir / 'share-02.txt').read_text().startswith('B39WORDS1:')
        assert (token_dir / 'share-02.txt').read_text().startswith('B39SSS1:')
        session.send('v')
        for folder, i in [(word_dir, 3), (token_dir, 2), (word_dir, 1)]:
            session.expect('(paste token or @file; q cancels)')
            session.send('@' + str(folder / f'share-{i:02}.txt'))
        session.expect('SUCCESS: all n'); session.expect('Enter to continue'); session.send()
        session.expect('Backup verification: PASSED')
        session.expect('Choose'); session.send('q')
        session.expect('Choose'); session.send('2')
        for file in [single, token_dir / 'share-03.txt']:
            session.expect('(paste token or @file; q cancels)')
            session.send('@' + str(file))
        session.expect('Type REVEAL'); session.send('REVEAL')
        session.expect('BIP-39 mnemonic:')
        session.expect('BIP-39 passphrase: NOT PRESENT')
        session.expect('Enter to erase the display'); session.send()
        session.expect('Choose'); session.send('q')
        session.finish()


generation_recovery(24, 'Z' * 512)
generation_recovery(12, '')
generation_recovery(12, '  café \\ " 🔐  ')
cancellation_and_errors()
word_format_roundtrip()
print('PASS: 3 complete generation/export/all-share verification/recovery flows; independent Python reconstruction; paging; hidden input; exact terminal restoration; signals; oversized input; non-TTY rejection.')
