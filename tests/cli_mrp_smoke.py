#!/usr/bin/env python3
"""Exercise the real CLI against an isolated, authenticated loopback receiver.

Requires Python cryptography. No mDNS, physical receivers, credentials or PTP
ports are used. This verifies protocol negotiation, not Apple's iOS UI.
"""
from __future__ import annotations

import argparse
import os
import plistlib
import socket
import subprocess
import tempfile
import threading
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf(secret, salt, info):
    return HKDF(hashes.SHA512(), 32, salt.encode(), info.encode()).derive(secret)


def public(key):
    return key.public_key().public_bytes_raw()


def tlv_encode(items):
    result = bytearray()
    for tag, value in items.items():
        for i in range(0, len(value), 255):
            part = value[i:i + 255]
            result.extend(bytes((tag, len(part))) + part)
    return bytes(result)


def tlv_decode(data):
    result = {}
    i = 0
    while i < len(data):
        tag, length = data[i:i + 2]
        result[tag] = result.get(tag, b'') + data[i + 2:i + 2 + length]
        i += length + 2
    return result


def varint(data, offset=0):
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
        shift += 7
        assert shift < 70


def protobuf(data):
    result = {}
    offset = 0
    while offset < len(data):
        key, offset = varint(data, offset)
        wire = key & 7
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire == 2:
            length, offset = varint(data, offset)
            value = data[offset:offset + length]
            offset += length
        else:
            raise AssertionError(f'Unexpected protobuf wire type {wire}')
        result[key >> 3] = value
    return result


class Wire:
    def __init__(self, sock):
        self.sock = sock
        sock.settimeout(10)
        self.read_key = self.write_key = None
        self.read_counter = self.write_counter = 0
        self.pending = bytearray()

    def exact(self, length):
        data = bytearray()
        while len(data) < length:
            part = self.sock.recv(length - len(data))
            if not part:
                raise EOFError
            data.extend(part)
        return bytes(data)

    def read(self):
        while b'\r\n\r\n' not in self.pending:
            self.receive()
        end = self.pending.index(b'\r\n\r\n') + 4
        lines = bytes(self.pending[:end]).decode().split('\r\n')
        headers = dict(line.lower().split(': ', 1) for line in lines[1:] if ': ' in line)
        length = int(headers.get('content-length', 0))
        while len(self.pending) < end + length:
            self.receive()
        body = bytes(self.pending[end:end + length])
        del self.pending[:end + length]
        return lines[0], headers, body

    def receive(self):
        if self.read_key is None:
            part = self.sock.recv(65536)
            if not part:
                raise EOFError
        else:
            aad = self.exact(2)
            encrypted = self.exact(int.from_bytes(aad, 'little') + 16)
            nonce = b'\0' * 4 + self.read_counter.to_bytes(8, 'little')
            part = ChaCha20Poly1305(self.read_key).decrypt(nonce, encrypted, aad)
            self.read_counter += 1
        self.pending.extend(part)

    def send(self, plain):
        if self.write_key is None:
            self.sock.sendall(plain)
            return
        for i in range(0, len(plain), 1024):
            part = plain[i:i + 1024]
            aad = len(part).to_bytes(2, 'little')
            nonce = b'\0' * 4 + self.write_counter.to_bytes(8, 'little')
            self.sock.sendall(aad + ChaCha20Poly1305(self.write_key).encrypt(nonce, part, aad))
            self.write_counter += 1

    def reply(self, headers, body=b'', status=200):
        self.send((f'RTSP/1.0 {status} Result\r\nCSeq: {headers["cseq"]}\r\n'
                   f'Content-Length: {len(body)}\r\n'
                   'Content-Type: application/x-apple-binary-plist\r\n\r\n').encode() + body)


def listener(kind=socket.SOCK_STREAM):
    sock = socket.socket(socket.AF_INET, kind)
    sock.bind(('127.0.0.1', 0))
    if kind == socket.SOCK_STREAM:
        sock.listen()
    return sock


class Receiver:
    def __init__(self, reject=False, events=True):
        self.control = listener()
        self.event_listener = listener() if events else None
        self.audio = listener(socket.SOCK_DGRAM)
        self.rtcp = listener(socket.SOCK_DGRAM)
        self.server_key = ed25519.Ed25519PrivateKey.generate()
        self.client_key = ed25519.Ed25519PrivateKey.generate()
        self.requests = []
        self.condition = threading.Condition()
        self.error = None
        self.reject = reject
        self.secret = None
        self.wire = None
        self.event_wire = None
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    @property
    def credentials(self):
        seed = self.client_key.private_bytes(serialization.Encoding.Raw,
                                            serialization.PrivateFormat.Raw,
                                            serialization.NoEncryption())
        return (seed + public(self.client_key) + public(self.server_key)).hex()

    def serve(self):
        try:
            sock, _ = self.control.accept()
            self.wire = wire = Wire(sock)
            ephemeral = None
            verify_key = None
            while True:
                line, headers, body = wire.read()
                method, uri, _ = line.split(' ')
                parsed = plistlib.loads(body) if body.startswith(b'bplist00') else None
                with self.condition:
                    self.requests.append((method, uri, parsed, body))
                    self.condition.notify_all()
                if uri == '/pair-verify':
                    tlv = tlv_decode(body)
                    if tlv[6] == b'\x01':
                        ephemeral = x25519.X25519PrivateKey.generate()
                        client_public = tlv[3]
                        self.secret = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(client_public))
                        verify_key = hkdf(self.secret, 'Pair-Verify-Encrypt-Salt', 'Pair-Verify-Encrypt-Info')
                        identity = b'loopback-receiver'
                        signature = self.server_key.sign(public(ephemeral) + identity + client_public)
                        encrypted = ChaCha20Poly1305(verify_key).encrypt(
                            b'\0' * 4 + b'PV-Msg02', tlv_encode({1: identity, 10: signature}), None)
                        wire.reply(headers, tlv_encode({6: b'\x02', 3: public(ephemeral), 5: encrypted}))
                    else:
                        assert tlv[6] == b'\x03'
                        verified = tlv_decode(ChaCha20Poly1305(verify_key).decrypt(
                            b'\0' * 4 + b'PV-Msg03', tlv[5], None))
                        self.client_key.public_key().verify(verified[10], client_public + verified[1] + public(ephemeral))
                        wire.reply(headers, tlv_encode({6: b'\x04'}))
                        wire.read_key = hkdf(self.secret, 'Control-Salt', 'Control-Write-Encryption-Key')
                        wire.write_key = hkdf(self.secret, 'Control-Salt', 'Control-Read-Encryption-Key')
                    continue
                reply = {}
                status = 200
                if uri == '/info':
                    reply = {'name': 'Loopback', 'model': 'TestReceiver',
                             'supportedFormats': {'audio': 1 << 18}}
                elif method == 'SETUP':
                    if 'streams' not in parsed:
                        if self.event_listener:
                            reply = {'eventPort': self.event_listener.getsockname()[1]}
                    else:
                        reply = {'streams': [{'dataPort': self.audio.getsockname()[1],
                                             'controlPort': self.rtcp.getsockname()[1]}]}
                elif uri == '/command' and self.reject:
                    if parsed.get('type') == 'updateMRNowPlayingInfo':
                        status = 501
                wire.reply(headers, plistlib.dumps(reply, fmt=plistlib.FMT_BINARY), status)
                if method == 'TEARDOWN':
                    break
        except EOFError:
            pass
        except Exception as exc:
            self.error = exc
            with self.condition:
                self.condition.notify_all()

    def wait(self, predicate, timeout=10):
        with self.condition:
            assert self.condition.wait_for(lambda: self.error or predicate(self.requests), timeout), self.requests
            if self.error:
                raise self.error
            return list(self.requests)

    def event(self, value=None, **extra):
        if self.event_wire is None:
            sock, _ = self.event_listener.accept()
            self.event_wire = Wire(sock)
            self.event_wire.write_key = hkdf(self.secret, 'Events-Salt', 'Events-Write-Encryption-Key')
            self.event_wire.read_key = hkdf(self.secret, 'Events-Salt', 'Events-Read-Encryption-Key')
        cseq = 500 + self.event_wire.write_counter
        root = {'type': 'sendMediaRemoteCommand', 'value': value} if value else {'type': 'updateInfo'}
        root.update(extra)
        body = plistlib.dumps(root, fmt=plistlib.FMT_BINARY)
        self.event_wire.send((f'POST /command RTSP/1.0\r\nCSeq: {cseq}\r\n'
                              'Content-Type: application/x-apple-binary-plist\r\n'
                              f'Content-Length: {len(body)}\r\n\r\n').encode() + body)
        line, headers, response = self.event_wire.read()
        assert line == 'RTSP/1.0 200 OK', line
        assert headers['cseq'] == str(cseq)
        assert response == b''

    def close(self):
        if self.wire:
            self.wire.sock.close()
        if self.event_wire:
            self.event_wire.sock.close()
        for sock in (self.control, self.event_listener, self.audio, self.rtcp):
            if sock:
                sock.close()
        self.thread.join(2)
        if self.error:
            raise self.error


class Cli:
    def __init__(self, binary, receiver, directory, features, group=None, enabled=True):
        self.pipe = Path(directory) / ('command-' + uuid4().hex)
        args = [str(binary), '--protocol', 'airplay2', '--timing', 'ntp',
                '--port', str(receiver.control.getsockname()[1]), '--auth', receiver.credentials,
                '--txt', f'model=TestReceiver features={features}', '--cmdpipe', str(self.pipe),
                '--debug', '3', '--dacp', '0011223344556677']
        if group:
            args += ['--group-uuid', group]
        args += ['127.0.0.1']
        self.lines = []
        self.condition = threading.Condition()
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env={**os.environ, 'CLIAIRPLAY_MRP': '1' if enabled else '0'})
        self.readers = []
        for stream in (self.proc.stdout, self.proc.stderr):
            thread = threading.Thread(target=self.collect, args=(stream,), daemon=True)
            thread.start()
            self.readers.append(thread)
        self.wait('[STATUS] connected')

    def collect(self, stream):
        for raw in iter(stream.readline, b''):
            with self.condition:
                self.lines.append(raw.decode(errors='replace').strip())
                self.condition.notify_all()

    def wait(self, text):
        with self.condition:
            assert self.condition.wait_for(lambda: any(text in line for line in self.lines), 12), '\n'.join(self.lines)

    def send(self, text):
        with self.pipe.open('w') as writer:
            writer.write(text + '\n')

    def close(self):
        if self.proc.poll() is None:
            self.send('ACTION=DISCONNECT')
        try:
            code = self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            raise
        for thread in self.readers:
            thread.join(2)
        assert code == 0, '\n'.join(self.lines)
        assert not any('Sanitizer' in line or 'runtime error:' in line for line in self.lines), self.lines


def commands(requests):
    return [root for method, uri, root, _ in requests if method == 'POST' and uri == '/command']


def inspect_sequence(receiver, group):
    requests = receiver.wait(lambda rows: any(root and root.get('type') == 'updateMRNowPlayingClient'
                                            for _, _, root, _ in rows))
    setup = next(root for method, _, root, _ in requests if method == 'SETUP' and 'streams' not in root)
    assert setup['senderSupportsRelay'] is True
    assert setup['isMultiSelectAirPlay'] is True
    if group:
        assert setup['groupUUID'].upper() == group.upper()
    assert setup['sessionUUID'] != setup.get('groupUUID')
    sequence = commands(requests)
    assert [item.get('type', 'DEVICE_INFO') for item in sequence[:5]] == [
        'DEVICE_INFO', 'updateMRNowPlayingInfo', 'updateMRSupportedCommands',
        'updateMRPlaybackState', 'updateMRNowPlayingClient']
    blob = sequence[0]['params']['data']
    length, offset = varint(blob)
    assert length == len(blob) - offset
    envelope = protobuf(blob[offset:])
    assert envelope[1] == 15
    info = protobuf(envelope[20])
    assert info[41].decode() == setup['sessionUUID']
    if group:
        assert info[42].decode().upper() == group.upper()
    supported = sequence[2]['params']['mrSupportedCommandsFromSender']
    entries = [plistlib.loads(item) for item in supported]
    assert {entry['kCommandInfoCommandKey'] for entry in entries} == {0, 1, 2, 4, 5}, entries
    assert all(entry['kCommandInfoEnabledKey'] is True for entry in entries)
    client = protobuf(sequence[4]['params']['mrNowPlayingClient'])
    assert client[2] == b'com.apple.Music'
    wrapper = sequence[1]['params']
    assert wrapper['type'] == 'npi-text' and wrapper['mergePolicy'] == 'replace'
    nowplaying = wrapper['params']
    prefix = 'kMRMediaRemoteNowPlayingInfo'
    assert nowplaying[prefix + 'Title'] == 'Loopback Track'
    assert nowplaying[prefix + 'Artist'] == 'Test Artist'
    assert nowplaying[prefix + 'Album'] == 'Test Album'
    assert nowplaying[prefix + 'Duration'] == 180.0
    assert nowplaying[prefix + 'PlaybackRate'] == 0.0
    assert isinstance(nowplaying[prefix + 'UniqueIdentifier'], int)
    assert nowplaying[prefix + 'ArtworkMIMEType'] == 'image/jpeg'
    artwork = Path(__file__).parent / 'fixtures' / 'sof1-8bit-dqt16.jpg'
    assert nowplaying[prefix + 'ArtworkData'] == artwork.read_bytes()
    return setup['sessionUUID']


def run(binary):
    with tempfile.TemporaryDirectory(prefix='cliairplay-mrp-') as directory:
        group = str(uuid4())
        sessions = []
        # A receiver that wants only MRP and a receiver with all legacy metadata.
        for features in ('0x0,0x40000', '0x38000,0x40000'):
            receiver = Receiver()
            cli = None
            try:
                cli = Cli(binary, receiver, directory, features, group)
                artwork = Path(__file__).parent / 'fixtures' / 'sof1-8bit-dqt16.jpg'
                cli.send(f'TITLE=Loopback Track\nARTIST=Test Artist\nALBUM=Test Album\nITEMID=loopback-1\n'
                         f'DURATION=180\nARTWORKFILE={artwork.resolve()}\nACTION=SENDMETA')
                sessions.append(inspect_sequence(receiver, group))
                # Every control traverses a real reverse TCP socket and AEAD frames.
                for value, expected in [('play', 'play'), ('paus', 'pause'), ('plps', 'play_pause'),
                                        ('nitm', 'next'), ('pitm', 'previous')]:
                    receiver.event(value)
                    cli.wait(f'[EVENT] remote command={expected}')
                for code, expected in [('0', 'play'), ('1', 'pause'), ('2', 'play_pause'),
                                       ('4', 'next'), ('5', 'previous')]:
                    with cli.condition:
                        before = len(cli.lines)
                    receiver.event(type='sendMediaRemoteCommand', modernMediaRemoteCommand=code)
                    with cli.condition:
                        assert cli.condition.wait_for(
                            lambda: any(f'[EVENT] remote command={expected}' in line
                                        for line in cli.lines[before:]), 5), cli.lines[before:]
                receiver.event('dvlc', volume=0.42)
                cli.wait('[EVENT] volume value=0.420000')
                receiver.event('dvlc', params={'volume': 1})
                cli.wait('[EVENT] volume value=1.000000')
                receiver.event('dvlc', volume=float('nan'))
                receiver.event()
                # Drive actual PCM and pause/resume timeline publication.
                cli.proc.stdin.write(b'\0' * (352 * 4 * 8))
                cli.proc.stdin.flush()
                cli.wait('[STATUS] audio buffered_ms=')
                cli.send('START_UNIX_MS=0\nACTION=START')
                cli.wait('[STATUS] started')
                receiver.audio.settimeout(5)
                packet, _ = receiver.audio.recvfrom(8192)
                second_packet, _ = receiver.audio.recvfrom(8192)
                for audio_packet in (packet, second_packet):
                    assert audio_packet[0] == 0x80 and audio_packet[1] & 0x7f == 96
                    sequence = int.from_bytes(audio_packet[2:4], 'big')
                    assert audio_packet[-8:] == sequence.to_bytes(2, 'little') + b'\0' * 6
                    ChaCha20Poly1305(receiver.secret).decrypt(
                        b'\0' * 4 + audio_packet[-8:], audio_packet[12:-8], audio_packet[4:12])
                assert (int.from_bytes(second_packet[2:4], 'big') - int.from_bytes(packet[2:4], 'big')) & 0xffff == 1
                assert (int.from_bytes(second_packet[4:8], 'big') - int.from_bytes(packet[4:8], 'big')) & 0xffffffff == 352
                cli.send('ACTION=PAUSE')
                cli.wait('[STATUS] paused')
                receiver.wait(lambda rows: any(root and root.get('type') == 'updateMRPlaybackState'
                                               and root['params'].get('mrPlaybackState') == 2
                                               for _, _, root, _ in rows))
                cli.send('ACTION=PLAY')
                receiver.wait(lambda rows: sum(bool(root and root.get('type') == 'updateMRPlaybackState'
                                               and root['params'].get('mrPlaybackState') == 1)
                                               for _, _, root, _ in rows) >= 2)
                rows = list(receiver.requests)
                if features.startswith('0x0,'):
                    assert not any(method == 'SET_PARAMETER' and body.startswith(b'mlit')
                                   for method, _, _, body in rows)
                    assert not any(method == 'SET_PARAMETER' and body.startswith(b'\xff\xd8')
                                   for method, _, _, body in rows)
                print(f'PASS {features}: HAP verification, SETUP relay/group, MRP sequence/identity, '
                      'five controls, volume, unknown ACK, PCM, pause/resume')
            finally:
                if cli:
                    cli.close()
                receiver.close()
        assert sessions[0] != sessions[1], 'Separate member sessions must not share sessionUUID'
        for features, enabled in [('0x38000,0x0', True), ('0x38000,0x40000', False)]:
            receiver = Receiver()
            cli = None
            try:
                cli = Cli(binary, receiver, directory, features, enabled=enabled)
                cli.send('TITLE=No MRP\nACTION=SENDMETA')
                receiver.wait(lambda rows: any(method == 'SET_PARAMETER' and body.startswith(b'mlit')
                                              for method, _, _, body in rows))
                cli.close()
                cli = None
                assert not commands(receiver.requests)
                setup = next(root for method, _, root, _ in receiver.requests
                             if method == 'SETUP' and 'streams' not in root)
                assert not setup.get('senderSupportsRelay', False)
                assert not setup.get('isMultiSelectAirPlay', False)
                print(f'PASS feature/opt-out isolation: {features} enabled={enabled}')
            finally:
                if cli:
                    cli.close()
                receiver.close()
        receiver = Receiver(reject=True, events=False)
        cli = None
        try:
            cli = Cli(binary, receiver, directory, '0x38000,0x40000')
            cli.send('TITLE=Refused Track\nITEMID=reject-1\nACTION=SENDMETA')
            cli.wait('[STATUS] mrp path=command status=501')
            cli.send('TITLE=Next Track\nITEMID=reject-2\nACTION=SENDMETA\nPROGRESS=4')
            receiver.wait(lambda rows: sum(method == 'SET_PARAMETER' and body.startswith(b'mlit')
                                          for method, _, _, body in rows) >= 2)
            cli.close()
            cli = None
            assert len(commands(receiver.requests)) == 2, commands(receiver.requests)
            print('PASS missing event socket: outgoing MRP remains available; '
                  '501 disables later MRP without stopping the session')
        finally:
            if cli:
                cli.close()
            receiver.close()
    print('All real-CLI loopback protocol scenarios passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary.resolve())
