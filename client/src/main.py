import threading
import requests
import socket
import sys
import hashlib

from flask import Flask, request
from time import sleep

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key

from envelope import Envelope
from message import Message

port_set_lock = threading.Lock()

known_message_hashes = set()


self_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
self_public_key = self_private_key.public_key()


def is_known(envelope: bytes) -> bool:
    hash = hashlib.sha256(envelope).hexdigest()
    if hash in known_message_hashes:
        return True
    known_message_hashes.add(hash)
    return False


class WhisperWriter(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.__sock = socket.socket()
        self.__ip = ''
        self.__port = 0

    def send(self, message: bytes):
        sleep(1)
        port_set_lock.acquire()
        sock = socket.socket()
        sock.connect((self.__ip, self.__port))
        sock.send(message)
        sock.close()
        port_set_lock.release()

    def set_addr(self, adr: str):
        port_set_lock.acquire()
        self.__ip = adr.split(':')[0]
        self.__port = int(adr.split(':')[1])
        port_set_lock.release()

    def run(self):
        print('ready to write')
        while True:
            rec_bup_key_str = input()
            sign = input('sign? y/n: ') == 'y'
            ttl = int(input('ttl: '))
            rec_pub_key = load_der_public_key(bytes.fromhex(rec_bup_key_str))
            payload = input('message: ')
            if sign:
                message = Message.make_signed(payload, self_public_key, self_private_key)
            else:
                message = Message.make_unsigned(payload)
            envelope = Envelope.make(message, ttl, rec_pub_key)
            self.send(envelope.serialize())


writer = WhisperWriter()
app = Flask(__name__)

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


class WhisperReader(threading.Thread):
    def __init__(self, port: int):
        threading.Thread.__init__(self)
        self.__sock = socket.socket()
        self.__sock.bind(('', port))
        self.__sock.listen(1)

    def run(self):
        print('ready to read')
        while True:
            conn, _ = self.__sock.accept()
            envelope_b = conn.recv(2048)
            if not envelope_b:
                continue
            envelope = Envelope.deserialized(envelope_b)
            if not envelope.is_version_valid():
                print('invalid envelope version')
                continue
            if not envelope.is_nonce_valid():
                print('invalid envelope nonce')
                continue
            if envelope.is_expired():
                print('envelope expired')
                continue

            writer.send(envelope_b)

            if is_known(envelope_b):
                print('got duplicate envelope')
                continue

            message = envelope.get_message(self_private_key)
            if not message:
                print('message is for another user')
                continue
            if message.is_signed():
                if message.is_signature_valid():
                    print('\nsender pub key:\n')
                    print(message.get_sender_pubkey_hex())
                    print()
                else:
                    print('message has invalid signature')
            else:
                print('\nmessage unsigned')

            print(f'got new message: {message.get_payload_str()}\n')

                
@app.post('/redock')
def redock():
    new_next = request.json['next']
    print(f'redocking to {new_next}', file=sys.stdout)
    writer.set_addr(new_next)
    return '', 200


def main():
    self_whisper_port = int(input('whisper port: '))
    self_redock_port = int(input('redock port: '))
    docker_url = input('docker url: ')

    print('\nyour pubkey is:\n')
    print(self_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex())
    print()

    docker_resp = requests.post(f'{docker_url}/dock', json={'whisper_port': self_whisper_port, 'redock_port': self_redock_port})

    if not docker_resp:
        print('could not connect to the docker server')
        return

    next_addr = docker_resp.json()['next']

    print(f'docking to {next_addr}')

    reader = WhisperReader(self_whisper_port)
    reader.start()

    writer.set_addr(next_addr)
    writer.start()

    app.run(host='0.0.0.0', port=self_redock_port, debug=False)

    writer.join()
    reader.join()


if __name__ == '__main__':
    main()
