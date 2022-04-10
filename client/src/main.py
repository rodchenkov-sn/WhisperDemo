import threading
import requests
import socket
import sys
import datetime
import hashlib

from math import ceil
from flask import Flask, request
from time import sleep
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature
from rsa import PublicKey, PrivateKey


PROTOCOL_VERSION = (0).to_bytes(1, 'big')
MAX_NONCE = 2 ** 64
NONCE_TARGET = '00000'
DER_PUB_KEY_LEN = 294
SIGNATURE_LEN = 256


port_set_lock = threading.Lock()

known_message_hashes = set()


self_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
self_public_key = self_private_key.public_key()


def add_proof_of_work(data: bytes) -> bytes:
    for nonce in range(MAX_NONCE):
        hash_res = hashlib.sha256(data + nonce.to_bytes(8, 'big')).hexdigest()
        if hash_res.endswith(NONCE_TARGET):
            print(f'nonce found: {nonce}')
            return data + nonce.to_bytes(8, 'big')
    return data + (0) + nonce.to_bytes(8, 'big')


def sign_data(data: bytes) -> bytes:
    der_bytes = self_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signature = self_private_key.sign(
        data,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return data + der_bytes + signature


def encrypt_data(data: bytes, pubkey: PublicKey) -> bytes:
    l = len(data)
    parts = ceil(l / 100)
    encrypted = b''
    for p in range(parts):
        if p == parts - 1:
            d = data[100*p:]
        else:
            d = data[100*p:100*(p+1)]
        encrypted += pubkey.encrypt(
            d,
            padding.OAEP(
                padding.MGF1(hashes.SHA256()),
                hashes.SHA256(),
                None
            )
        )
    return encrypted


def decrypt_data(data: bytes, key: PrivateKey) -> Optional[bytes]:
    try:
        l = len(data)
        parts = ceil(l / 256)
        decrypted = b''
        for p in range(parts):
            if p == parts - 1:
                d = data[256*p:]
            else:
                d = data[256*p:256*(p+1)]
            decrypted = decrypted + key.decrypt(
                d,
                padding.OAEP(
                    padding.MGF1(hashes.SHA256()),
                    hashes.SHA256(),
                    None
                )
            )
        return decrypted
    except:
        return None


def make_envelope(data: bytes) -> bytes:
    now = int(datetime.datetime.now().timestamp())
    ttl = 20
    expiry = now + ttl
    envelope = PROTOCOL_VERSION + expiry.to_bytes(4, 'big') + ttl.to_bytes(4, 'big') + data
    return add_proof_of_work(envelope)


def is_valid_version(envelope: bytes) -> bool:
    return envelope.startswith(PROTOCOL_VERSION)


def has_expired(envelope: bytes) -> bool:
    expiry = int.from_bytes(envelope[1:5], 'big')
    now = int(datetime.datetime.now().timestamp())
    return now > expiry


def has_pow(envelope: bytes) -> bool:
    return hashlib.sha256(envelope).hexdigest().endswith(NONCE_TARGET)


def is_known(envelope: bytes) -> bool:
    hash = hashlib.sha256(envelope).hexdigest()
    if hash in known_message_hashes:
        return True
    known_message_hashes.add(hash)
    return False


def get_data(envelope: bytes) -> bytes:
    return envelope[9:-8]


def get_message(data: bytes) -> bytes:
    return data[:-(DER_PUB_KEY_LEN + SIGNATURE_LEN)]


def get_pubkey(data: bytes) -> bytes:
    return data[-(DER_PUB_KEY_LEN + SIGNATURE_LEN):-SIGNATURE_LEN]


def get_signature(data: bytes) -> bytes:
    return data[-SIGNATURE_LEN:]


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
            rec_pub_key = load_der_public_key(bytes.fromhex(rec_bup_key_str))
            message = input('message: ').encode()
            self.send(make_envelope(encrypt_data(sign_data(message), rec_pub_key)))


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
            envelope = conn.recv(2048)
            if not envelope:
                continue
            if not is_valid_version(envelope):
                print('got invalid envelope')
                continue
            if has_expired(envelope):
                print('got expired envelope')
                continue
            if not has_pow(envelope):
                print('got envelope without pow')
                continue
            print('got valid envelope')
            writer.send(envelope)

            encrypted_data = get_data(envelope) 

            data = decrypt_data(encrypted_data, self_private_key)
            if data is None:
                print('envelope is for another user')
                continue

            if is_known(envelope):
                print('got duplicate message')
                continue
            else:
                print('got new message for us')

            message = get_message(data)

            pubkey = load_der_public_key(get_pubkey(data))
            signature = get_signature(data)

            try:
                pubkey.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print('message verified, sender pubkey: \n')
                print(pubkey.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ).hex())
                print()
            except InvalidSignature:
                print('message unverified')
                continue

            print(f'message: {message.decode()}\n')

                
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
