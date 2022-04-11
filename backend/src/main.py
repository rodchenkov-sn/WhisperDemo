import requests
import threading
import time
import socket
import grpc

from concurrent import futures

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key

from flask import Flask, request

import backend_pb2 as bs
import backend_pb2_grpc as bss

import frontend_pb2 as fs
import frontend_pb2_grpc as fss

from message import Message
from envelope import Envelope
from users_repo import UsersRepo
from whisper_reader import WhisperReader


app = Flask(__name__)

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


class FlaskRunner(threading.Thread):
    def __init__(self, host: str, port: int):
        super().__init__()
        self.__host = host
        self.__port = port

    def run(self):
        app.run(self.__host, self.__port, debug=False)


class BackendServicer(bss.BackendServiceServicer):
    def __init__(self):
        super().__init__()
        self.__send_message_lock = threading.Lock()
        self.__connected = False
        self.__private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.__public_key = self.__private_key.public_key()


    def Connect(self, request, context):
        if self.__connected:
            return bs.SimpleResponse(ok=False, desc='already connected')
        self.__connected = True
        self.__docking_url = request.dockingUrl
        self.__whisper_port = request.whisperPort
        self.__redock_port = request.redockPort
        self.__users_repo = UsersRepo(self.__docking_url)
        self.__whisper_reader = WhisperReader(self.__whisper_port, self.__private_key, request.frontendUrl, self.__users_repo, self)
        self.__redocker_runner = FlaskRunner('0.0.0.0', self.__redock_port)

        docker_resp = requests.post(f'{self.__docking_url}/dock', json={
            'whisper_port': self.__whisper_port, 
            'redock_port': self.__redock_port,
            'username': request.username,
            'pubkey': self.__public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ).hex()
            }
        )

        if not docker_resp:
            return bs.SimpleResponse(ok=False, desc='cant connect to the docking server')

        self.__next_addr = docker_resp.json()['next']
        print(f'docking to {self.__next_addr}')

        self.__whisper_reader.start()
        self.__redocker_runner.start()

        return bs.SimpleResponse(ok=True)


    def GetUsers(self, request, context):
        self.__users_repo.full_update()
        for u in self.__users_repo.get_usernames():
            yield bs.User(username=u)


    def SendMessage(self, request, context):
        username = request.username
        text = request.text
        sign = request.sign
        ttl = request.ttl
        rec_pub_key_str = self.__users_repo.get_pubkey(username)
        rec_pub_key = load_der_public_key(bytes.fromhex(rec_pub_key_str))
        if sign:
            message = Message.make_signed(text, self.__public_key, self.__private_key)
        else:
            message = Message.make_unsigned(text)
        envelope = Envelope.make(message, ttl, rec_pub_key)
        self.send_message(envelope.serialize())
        return bs.SimpleResponse(ok=True)


    def request_reconnect(self, new_next: str):
        print(f'redocking to {new_next}')
        self.__send_message_lock.acquire()
        self.__next_addr = new_next
        self.__send_message_lock.release()


    def send_message(self, message: bytes):
        ip = self.__next_addr.split(':')[0]
        port = int(self.__next_addr.split(':')[1])
        time.sleep(1)
        self.__send_message_lock.acquire()
        sock = socket.socket()
        sock.connect((ip, port))
        sock.send(message)
        sock.close()
        self.__send_message_lock.release()


backend_servicer = BackendServicer()


@app.post('/redock')
def redock():
    new_next = request.json['next']
    backend_servicer.request_reconnect(new_next)
    return '', 200


def main():
    port = int(input('port: '))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    bss.add_BackendServiceServicer_to_server(backend_servicer, server)
    server.add_insecure_port(f'[::]:{port}')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    main()
