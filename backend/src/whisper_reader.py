import threading
import socket
import grpc
import hashlib

import frontend_pb2 as fs
import frontend_pb2_grpc as fss

from rsa import PrivateKey

from users_repo import UsersRepo
from envelope import Envelope
from message import Message
from whisper_writer import WhisperWriter


class WhisperReader(threading.Thread):
    def __init__(self, port: int, priv_key: PrivateKey, frontend_adr: str, users_repo: UsersRepo, writer: WhisperWriter):
        super().__init__()
        self.__sock = socket.socket()
        self.__sock.bind(('', port))
        self.__sock.listen(1)
        self.__known_messages = set()
        self.__private_key = priv_key
        self.__channel = grpc.insecure_channel(frontend_adr)
        self.__frontend = fss.FrontendServiceStub(self.__channel)
        self.__users_repo = users_repo
        self.__writer = writer


    def is_known(self, envelope: bytes) -> bool:
        hash = hashlib.sha256(envelope).hexdigest()
        if hash in self.__known_messages:
            return True
        self.__known_messages.add(hash)
        return False


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

            self.__writer.send_message(envelope_b)

            if self.is_known(envelope_b):
                print('got duplicate envelope')
                continue

            message = envelope.get_message(self.__private_key)
            if not message:
                print('message is for another user')
                continue
            sender = None
            if message.is_signed():
                if message.is_signature_valid():
                    sender = self.__users_repo.get_username(message.get_sender_pubkey_hex())
                else:
                    print('message has invalid signature')
            else:
                print('message unsigned')
            print('got new message for us')
            self.__frontend.ProcessNewMessage(fs.FsMessage(text=message.get_payload_str(), username=sender))