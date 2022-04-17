import threading
import time
import hashlib
import grpc

from typing import Optional
from hashlib import sha1

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key

import backend_pb2 as bs
import backend_pb2_grpc as bss

import frontend_pb2 as fs
import frontend_pb2_grpc as fss

from message import Message
from envelope import Envelope
from node_data import NodeData, StoredItem
from stabilizer import Stabilizer
from dht_ops import dht_lookup, dht_set, dht_get


class BackendServicer(bss.BackendServiceServicer):
    def __init__(self, addr: str, known_node: Optional[str] = None):
        self.__connected = False
        self.__private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.__public_key = self.__private_key.public_key()
        self.__known_messages = set()

        self.__node_data = NodeData(addr, [])

        self.__stabilizer = Stabilizer(self.__node_data)
        self.__stabilizer.start()

        if known_node is not None:
            with self.__node_data.lock:
                docking_addr = dht_lookup(addr, known_node)
                self.__node_data.succ = docking_addr
                print(f'connecting to {docking_addr}')
                docking_stub = bss.BackendServiceStub(grpc.insecure_channel(docking_addr))
                docking_stub.Dock(bs.NodeAddress(address=addr))
                for item in docking_stub.CopyData(bs.NodeAddress(address=addr)):
                    stored_item = StoredItem(item.hash, item.data)
                    self.__node_data.stored_items.append(stored_item)

    # frontend methods

    def Connect(self, request, context):
        if self.__connected:
            return bs.SimpleResponse(ok=False, desc='already connected')

        self.__frontend = fss.FrontendServiceStub(grpc.insecure_channel(request.frontendUrl))

        pubkey_str = self.__public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()

        username = request.username

        dht_set(username, pubkey_str, self.__node_data.addr)
        dht_set(pubkey_str, username, self.__node_data.addr)

        return bs.SimpleResponse(ok=True)


    def SendMessage(self, request, context):
        with self.__node_data.lock:
            if self.__node_data.succ is None:
                return bs.SimpleResponse(ok=False, desc='not in network')
        username = request.username
        text = request.text
        sign = request.sign
        ttl = request.ttl
        rec_pub_key_str = dht_get(username, self.__node_data.addr)
        if rec_pub_key_str is None:
            return bs.SimpleResponse(ok=False, desc='username not found')
        rec_pub_key = load_der_public_key(bytes.fromhex(rec_pub_key_str))
        if sign:
            message = Message.make_signed(text, self.__public_key, self.__private_key)
        else:
            message = Message.make_unsigned(text)
        envelope = Envelope.make(message, ttl, rec_pub_key)

        sender = threading.Thread(target=self.__send_message, args=[envelope.serialize()])
        sender.setDaemon(False)
        sender.start()

        return bs.SimpleResponse(ok=True)

    # whisper methods

    def HandleMewEnvelope(self, request, context):
        envelope_b = request.envelope 
        envelope = Envelope.deserialized(envelope_b)
        if not envelope.is_version_valid():
            print('invalid envelope version')
            return bs.SimpleResponse(ok=False)
        if not envelope.is_nonce_valid():
            print('invalid envelope nonce')
            return bs.SimpleResponse(ok=False)
        if envelope.is_expired():
            print('envelope expired')
            return bs.SimpleResponse(ok=False)

        sender = threading.Thread(target=self.__send_message, args=[envelope_b])
        sender.setDaemon(False)
        sender.start()

        if self.__is_known(envelope_b):
            return bs.SimpleResponse(ok=True)

        message = envelope.get_message(self.__private_key)
        if not message:
            return bs.SimpleResponse(ok=True)
        sender = None
        if message.is_signed():
            if message.is_signature_valid():
                sender = dht_get(message.get_sender_pubkey_hex(), self.__node_data.addr)
            else:
                print('message has invalid signature')
        else:
            print('message unsigned')
        print('got new message for us')

        self.__frontend.ProcessNewMessage(fs.FsMessage(text=message.get_payload_str(), username=sender))

        return bs.SimpleResponse(ok=True)

    # dht methods

    def Ping(self, request, context):
        return bs.NullMessage()


    def Dock(self, request, context):
        print(f'docking req from {request.address}')
        with self.__node_data.lock:
            self.__node_data.pred = request.address
            print(f'new pred: {self.__node_data.pred}')
            if self.__node_data.succ is None:
                self.__node_data.succ = request.address
                print(f'new succ: {self.__node_data.succ}')
        return bs.NullMessage()

    
    def GetSucc(self, request, context):
        with self.__node_data.lock:
            if self.__node_data.succ is None:
                return bs.OptionalNodeAddress(hasValue=False)
            return bs.OptionalNodeAddress(
                hasValue=True,
                nodeAddress=bs.NodeAddress(
                    address=self.__node_data.succ
                )
            )


    def GetPred(self, request, context):
        with self.__node_data.lock:
            if self.__node_data.pred is None:
                return bs.OptionalNodeAddress(hasValue=False)
            return bs.OptionalNodeAddress(
                hasValue=True,
                nodeAddress=bs.NodeAddress(
                    address=self.__node_data.pred
                )
            )


    def GetItem(self, request, context):
        required_hash = request.hash
        print(f'getting {required_hash}')
        with self.__node_data.lock:
            for item in self.__node_data.stored_items:
                if required_hash == item.hash:
                    return bs.OptionalStoredItem(
                        hasValue=True,
                        storedItem=bs.StoredItem(
                            hash=item.hash,
                            data=item.data
                        )
                    )
        return bs.OptionalStoredItem(hasValue=False)


    def SetItem(self, request, context):
        new_hash = request.hash
        new_data = request.data
        print(f'setting {new_hash} -> {new_data}')
        with self.__node_data.lock:
            if all(map(lambda i: i.hash != new_hash, self.__node_data.stored_items)):
                self.__node_data.stored_items.append(
                    StoredItem(new_hash, new_data)
                )
        return bs.NullMessage()


    def CopyData(self, request, context):
        requester_hash = sha1(request.address.encode()).hexdigest()
        with self.__node_data.lock:
            for item in self.__node_data.stored_items:
                if item.hash <= requester_hash:
                    yield bs.StoredItem(
                        hash=item.hash,
                        data=item.data
                    )

    # util methods

    def __send_message(self, message: bytes):
        with self.__node_data.lock:
            channel = grpc.insecure_channel(self.__node_data.succ)
        stub = bss.BackendServiceStub(channel)
        stub.HandleMewEnvelope(bs.Envelope(envelope=message))


    def __is_known(self, envelope: bytes) -> bool:
        hash = hashlib.sha256(envelope).hexdigest()
        if hash in self.__known_messages:
            return True
        self.__known_messages.add(hash)
        return False
