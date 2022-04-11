from dataclasses import dataclass
from datetime import datetime
from math import ceil, sqrt
from hashlib import sha256
from typing import Optional

from rsa import PrivateKey, PublicKey

from message import Message


@dataclass
class Envelope:
    VERSION = (0).to_bytes(1, 'big')
    MAX_NONCE = 2 ** 64
    
    version: bytes
    expiry: bytes
    ttl: bytes
    data: bytes
    nonce: bytes

    @classmethod
    def make(cls, message: Message, ttl: int, pub_key: PublicKey) -> Optional['Envelope']:
        now = int(datetime.now().timestamp())
        expiry = now + ttl

        version_b = cls.VERSION
        expiry_b = expiry.to_bytes(4, 'big')
        ttl_b = ttl.to_bytes(4, 'big')
        data_b = message.encrypt(pub_key)
        nonce_b = cls.__calc_nonce(version_b + expiry_b + ttl_b + data_b, ttl)
        if nonce_b is None:
            None
        return Envelope(version_b, expiry_b, ttl_b, data_b, nonce_b)

    @classmethod
    def deserialized(cls, envelope_b: bytes) -> 'Envelope':
        version = envelope_b[:1]
        expiry = envelope_b[1:5]
        ttl = envelope_b[5:9]
        data = envelope_b[9:-8]
        nonce = envelope_b[-8:]
        return Envelope(version, expiry, ttl, data, nonce)

    @classmethod
    def __calc_nonce_difficulty(cls, ttl: int, size: int) -> int:
        return ceil(max(sqrt(size / 256 * ttl), 1))

    @classmethod
    def __calc_nonce_target(cls, ttl: int, size: int) -> str:
        difficulty = cls.__calc_nonce_difficulty(ttl, size)
        return 2 ** (256 - difficulty)

    @classmethod
    def __calc_nonce(cls, data: bytes, ttl: int) -> Optional[bytes]:
        future_size = len(data) + 8
        nonce_target = cls.__calc_nonce_target(ttl, future_size)
        print(f'difficulty: {cls.__calc_nonce_difficulty(ttl, future_size)} calculating nonce...')
        for nonce in range(cls.MAX_NONCE):
            hash_res = sha256(data + nonce.to_bytes(8, 'big')).hexdigest()
            if int(hash_res, 16) < nonce_target:
                print(f'nonce found: {nonce}')
                return nonce.to_bytes(8, 'big')
        print('could not find nonce')
        return None
    
    def serialize(self) -> bytes:
        return self.version + self.expiry + self.ttl + self.data + self.nonce

    def is_version_valid(self) -> bool:
        return self.version == self.VERSION

    def is_nonce_valid(self) -> bool:
        target = self.__calc_nonce_target(int.from_bytes(self.ttl, 'big'), len(self.serialize()))
        return int(sha256(self.serialize()).hexdigest(), 16) < target

    def is_expired(self) -> bool:
        now = int(datetime.now().timestamp())
        return now > int.from_bytes(self.expiry, 'big')

    def get_message(self, priv_key: PrivateKey) -> Optional[Message]:
        return Message.decrypted(self.data, priv_key)
