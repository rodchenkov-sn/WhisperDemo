from dataclasses import dataclass

from typing import Optional
from math import ceil

from rsa import PublicKey, PrivateKey

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key


@dataclass
class Message:
    DER_PUB_KEY_LEN = 294
    SIGNATURE_LEN = 256
    HAS_SIGNATURE_FLAG = (1).to_bytes(1, 'big')
    NO_SIGNATURE_FLAG = (0).to_bytes(1, 'big')

    flags: bytes
    payload: bytes
    der: Optional[bytes] = None
    signature: Optional[bytes] = None

    @classmethod
    def make_unsigned(cls, payload_str: str) -> 'Message':
        return Message(cls.NO_SIGNATURE_FLAG, payload_str.encode())

    @classmethod
    def make_signed(cls, payload_str: str, pub_key: PublicKey, priv_key: PrivateKey) -> 'Message':
        payload = payload_str.encode()
        der_bytes = pub_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        signature = priv_key.sign(
            payload,
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return Message(cls.HAS_SIGNATURE_FLAG, payload, der_bytes, signature)

    @classmethod
    def decrypted(cls, data: bytes, priv_key: PrivateKey) -> Optional['Message']:
        try:
            l = len(data)
            parts = ceil(l / 256)
            decrypted = b''
            for p in range(parts):
                if p == parts - 1:
                    d = data[256*p:]
                else:
                    d = data[256*p:256*(p+1)]
                decrypted = decrypted + priv_key.decrypt(
                    d,
                    padding.OAEP(
                        padding.MGF1(hashes.SHA256()),
                        hashes.SHA256(),
                        None
                    )
                )
            if decrypted.startswith(cls.HAS_SIGNATURE_FLAG):
                payload = decrypted[1:-(cls.DER_PUB_KEY_LEN + cls.SIGNATURE_LEN)]
                der = decrypted[-(cls.DER_PUB_KEY_LEN + cls.SIGNATURE_LEN):-cls.SIGNATURE_LEN]
                signature = decrypted[-cls.SIGNATURE_LEN:]
                return Message(cls.HAS_SIGNATURE_FLAG, payload, der, signature)
            payload = decrypted[1:]
            return Message(cls.NO_SIGNATURE_FLAG, payload)
        except:
            return None

    def encrypt(self, pub_key: PublicKey) -> bytes:
        data = self.flags + self.payload + (self.der if self.der is not None else b'') \
            + (self.signature if self.signature is not None else b'')
        l = len(data)
        parts = ceil(l / 100)
        encrypted = b''
        for p in range(parts):
            if p == parts - 1:
                d = data[100*p:]
            else:
                d = data[100*p:100*(p+1)]
            encrypted += pub_key.encrypt(
                d,
                padding.OAEP(
                    padding.MGF1(hashes.SHA256()),
                    hashes.SHA256(),
                    None
                )
            )
        return encrypted

    def is_signed(self) -> bool:
        return self.signature is not None

    def is_signature_valid(self) -> bool:
        if not self.is_signed():
            raise ValueError('no signature')
        try:
            pubkey = load_der_public_key(self.der)
            pubkey.verify(
                self.signature,
                self.payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True
        except:
            return False

    def get_sender_pubkey_hex(self) -> str:
        if self.der is None:
            raise ValueError('no der key')
        pubkey = load_der_public_key(self.der)
        return pubkey.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()

    def get_payload_str(self) -> str:
        return self.payload.decode()
