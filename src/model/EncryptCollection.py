from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.util import encrypter

NONCE_LEN = 12

@dataclass(kw_only=True)
class EncryptCollection:
    salt:bytes = None
    myX25519PivKey:X25519PrivateKey = None
    otherPartyX25519PubKey:X25519PublicKey = None
    sharedSecret:bytes = None
    def deriveSharedSecretByX25519(self, info:bytes) -> None:
        self.sharedSecret = encrypter.deriveSecretByX25519(self.myX25519PivKey, self.otherPartyX25519PubKey, self.salt, info)
    aesKey:AESGCM = None
    def deriveAesKey(self, info:bytes) -> None:
        self.aesKey = encrypter.deriveAesKey(self.sharedSecret, self.salt, info)
    def deriveNonce(self, info:bytes) -> bytes:
        return encrypter.deriveBytesBySecret(self.sharedSecret, self.salt, info, NONCE_LEN)

@dataclass(kw_only=True)
class PrivateEncryptCollection:
    sharedSecret:bytes
    salt:bytes
    aesKey:AESGCM = None
    def deriveAesKey(self, info:bytes) -> None:
        self.aesKey = encrypter.deriveAesKey(self.sharedSecret, self.salt, info)
    def deriveNonce(self, info:bytes) -> bytes:
        return encrypter.deriveBytesBySecret(self.sharedSecret, self.salt, info, NONCE_LEN)