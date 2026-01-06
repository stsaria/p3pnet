from time import time
from threading import Lock

from src.interfaces.Manager import CannotDeleteAndWriteKVManager
from src.util.ed25519 import Ed25519PublicKey

class IpToEd25519PubKeys(CannotDeleteAndWriteKVManager):
    _ipToEd25519PubKeys:dict[str, tuple[int, Ed25519PublicKey]] = {}
    _ipToEd25519PubKeysLock:Lock = Lock()

    @classmethod
    def put(cls, ip:str, publicKey:Ed25519PublicKey) -> bool:
        with cls._ipToEd25519PubKeysLock:
            if previous := cls._ipToEd25519PubKeys.get(ip):
                return previous[1].public_bytes_raw() == publicKey.public_bytes_raw()
            cls._ipToEd25519PubKeys[ip] = publicKey
        return True
    
    @classmethod
    def get(cls, ip:str) -> Ed25519PublicKey | None:
        with cls._ipToEd25519PubKeysLock:
            return cls._ipToEd25519PubKeys.get(ip)
    
    @classmethod
    def gc(cls, deleteTime:int) -> None:
        with cls._ipToEd25519PubKeysLock:
            for ip, (t, _) in cls._ipToEd25519PubKeys:
                if time() - t >= deleteTime:
                    cls._ipToEd25519PubKeys.pop(ip)