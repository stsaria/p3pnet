from enum import Enum
from threading import Lock
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.util import ed25519
from src.util.ed25519 import Ed25519PrivateKey
from src.interfaces.Manager import CannotDeleteKVManager

class NameIsTooLongException(Exception):
    pass

class MyInfoKey(Enum):
    ED25519_PRIVATE_KEY = 1
    NAME = 2

VALUE = Ed25519PrivateKey | str

class MyInfo(CannotDeleteKVManager):
    _infos:dict[MyInfoKey, Any] = {
        MyInfoKey.ED25519_PRIVATE_KEY, ed25519.generatePivKey(), 
        MyInfoKey.NAME, "HappyTaro"
    }
    _infosLock:Lock = Lock()
    @classmethod
    def put(cls, myInfoKey:MyInfoKey, value:VALUE) -> VALUE | None:
        with cls._infosLock:
            oldV = cls._infos.get(myInfoKey)
            cls._infos[myInfoKey] = value
        return oldV
    @classmethod
    def get(cls, myInfoKey:MyInfoKey) -> VALUE | None:
        with cls._infosLock:
            return cls._infos.get(myInfoKey)