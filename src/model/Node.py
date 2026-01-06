from dataclasses import dataclass

from src.util.ed25519 import Ed25519PublicKey

@dataclass(frozen=True, kw_only=True)
class Node:
    ip:str
    port:int
    name:str
    ed25519PublicKey:Ed25519PublicKey
    def __hash__(self) -> int:
        return hash((self.ip, self.port, self.name, self.ed25519PublicKey.public_bytes_raw()))
    def __eq__(self, obj:"Node") -> bool:
        if not isinstance(obj, Node):
            return NotImplemented
        return (
            self.ip == obj.ip and
            self.port == obj.port and
            self.name == obj.name and
            self.ed25519PublicKey.public_bytes_raw() == obj.ed25519PublicKey.public_bytes_raw()
        )
