from socket import IPPROTO_IPV6, IPV6_V6ONLY, SO_REUSEADDR, SOL_SOCKET, socket as Socket
from socket import AF_INET, SOCK_DGRAM, AF_INET6
from typing import Generator

from src.manager.BannedIps import BannedIps
from src.protocol.Protocol import MAGIC, SOCKET_BUFFER, PacketElementSize
from src.model.NetConfig import NetConfig

WSAENOTSOCK = 10038

class Net:
    def __init__(self, netConfig:NetConfig) -> None:
        prot = {
            4: AF_INET,
            6: AF_INET6
        }[netConfig.ipVersion]
        self._sock:Socket = Socket(prot, SOCK_DGRAM)
        self._sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        if prot == AF_INET6: self._sock.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 1)
        self._sock.bind(netConfig.addr)
        self._netConfig:NetConfig = netConfig
    def sendTo(self, data:bytes, addr:tuple[str, int]) -> int:
        return self._sock.sendto(MAGIC+data, addr)
    def recv(self) -> Generator[tuple[bytes, tuple[str, int]], None, None]:
        while True:
            try:
                data, addr = self._sock.recvfrom(SOCKET_BUFFER)
                if not data.startswith(MAGIC):
                    continue
                elif BannedIps.contains(addr[0]):
                    continue
                yield data[PacketElementSize.MAGIC:], addr
            except Exception:
                return
    def close(self) -> None:
        self._sock.close()