import struct
from ryu.lib.packet import packet_base
from ryu.lib import addrconv

from .netlink import Netlink

class FpmHeader(packet_base.PacketBase):
    """
    FPM header encoder/decoder class

    An instance has the following attributes at least.

    __init__ takes the corresponding args in this order.

    =============== ==================== =====================
    Attribute       Description          Example
    =============== ==================== =====================
    version
    msg_type
    length
    =============== ==================== =====================
    """

    _PACK_STR = '!HHI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, version, msg_type, length):
        super(Netlink, self).__init__()
        self.version = version
        self.msg_type = msg_type
        self.length = length

    @classmethod
    def parser(cls, buf):
        version, msg_type, length = struct.unpack_from(cls._PACK_STR, buf)

        if version != 1:
            # support version 1 only
            return (None, None, buf)

        if msg_type != 1:
            # support netlink only
            return (None, None, buf)

        return (cls(version, msg_type, length),
                Netlink,
                buf[FpmHeader._MIN_LEN:])

    def serialize(self, payload, prev):
        '''
        Not implement now
        '''
        return None
