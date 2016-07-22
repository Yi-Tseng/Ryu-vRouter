import struct
from ryu.lib.packet import packet_base
from ryu.lib import addrconv

from .rtnetlink import RtNetlink

# Netlink message types
RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_GETROUTE = 26

# Flags
NLM_F_REQUEST = 1
NLM_F_MULTI   = 2
NLM_F_ACK     = 4
NLM_F_ECHO    = 8


class Netlink(packet_base.PacketBase):
    """
    Netlink header encoder/decoder class

    RFC 3549
    https://tools.ietf.org/html/rfc3549

    An instance has the following attributes at least.

    __init__ takes the corresponding args in this order.

    =============== ==================== =====================
    Attribute       Description          Example
    =============== ==================== =====================
    length          message length       1024
    msg_type        message type         24
    flags           flags                1
    sequence        sequence number      1
    process_port_id process port ID      1
    =============== ==================== =====================
    """

    _PACK_STR = '!IHHII'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, length, msg_type, flags, sequence, process_port_id):
        super(Netlink, self).__init__()
        self.length = length
        self.msg_type = msg_type
        self.flags = flags
        self.sequence = sequence
        self.process_port_id = process_port_id

    @classmethod
    def parser(cls, buf):
        length, msg_type, flags, sequence, process_port_id = struct.unpack_from(cls._PACK_STR, buf)
        return (cls(length, msg_type, flags, sequence, process_port_id),
                RtNetlink,
                buf[Netlink._MIN_LEN:])

    def serialize(self, payload, prev):
        '''
        Not implement now
        '''
        return None
