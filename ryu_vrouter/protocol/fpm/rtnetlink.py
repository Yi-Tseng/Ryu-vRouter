import struct
from ryu.lib.packet import packet_base
from ryu.lib.packet import ipv4, ipv6
from ryu.lib import addrconv

# RtNetlink protcols
UNSPEC = 0
REDIRECT = 1
KERNEL = 2
BOOT = 3
STATIC = 4
GATED = 8
RA = 9
MRT = 10
ZEBRA = 11
BIRD = 12
DNROUTED = 13
XORP = 14
NTK = 15
DHCP = 16
MROUTED = 17
UNKNOWN = 0


class RtNetlink(packet_base.PacketBase):
    """
    Netlink routing message encoder/decoder class

    From linux/rtnetlink.h

    An instance has the following attributes at least.

    __init__ takes the corresponding args in this order.

    =============== ==================== =====================
    Attribute       Description          Example
    =============== ==================== =====================
    address_family  address family
    dst_len         destionation length
    src_len         source length
    tos             TOS filter
    table           routing table id
    protocol        routing protocol
    scope           distance to the dst
    msg_type        route type
    flags           flags
    rt_attrs        routing attributes
    =============== ==================== =====================
    """

    _PACK_STR = '!BBBBBBBBL'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, address_family, dst_len, src_len, tos, table, protocol, scope, msg_type, flags, rt_attrs=None):
        super(RtNetlink, self).__init__()
        self.address_family = address_family
        self.dst_len        = dst_len
        self.src_len        = src_len
        self.tos            = tos
        self.table          = table
        self.protocol       = protocol
        self.scope          = scope
        self.msg_type       = msg_type
        self.flags          = flags

        if rt_attrs:
            self.rt_attrs = rt_attrs
        else:
            self.rt_attrs = []

    @classmethod
    def parser(cls, buf):

        # rtnetlink header
        address_family, dst_len, src_len, tos, table, protocol, scope, msg_type, flags = struct.unpack_from(cls._PACK_STR, buf)

        # routing attributes
        buf = buf[RtNetlink._MIN_LEN:]
        rt_atts = []

        while buf:
            rt_attr, ncls, buf = RtAttribute.parser(buf)

            if not rt_attr:
                break

            rt_atts.append(rt_attr)
            buf = buf[rt_attr.length:]

        return (cls(address_family, dst_len, src_len, tos, table, protocol, scope, msg_type, flags, rt_atts),
                None,
                buf)

    def serialize(self, payload, prev):
        '''
        Not implement now
        '''
        return None


# Attribute types
RTA_DST = 1;
RTA_OIF = 4;
RTA_GATEWAY = 5;
RTA_PRIORITY = 6;

class RtAttribute(packet_base.PacketBase):
    """
    Routing attributes decoder/encoder class

    An instance has the following attributes at least.

    __init__ takes the corresponding args in this order.

    =============== ==================== =====================
    Attribute       Description          Example
    =============== ==================== =====================
    length          attribute length
    attr_type       attribute type
    =============== ==================== =====================
    """

    attr_cls_map = {
        RTA_DST: RtAttrDst,
        RTA_OIF: RtAttrOif,
        RTA_GATEWAY: RtAttrGateway,
        RTA_PRIORITY: RtAttrPriority
    }

    _PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, length, attr_type):
        super(RtAttribute, self).__init__()
        self.length = length
        self.attr_type = attr_type

    @classmethod
    def parser(cls, buf):

        if len(buf) < _MIN_LEN:
            return (None, None, buf)

        length, attr_type = struct.unpack_from(cls._PACK_STR, buf)
        attr_data = buf[cls._MIN_LEN:cls._MIN_LEN + length]
        attr_cls = cls.get_attr_cls(attr_type)
        attr = None

        if attr_cls:
            attr = attr_cls(length, attr_type, attr_data)

        return (attr, None, buf[cls._MIN_LEN + length:])

    @classmethod
    def get_attr_cls(cls, type):
        return cls.attr_cls_map.get(type, None)

    def serialize(self, payload, prev):
        '''
        Not implement now
        '''
        return None


class RtAttrDst(RtAttribute):
    """
    Destination address route attribute class

    An instance has the following attributes at least.

    =============== ==================== =====================
    Attribute       Description          Example
    =============== ==================== =====================
    dst_address     destination address  IPv4 or v6 address
    =============== ==================== =====================
    """
    def __init__(self, length, attr_type, attr_data):
        super(RtAttrDst, self).__init__(length, attr_type)

        if length == 4:
            # 4 bytes, ipv4
            self.dst_address = addrconv.ipv4.bin_to_text(attr_data)

        else if length == 16:
            # 16 bytes, ipv6
            self.dst_address = addrconv.ipv6.bin_to_text(attr_data)

        else:
            # invalid address
            self.dst_address = None


class RtAttrOif(RtAttribute):
    """
    Output interface route attribute class

    An instance has the following attributes at least.

    =============== ==================== =====================
    Attribute       Description          Example
    =============== ==================== =====================
    oif             output interface
    =============== ==================== =====================
    """
    _PACK_STR = '!I'

    def __init__(self, length, attr_type, attr_data):
        super(RtAttrOif, self).__init__(length, attr_type)

        if length != 4:
            self.oif = None

        else:
            self.oif = struct.unpack_from(_PACK_STR, attr_data)


class RtAttrGateway(RtAttribute):
    """
    Gateway route attribute class

    An instance has the following attributes at least.

    =============== ==================== =====================
    Attribute       Description          Example
    =============== ==================== =====================
    gateway         gateway address      IPv4 or v6 address
    =============== ==================== =====================
    """
    def __init__(self, length, attr_type, attr_data):
        super(RtAttrGateway, self).__init__(length, attr_type)

        if length == 4:
            # 4 bytes, ipv4
            self.gateway = addrconv.ipv4.bin_to_text(attr_data)

        else if length == 16:
            # 16 bytes, ipv6
            self.gateway = addrconv.ipv6.bin_to_text(attr_data)

        else:
            # invalid address
            self.gateway = None


class RtAttrPriority(RtAttribute):
    """
    Pirority route attribute class

    An instance has the following attributes at least.

    =============== ==================== =====================
    Attribute       Description          Example
    =============== ==================== =====================
    pirority        pirority
    =============== ==================== =====================
    """
    _PACK_STR = '!I'

    def __init__(self, length, attr_type, attr_data):
        super(RtAttrPriority, self).__init__(length, attr_type)

        if length != 4:
            self.pirority = None

        else:
            self.pirority = struct.unpack_from(_PACK_STR, attr_data)
