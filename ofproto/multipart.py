import struct
from dataclasses import dataclass, field
from typing import List


# ------------------------------------------------------------------ #
# OFPMultipartRequest                                                  #
# ------------------------------------------------------------------ #

@dataclass
class OFPMultipartRequest:
    """
    OpenFlow 1.3 Multipart Request Body (sent after the OFPHeader).

    Format: !HH4x
    ! = Big-Endian
    H = uint16_t (2 bytes) -> type   (e.g. OFPMP_PORT_DESC = 13)
    H = uint16_t (2 bytes) -> flags  (0 for a single request)
    4x = 4 bytes padding

    Total body size = 8 bytes
    For PORT_DESC there is no additional request body.
    """

    type:  int
    flags: int = 0

    STRUCT_FMT  = "!HH4x"
    STRUCT_SIZE = struct.calcsize(STRUCT_FMT)  # 8

    @classmethod
    def parse(cls, data: bytes) -> "OFPMultipartRequest":
        type_, flags = struct.unpack(cls.STRUCT_FMT, data[:cls.STRUCT_SIZE])
        return cls(type=type_, flags=flags)

    def pack(self) -> bytes:
        return struct.pack(self.STRUCT_FMT, self.type, self.flags)


# ------------------------------------------------------------------ #
# OFPPort  (one entry inside a PORT_DESC reply body)                  #
# ------------------------------------------------------------------ #

@dataclass
class OFPPort:
    """
    OpenFlow 1.3 Port Description.

    Format: !I4s6s2s16sIIIIIIII
    ! = Big-Endian
    I  = uint32_t (4 bytes)  -> port_no
    4x = 4 bytes padding
    6s = uint8_t[6] (6 bytes) -> hw_addr (MAC)
    2x = 2 bytes padding
    16s= char[16] (16 bytes) -> name
    I  = uint32_t (4 bytes)  -> config
    I  = uint32_t (4 bytes)  -> state
    I  = uint32_t (4 bytes)  -> curr  (current features)
    I  = uint32_t (4 bytes)  -> advertised
    I  = uint32_t (4 bytes)  -> supported
    I  = uint32_t (4 bytes)  -> peer
    I  = uint32_t (4 bytes)  -> curr_speed (kbps)
    I  = uint32_t (4 bytes)  -> max_speed  (kbps)

    Total = 64 bytes
    """

    port_no:     int
    hw_addr:     bytes
    name:        str
    config:      int
    state:       int
    curr:        int
    advertised:  int
    supported:   int
    peer:        int
    curr_speed:  int
    max_speed:   int

    STRUCT_FMT  = "!I4x6s2x16sIIIIIIII"
    STRUCT_SIZE = struct.calcsize(STRUCT_FMT)  # 64

    @classmethod
    def parse(cls, data: bytes) -> "OFPPort":
        (
            port_no, hw_addr, name,
            config, state,
            curr, advertised, supported, peer,
            curr_speed, max_speed,
        ) = struct.unpack(cls.STRUCT_FMT, data[:cls.STRUCT_SIZE])

        return cls(
            port_no    = port_no,
            hw_addr    = hw_addr,
            name       = name.rstrip(b'\x00').decode('utf-8', errors='replace'),
            config     = config,
            state      = state,
            curr       = curr,
            advertised = advertised,
            supported  = supported,
            peer       = peer,
            curr_speed = curr_speed,
            max_speed  = max_speed,
        )

    def pack(self) -> bytes:
        return struct.pack(
            self.STRUCT_FMT,
            self.port_no,
            self.hw_addr,
            self.name.encode('utf-8').ljust(16, b'\x00'),
            self.config,
            self.state,
            self.curr,
            self.advertised,
            self.supported,
            self.peer,
            self.curr_speed,
            self.max_speed,
        )


# ------------------------------------------------------------------ #
# OFPMultipartReply                                                    #
# ------------------------------------------------------------------ #

@dataclass
class OFPMultipartReply:
    """
    OpenFlow 1.3 Multipart Reply Body (received after the OFPHeader).

    Header body format: !HH4x  (same layout as OFPMultipartRequest)
    Followed by a variable-length body whose structure depends on `type`.

    For PORT_DESC (type=13), the body is an array of OFPPort (64 bytes each).
    """

    type:  int
    flags: int
    ports: List[OFPPort] = field(default_factory=list)

    STRUCT_FMT  = "!HH4x"
    STRUCT_SIZE = struct.calcsize(STRUCT_FMT)  # 8

    # OFPMP_REPLY_MORE: set in flags when more replies will follow
    OFPMP_REPLY_MORE = 0x0001

    @classmethod
    def parse(cls, data: bytes) -> "OFPMultipartReply":
        type_, flags = struct.unpack(cls.STRUCT_FMT, data[:cls.STRUCT_SIZE])

        ports = []
        offset = cls.STRUCT_SIZE

        # Parse the body as an array of OFPPort entries (64 bytes each)
        while offset + OFPPort.STRUCT_SIZE <= len(data):
            port = OFPPort.parse(data[offset:])
            ports.append(port)
            offset += OFPPort.STRUCT_SIZE

        return cls(type=type_, flags=flags, ports=ports)

    @property
    def has_more(self) -> bool:
        """True if the switch will send additional MULTIPART_REPLY messages."""
        return bool(self.flags & self.OFPMP_REPLY_MORE)
