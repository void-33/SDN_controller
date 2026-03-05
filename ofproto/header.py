import struct
from dataclasses import dataclass


@dataclass
class OFPHeader:
    """
    # OpenFlow 1.3 Header Format: !BBHI
    # ! = Network Byte Order (Big-Endian)
    # B = uint8_t (1 byte)  -> version
    # B = uint8_t (1 byte)  -> type
    # H = uint16_t (2 bytes) -> length
    # I = uint32_t (4 bytes) -> xid
    """

    version: int
    message_type: int
    message_length: int
    xid: int

    STRUCT_FMT = "!BBHI"
    STRUCT_SIZE = struct.calcsize(STRUCT_FMT)  # 8

    @classmethod
    def parse(cls, data: bytes):
        """
        Parse raw bytes into an OFPHeader object.
        """
        version, message_type, message_length, xid = struct.unpack(cls.STRUCT_FMT, data)
        return cls(version, message_type, message_length, xid)

    def pack(self) -> bytes:
        """
        Serialize the OFPHeader object back into bytes.
        """
        return struct.pack(
            self.STRUCT_FMT, self.version, self.message_type, self.message_length, self.xid
        )
