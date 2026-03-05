import struct
from dataclasses import dataclass


@dataclass
class OFPMatch:
    """
    # OpenFlow 1.3 Flow Match Format: !BBHI
    # ! = Network Byte Order (Big-Endian)
    # H = uint16_t (2 byte)  -> type
    # H = uint16_t (2 byte)  -> length (excluding padding)
    # B = uint8_t [4] (4byte) -> oxm_field  (minimum size = 4 bytes)
    # padding to make total = multiple of 8 (min size =8)
    """

    type: int
    length: int
    oxm_field: bytes
    padding: bytes

    STRUCT_FMT_FIXED = "!HH"
    STRUCT_SIZE_FIXED = struct.calcsize(STRUCT_FMT_FIXED)  # 4

    @classmethod
    def parse(cls, data: bytes):
        """
        Parse raw bytes into an OFPMatch object.
        """
        type, length = struct.unpack(cls.STRUCT_FMT_FIXED, data[: cls.STRUCT_SIZE_FIXED])

        oxm_field_length = length - cls.STRUCT_SIZE_FIXED
        oxm_field = data[
            cls.STRUCT_SIZE_FIXED : cls.STRUCT_SIZE_FIXED + oxm_field_length
        ]

        total_length_with_padding = ((length + 7) // 8) * 8  # next multiple of 8
        padding_len = total_length_with_padding - length
        padding = data[
            cls.STRUCT_SIZE_FIXED
            + oxm_field_length : cls.STRUCT_SIZE_FIXED
            + oxm_field_length
            + padding_len
        ]

        return cls(type, length, oxm_field, padding)

    def pack(self) -> bytes:
        """
        Serialize the OFPMatch object back into bytes.
        """

        length = self.STRUCT_SIZE_FIXED + len(self.oxm_field)
        padding_length = ((length + 7) // 8) * 8 - length
        padding_bytes = b"\x00" * padding_length

        return (
            struct.pack(self.STRUCT_FMT_FIXED, self.type, self.length)
            + self.oxm_field
            + padding_bytes
        )