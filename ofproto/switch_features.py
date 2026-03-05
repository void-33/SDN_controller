import struct
from dataclasses import dataclass


@dataclass
class OFPSwitchFeaturesBody:
    """
    # OpenFlow 1.3 Features Reply Body Format: !QIBB2xII
    # ! = Network Byte Order (Big-Endian)
    # Q = uint64_t (8 bytes) -> datapath_id
    # I = uint32_t (4 bytes) -> n_buffers
    # B = uint8_t  (1 byte)  -> n_tables
    # B = uint8_t  (1 byte)  -> auxiliary_id
    # 2x = pad     (2 bytes) -> (ignored/padding)
    # I = uint32_t (4 bytes) -> capabilities
    # I = uint32_t (4 bytes) -> reserved
    # Total Body = 24 bytes (Header 8 + Body 24 = 32 bytes total)
    """

    datapath_id: int
    n_buffers: int
    n_tables: int
    auxiliary_id: int
    capabilities: int
    reserved: int

    STRUCT_FMT = "!QIBB2xII"
    STRUCT_SIZE = struct.calcsize(STRUCT_FMT)  # 24

    @classmethod
    def parse(cls, data: bytes):
        """
        Parse raw bytes into an  object.
        """
        datapath_id, n_buffers, n_tables, auxiliary_id, capabilities, reserved = (
            struct.unpack(cls.STRUCT_FMT, data)
        )
        return cls(
            datapath_id, n_buffers, n_tables, auxiliary_id, capabilities, reserved
        )

    def pack(self) -> bytes:
        """
        Serialize the OFPSwitchFeaturesBody object back into bytes.
        """
        return struct.pack(
            self.STRUCT_FMT,
            self.datapath_id,
            self.n_buffers,
            self.n_tables,
            self.auxiliary_id,
            self.capabilities,
            self.reserved,
        )
