import struct
from dataclasses import dataclass
from .match import OFPMatch

@dataclass
class OFPPacketIn:
    """
    # OpenFlow 1.3 PACKET_IN Body Format: !IHBBQ
    # ! = Big-Endian
    # I = uint32_t (4 bytes) -> buffer_id
    # H = uint16_t (2 bytes) -> total_len (length of the frame the switch received)
    # B = uint8_t  (1 byte)  -> reason (why it was sent)
    # B = uint8_t  (1 byte)  -> table_id (which table it hit)
    # Q = uint64_t (8 bytes) -> cookie
    # - struct OFPMatch (Variable, usually 8 bytes)
    # - 2 bytes of padding (00 00)
    # - The raw Ethernet Frame (The actual packet) (14 bytes)
    """

    buffer_id: int
    frame_len: int
    reason: int
    table_id: int
    cookie: int
    ofp_match: OFPMatch
    match_padding_length : int    
    frame_data: bytes
    

    STRUCT_FMT_FIXED = "!IHBBQ"
    STRUCT_SIZE_FIXED = struct.calcsize(STRUCT_FMT_FIXED)  # 16

    @classmethod
    def parse(cls, data: bytes):
        """
        Parse raw bytes into an OFPPacketIn object.
        """
        buffer_id, frame_len, reason, table_id, cookie = struct.unpack(cls.STRUCT_FMT_FIXED,data[:cls.STRUCT_SIZE_FIXED])

        match_offset = cls.STRUCT_SIZE_FIXED
        ofp_match = OFPMatch.parse(data[match_offset:])
        match_length = ofp_match.length

        match_padding_length = ((match_length + 7) // 8) * 8 - match_length
        frame_offset = match_offset + match_length + match_padding_length + 2  #2 extra padding because frame size if 14 bytes

        frame_data = data[frame_offset:]

        return cls(buffer_id, frame_len, reason, table_id, cookie, ofp_match,match_padding_length,  frame_data)

    def pack(self) -> bytes:
        """
        Serialize the OFPPacketIn object back into bytes.
        """
        padding = b'\x00' * 2
        return struct.pack(
            self.STRUCT_FMT_FIXED,
            self.buffer_id,
            self.frame_len,
            self.reason,
            self.table_id,
            self.cookie
        ) + self.ofp_match.pack() + padding + self.frame_data
