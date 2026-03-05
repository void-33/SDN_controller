from ctypes import BigEndianStructure, c_uint8, c_uint16, c_uint32, c_uint64

# OpenFlow 1.3 Header Format: !BBHI
# ! = Network Byte Order (Big-Endian)
# B = uint8_t (1 byte)  -> version
# B = uint8_t (1 byte)  -> type
# H = uint16_t (2 bytes) -> length
# I = uint32_t (4 bytes) -> xid

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

# OpenFlow 1.3 PACKET_IN Body Format: !IHBBQ
# ! = Big-Endian
# I = uint32_t (4 bytes) -> buffer_id
# H = uint16_t (2 bytes) -> total_len (length of the frame the switch received)
# B = uint8_t  (1 byte)  -> reason (why it was sent)
# B = uint8_t  (1 byte)  -> table_id (which table it hit)
# Q = uint64_t (8 bytes) -> cookie
# -------------------------
# Total so far: 16 bytes
# -------------------------
# Followed by:
# - struct ofp_match (Variable, usually 8 bytes)
# - 2 bytes of padding (00 00)
# - The raw Ethernet Frame (The actual packet)

# OpenFlow 1.3 PACKET_OUT Fixed Body: !IIH6x
# ! = Big-Endian
# I = uint32_t (4 bytes) -> buffer_id
# I = uint32_t (4 bytes) -> in_port
# H = uint16_t (2 bytes) -> actions_len
# 6x = padding (6 bytes) -> pad[6]
# Total = 16 bytes (plus 8 bytes header = 24 bytes)

# class OFP_HEADER(BigEndianStructure):
#     _pack_ = 1
#     _fields_ = [
#         ('version', c_uint8),
#         ('type',c_uint8),
#         ('length',c_uint16),
#         ('xid',c_uint32),
#     ]

