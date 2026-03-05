import struct
from dataclasses import dataclass, field
from typing import List, Optional
from enum import IntEnum

class LLDP_TLV_TYPE(IntEnum):
    END         = 0
    CHASSIS_ID  = 1
    PORT_ID     = 2
    TTL         = 3
    PORT_DESC   = 4
    SYSTEM_NAME = 5
    SYSTEM_DESC = 6
    SYSTEM_CAPS = 7
    MGMT_ADDR   = 8

# Chassis ID Subtype Constants
class CHASSIS_ID_SUBTYPE(IntEnum):
    CHASSIS_COMPONENT = 1
    INTERFACE_ALIAS   = 2
    PORT_COMPONENT    = 3
    MAC_ADDRESS       = 4
    NETWORK_ADDRESS   = 5
    INTERFACE_NAME    = 6
    LOCAL             = 7

# Port ID Subtype Constants
class PORT_ID_SUBTYPE(IntEnum):
    INTERFACE_ALIAS  = 1
    PORT_COMPONENT   = 2
    MAC_ADDRESS      = 3
    NETWORK_ADDRESS  = 4
    INTERFACE_NAME   = 5
    AGENT_CIRCUIT_ID = 6
    LOCAL            = 7


@dataclass
class LLDPTlv:
    """
    Represents a single LLDP TLV (Type-Length-Value).

    TLV Header is 2 bytes:
    - Bits 15-9 (7 bits): Type
    - Bits 8-0  (9 bits): Length (number of bytes in Value)
    """
    tlv_type: int
    value: bytes

    @classmethod
    def parse(cls, data: bytes) -> Optional[tuple]:
        """
        Parse one TLV from raw bytes.
        Returns (LLDPTlv instance, bytes_consumed) or None if data is too short.
        """
        if len(data) < 2:
            return None

        header = struct.unpack("!H", data[:2])[0]
        tlv_type = (header >> 9) & 0x7F   # top 7 bits
        length   = header & 0x1FF          # bottom 9 bits

        total_size = 2 + length
        if len(data) < total_size:
            return None

        value = data[2:total_size]
        return cls(tlv_type, value), total_size

    def pack(self) -> bytes:
        """
        Serialize this TLV back into bytes.
        """
        header = ((self.tlv_type & 0x7F) << 9) | (len(self.value) & 0x1FF)
        return struct.pack("!H", header) + self.value

    # ------------------------------------------------------------------ #
    # Convenience constructors for common TLV types                        #
    # ------------------------------------------------------------------ #

    @classmethod
    def chassis_id_mac(cls, mac: bytes) -> "LLDPTlv":
        """Create a Chassis ID TLV with MAC address subtype (4)."""
        return cls(
            tlv_type=LLDP_TLV_TYPE.CHASSIS_ID,
            value=struct.pack("!B6s", CHASSIS_ID_SUBTYPE.MAC_ADDRESS, mac),
        )

    @classmethod
    def port_id_port_component(cls, port_no: int) -> "LLDPTlv":
        """Create a Port ID TLV with Port Component subtype (2) and 4-byte port number."""
        return cls(
            tlv_type=LLDP_TLV_TYPE.PORT_ID,
            value=struct.pack("!BI", PORT_ID_SUBTYPE.PORT_COMPONENT, port_no),
        )

    @classmethod
    def ttl(cls, seconds: int) -> "LLDPTlv":
        """Create a TTL TLV."""
        return cls(
            tlv_type=LLDP_TLV_TYPE.TTL,
            value=struct.pack("!H", seconds),
        )

    @classmethod
    def end(cls) -> "LLDPTlv":
        """Create an End-of-LLDPDU TLV."""
        return cls(tlv_type=LLDP_TLV_TYPE.END, value=b"")

    # ------------------------------------------------------------------ #
    # Convenience decoders                                                 #
    # ------------------------------------------------------------------ #

    def get_chassis_mac(self) -> Optional[bytes]:
        """
        If this is a Chassis ID TLV with MAC subtype, return the 6-byte MAC.
        """
        if self.tlv_type != LLDP_TLV_TYPE.CHASSIS_ID:
            return None
        if len(self.value) < 7:
            return None
        subtype = self.value[0]
        if subtype == CHASSIS_ID_SUBTYPE.MAC_ADDRESS:
            return self.value[1:7]
        return None

    def get_port_number(self) -> Optional[int]:
        """
        If this is a Port ID TLV with Port Component subtype,
        return the port number as an integer.
        """
        if self.tlv_type != LLDP_TLV_TYPE.PORT_ID:
            return None
        if len(self.value) < 5:
            return None
        subtype = self.value[0]
        if subtype == PORT_ID_SUBTYPE.PORT_COMPONENT:
            return struct.unpack("!I", self.value[1:5])[0]
        return None

    def get_ttl(self) -> Optional[int]:
        """If this is a TTL TLV, return the TTL in seconds."""
        if self.tlv_type != LLDP_TLV_TYPE.TTL:
            return None
        return struct.unpack("!H", self.value[:2])[0]


LLDP_MAC_NEAREST_BRIDGE = b'\x01\x80\xc2\x00\x00\x0e'
ETHERTYPE_LLDP = 0x88cc
ETHERNET_HEADER_FMT = "!6s6sH"
ETHERNET_HEADER_SIZE = struct.calcsize(ETHERNET_HEADER_FMT)  # 14
MIN_ETHERNET_FRAME_SIZE = 60


@dataclass
class LLDPPacket:
    """
    Represents a full LLDP Ethernet frame.

    Structure:
        Ethernet Header (14 bytes):
            - dst_mac  : 6 bytes
            - src_mac  : 6 bytes
            - ethertype: 2 bytes (always 0x88cc for LLDP)
        LLDP Payload:
            - Zero or more LLDPTlv objects
            - Must contain Chassis ID, Port ID, TTL, End TLVs (mandatory per spec)
    """
    dst_mac : bytes
    src_mac : bytes
    tlvs    : List[LLDPTlv] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> Optional["LLDPPacket"]:
        """
        Parse a raw Ethernet frame into an LLDPPacket.
        Returns None if the frame is not a valid LLDP packet.
        """
        if len(data) < ETHERNET_HEADER_SIZE:
            return None

        dst_mac, src_mac, ethertype = struct.unpack(
            ETHERNET_HEADER_FMT, data[:ETHERNET_HEADER_SIZE]
        )

        if ethertype != ETHERTYPE_LLDP:
            return None

        # Parse TLVs flexibly until END or end of data
        tlvs = []
        offset = ETHERNET_HEADER_SIZE

        while offset < len(data):
            result = LLDPTlv.parse(data[offset:])
            if result is None:
                break
            tlv, consumed = result
            tlvs.append(tlv)
            offset += consumed
            if tlv.tlv_type == LLDP_TLV_TYPE.END:
                break

        return cls(dst_mac=dst_mac, src_mac=src_mac, tlvs=tlvs)

    def pack(self) -> bytes:
        """
        Serialize the LLDPPacket into raw bytes, padded to minimum Ethernet size.
        """
        eth_header = struct.pack(
            ETHERNET_HEADER_FMT, self.dst_mac, self.src_mac, ETHERTYPE_LLDP
        )
        payload = b"".join(tlv.pack() for tlv in self.tlvs)
        frame = eth_header + payload

        # Pad to minimum Ethernet frame size
        if len(frame) < MIN_ETHERNET_FRAME_SIZE:
            frame += b'\x00' * (MIN_ETHERNET_FRAME_SIZE - len(frame))

        return frame

    # Convenience constructors                                             

    @classmethod
    def create(cls, dpid_int: int, port_no: int, ttl: int = 120) -> "LLDPPacket":
        """
        Build a standard LLDP discovery packet.
        :param dpid_int: Switch DPID as an integer
        :param port_no : Port number the LLDP will be sent out of
        :param ttl     : TTL in seconds (default 120)
        """
        src_mac = dpid_int.to_bytes(8, byteorder='big')[2:8]

        tlvs = [
            LLDPTlv.chassis_id_mac(src_mac),
            LLDPTlv.port_id_port_component(port_no),
            LLDPTlv.ttl(ttl),
            LLDPTlv.end(),
        ]
        return cls(dst_mac=LLDP_MAC_NEAREST_BRIDGE, src_mac=src_mac, tlvs=tlvs)

    # Lookup helpers                                                 

    def get_tlv(self, tlv_type: int) -> Optional[LLDPTlv]:
        """Return the first TLV matching tlv_type, or None."""
        for tlv in self.tlvs:
            if tlv.tlv_type == tlv_type:
                return tlv
        return None

    def get_chassis_mac(self) -> Optional[bytes]:
        tlv = self.get_tlv(LLDP_TLV_TYPE.CHASSIS_ID)
        return tlv.get_chassis_mac() if tlv else None

    def get_port_number(self) -> Optional[int]:
        tlv = self.get_tlv(LLDP_TLV_TYPE.PORT_ID)
        return tlv.get_port_number() if tlv else None

    def get_ttl(self) -> Optional[int]:
        tlv = self.get_tlv(LLDP_TLV_TYPE.TTL)
        return tlv.get_ttl() if tlv else None