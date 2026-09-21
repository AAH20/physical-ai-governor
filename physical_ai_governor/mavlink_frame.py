"""
Binary MAVLink v2 Frame Parser & Serializer.
Zero external dependencies (pure Python standard library).
Implements MAVLink v2 binary framing, CRC-16-MCRF4XX validation,
and direct parsing into RobotTelemetryPacket for real-time PX4/ArduPilot telemetry.
"""

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .telemetry_ingest import RobotTelemetryPacket

MAVLINK_V2_STX = 0xFD

# Standard MAVLink CRC-16 CRC_EXTRA seeds for message types
CRC_EXTRA = {
    0: 50,      # HEARTBEAT
    33: 104,    # GLOBAL_POSITION_INT
    36: 177,    # SERVO_OUTPUT_RAW
    285: 137,   # ACTUATOR_OUTPUT_STATUS
    331: 91,    # ODOMETRY
}


def crc_accumulate(byte_val: int, crc: int) -> int:
    """Standard ITU X.25 / MAVLink CRC accumulator."""
    tmp = byte_val ^ (crc & 0xFF)
    tmp = (tmp ^ (tmp << 4)) & 0xFF
    return ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF


def calculate_mavlink_crc(buffer: bytes, crc_extra: int) -> int:
    """Calculates MAVLink v2 CRC-16 including CRC_EXTRA byte."""
    crc = 0xFFFF
    for b in buffer:
        crc = crc_accumulate(b, crc)
    crc = crc_accumulate(crc_extra, crc)
    return crc


@dataclass
class MAVLinkV2Message:
    """Parsed MAVLink v2 binary packet frame."""
    magic: int
    length: int
    incompat_flags: int
    compat_flags: int
    seq: int
    sysid: int
    compid: int
    msgid: int
    payload: bytes
    checksum: int
    is_valid_crc: bool


class MAVLinkFrameParser:
    """
    Parses streaming binary MAVLink v2 telemetry bytes directly into
    validated MAVLinkV2Message objects and RobotTelemetryPackets.
    """

    def parse_frame(self, raw_bytes: bytes) -> Optional[MAVLinkV2Message]:
        """Parses a complete MAVLink v2 frame from binary bytes."""
        if len(raw_bytes) < 12:  # Min header 10 + 2 checksum
            return None

        stx = raw_bytes[0]
        if stx != MAVLINK_V2_STX:
            return None

        length = raw_bytes[1]
        incompat_flags = raw_bytes[2]
        compat_flags = raw_bytes[3]
        seq = raw_bytes[4]
        sysid = raw_bytes[5]
        compid = raw_bytes[6]

        # 24-bit little-endian message ID
        msgid = raw_bytes[7] | (raw_bytes[8] << 8) | (raw_bytes[9] << 16)

        total_expected = 10 + length + 2
        if len(raw_bytes) < total_expected:
            return None

        payload = raw_bytes[10 : 10 + length]
        received_crc = struct.unpack("<H", raw_bytes[10 + length : 10 + length + 2])[0]

        crc_seed = CRC_EXTRA.get(msgid, 0)
        calculated_crc = calculate_mavlink_crc(raw_bytes[1 : 10 + length], crc_seed)
        is_valid = (received_crc == calculated_crc)

        return MAVLinkV2Message(
            magic=stx,
            length=length,
            incompat_flags=incompat_flags,
            compat_flags=compat_flags,
            seq=seq,
            sysid=sysid,
            compid=compid,
            msgid=msgid,
            payload=payload,
            checksum=received_crc,
            is_valid_crc=is_valid,
        )

    def parse_to_telemetry_packet(
        self,
        raw_bytes: bytes,
        drone_id: str = "drone_px4_01",
        human_proximity: float = 10.0,
        battery: float = 90.0,
        default_thrusts: Optional[List[float]] = None,
    ) -> Optional[RobotTelemetryPacket]:
        """
        Parses binary MAVLink v2 GLOBAL_POSITION_INT (msgid 33) into RobotTelemetryPacket.
        """
        msg = self.parse_frame(raw_bytes)
        if msg is None or not msg.is_valid_crc:
            return None

        thrusts = default_thrusts or [15.0, 15.0, 15.0, 15.0]

        if msg.msgid == 33:  # GLOBAL_POSITION_INT
            if len(msg.payload) < 28:
                return None
            (
                time_boot_ms,
                lat_deg7,
                lon_deg7,
                alt_mm,
                relative_alt_mm,
                vx_cms,
                vy_cms,
                vz_cms,
                hdg_cdeg,
            ) = struct.unpack("<IiiiihhhH", msg.payload[:28])

            lat = lat_deg7 / 1e7
            lon = lon_deg7 / 1e7
            alt_m = alt_mm / 1000.0

            # Convert cm/s to m/s
            vx_mps = vx_cms / 100.0
            vy_mps = vy_cms / 100.0
            vz_mps = vz_cms / 100.0

            return RobotTelemetryPacket(
                robot_id=drone_id,
                robot_type="quadrotor_drone",
                timestamp_ns=time_boot_ms * 1_000_000,
                position_xyz=(round(lat, 6), round(lon, 6), round(alt_m, 2)),
                velocity_xyz=(round(vx_mps, 3), round(vy_mps, 3), round(vz_mps, 3)),
                joint_torques=thrusts,
                human_distance_meters=human_proximity,
                battery_percentage=battery,
                command_torque_input=thrusts,
            )

        return None


def serialize_mavlink_v2_global_position(
    sysid: int = 1,
    compid: int = 1,
    seq: int = 0,
    time_boot_ms: int = 100000,
    lat: float = 37.7749,
    lon: float = -122.4194,
    alt_m: float = 100.0,
    vx_mps: float = 1.2,
    vy_mps: float = 0.5,
    vz_mps: float = -0.1,
) -> bytes:
    """Synthesizes a valid binary MAVLink v2 GLOBAL_POSITION_INT frame with CRC."""
    msgid = 33
    lat_deg7 = int(lat * 1e7)
    lon_deg7 = int(lon * 1e7)
    alt_mm = int(alt_m * 1000)
    relative_alt_mm = alt_mm
    vx_cms = int(vx_mps * 100)
    vy_cms = int(vy_mps * 100)
    vz_cms = int(vz_mps * 100)
    hdg_cdeg = 0

    payload = struct.pack(
        "<IiiiihhhH",
        time_boot_ms,
        lat_deg7,
        lon_deg7,
        alt_mm,
        relative_alt_mm,
        vx_cms,
        vy_cms,
        vz_cms,
        hdg_cdeg,
    )
    length = len(payload)
    incompat_flags = 0
    compat_flags = 0

    header = struct.pack(
        "<BBBBBBB3s",
        MAVLINK_V2_STX,
        length,
        incompat_flags,
        compat_flags,
        seq,
        sysid,
        compid,
        bytes([msgid & 0xFF, (msgid >> 8) & 0xFF, (msgid >> 16) & 0xFF]),
    )

    crc_seed = CRC_EXTRA[msgid]
    crc = calculate_mavlink_crc(header[1:] + payload, crc_seed)
    checksum = struct.pack("<H", crc)

    return header + payload + checksum
