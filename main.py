# pyright: reportAny=false
from collections.abc import Callable
from dataclasses import dataclass
import re
import signal
import string
import threading
import time
from enum import IntEnum
from time import sleep
from typing import Any, Generic, Literal, Protocol, TypeVar, TypedDict, cast

import serial
import structlog
import uvicorn
from construct import (
    Array,
    Bytes,
    Const,
    ConstructError,
    Container,
    GreedyBytes,
    If,
    Int16ub,
    Int16ul,
    Optional,
    Prefixed,
    Struct,
    Int8ul,
    Switch,
    this,
)
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import BaseRoute, Route
from starlette.status import (
    HTTP_202_ACCEPTED,
    HTTP_400_BAD_REQUEST,
    HTTP_429_TOO_MANY_REQUESTS,
)

from aicc import AICCard

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


class AimeReaderCommand(IntEnum):
    GET_FW_VERSION = 0x30
    GET_HW_VERSION = 0x32

    START_POLLING = 0x40
    STOP_POLLING = 0x41
    CARD_DETECT = 0x42
    CARD_SELECT = 0x43
    CARD_HALT = 0x44

    MIFARE_KEY_SET_A = 0x50
    MIFARE_AUTHORIZE_A = 0x51
    MIFARE_READ = 0x52
    MIFARE_WRITE = 0x53
    MIFARE_KEY_SET_B = 0x54
    MIFARE_AUTHORIZE_B = 0x55

    ENTER_UPDATER_MODE = 0x60
    SEND_HEX_DATA = 0x61
    RESET = 0x62
    SEND_BINDATA_INIT = 0x63
    SEND_BINDATA_EXEC = 0x64

    FELICA_PUSH = 0x70
    FELICA_ENCAP = 0x71

    LED_SET_COLOR_RGB = 0x81
    LED_SET_COLOR_RGB_UNKNOWN = 0x82

    LED_GET_BOARD_INFO = 0xF0
    LED_FIRMWARE_SUM = 0xF2
    LED_SEND_HEX_DATA = 0xF3
    LED_ENTER_BOOT_MODE = 0xF4
    LED_RESET = 0xF5


class AimeReaderStatus(IntEnum):
    OK = 0x00
    CARD_ERROR = 0x01
    NOT_ACCEPT = 0x02
    INVALID_COMMAND = 0x03
    INVALID_DATA = 0x04
    CHECKSUM_ERROR = 0x05
    INTERNAL_ERROR = 0x06
    INVALID_FIRM_DATA = 0x07
    FIRM_UPDATE_SUCCESS = 0x08
    COMP_DUMMY_2ND = 0x10
    COMP_DUMMY_3RD = 0x20


class FelicaCommand(IntEnum):
    POLL = 0x00
    READ_WITHOUT_ENCRYPTION = 0x06
    WRITE_WITHOUT_ENCRYPTION = 0x08
    GET_SYSTEM_CODE = 0x0C
    ACTIVE = 0xA4


MifareCardRequestFormat = Struct(
    "uid" / Bytes(4),
    "block_no" / Int8ul,
)

ColorFormat = Struct(
    "r" / Int8ul,
    "g" / Int8ul,
    "b" / Int8ul,
)

FelicaEncapRequestFormat = Struct(
    "idm" / Bytes(8),
    "packet"
    / Prefixed(
        Int8ul,
        Struct(
            "command" / Int8ul,
            "payload"
            / Switch(
                this.command,
                {
                    FelicaCommand.POLL.value: Struct(
                        "system_code" / Int16ub,
                        "request_code" / Int8ul,
                        "timeout" / Int8ul,
                    ),
                    FelicaCommand.READ_WITHOUT_ENCRYPTION.value: Struct(
                        "idm" / Bytes(8),
                        "system_code_count" / Const(1, Int8ul),
                        "system_codes" / Array(this.system_code_count, Int16ul),
                        "read_block_count" / Int8ul,
                        "read_blocks" / Array(this.read_block_count, Int16ub),
                    ),
                    FelicaCommand.WRITE_WITHOUT_ENCRYPTION.value: Struct(
                        "idm" / Bytes(8),
                        "system_code_count" / Const(1, Int8ul),
                        "system_codes" / Array(this.system_code_count, Int16ul),
                        "write_block_count" / Int8ul,
                        "write_blocks" / Array(this.write_block_count, Int16ub),
                        "write_block_data" / Array(this.write_block_count, Bytes(16)),
                    ),
                    FelicaCommand.GET_SYSTEM_CODE.value: Struct(
                        "idm" / Bytes(8),
                    ),
                    FelicaCommand.ACTIVE.value: Struct(
                        "idm" / Bytes(8),
                        "value" / Int8ul,
                    ),
                },
                GreedyBytes,
            ),
        ),
        includelength=True,
    ),
)

AimeReaderRequestFormat = Struct(
    "address" / Int8ul,
    "sequence" / Int8ul,
    "command" / Int8ul,
    "payload"
    / Prefixed(
        Int8ul,
        Switch(
            this.command,
            {
                AimeReaderCommand.MIFARE_KEY_SET_A.value: Bytes(6),
                AimeReaderCommand.MIFARE_KEY_SET_B.value: Bytes(6),
                AimeReaderCommand.MIFARE_AUTHORIZE_A.value: MifareCardRequestFormat,
                AimeReaderCommand.MIFARE_AUTHORIZE_B.value: MifareCardRequestFormat,
                AimeReaderCommand.MIFARE_READ.value: MifareCardRequestFormat,
                AimeReaderCommand.LED_SET_COLOR_RGB.value: ColorFormat,
                AimeReaderCommand.LED_SET_COLOR_RGB_UNKNOWN.value: ColorFormat,
                AimeReaderCommand.FELICA_ENCAP.value: FelicaEncapRequestFormat,
            },
            GreedyBytes,
        ),
    ),
)


class MifareRequestPayload(Protocol):
    uid: bytes
    block_no: int


class ColorRequestPayload(Protocol):
    r: int
    g: int
    b: int


class FelicaPollRequestPayload(Protocol):
    system_code: int
    request_code: int
    timeout: int


class FelicaReadWithoutEncryptionRequestPayload(Protocol):
    idm: bytes
    system_code_count: int
    system_codes: list[int]
    read_block_count: int
    read_blocks: list[int]


class FelicaWriteWithoutEncryptionRequestPayload(Protocol):
    idm: bytes
    system_code_count: int
    system_codes: list[int]
    write_block_count: int
    write_blocks: list[int]
    write_block_data: list[bytes]


class FelicaGetSystemCodeRequestPayload(Protocol):
    idm: bytes


class FelicaActiveRequestPayload(Protocol):
    idm: bytes
    value: int


class FelicaRequest(Protocol):
    command: int
    payload: (
        FelicaPollRequestPayload
        | FelicaReadWithoutEncryptionRequestPayload
        | FelicaWriteWithoutEncryptionRequestPayload
        | FelicaGetSystemCodeRequestPayload
        | FelicaActiveRequestPayload
    )


class FelicaEncapRequestPayload(Protocol):
    idm: bytes
    packet: FelicaRequest


AimeReaderRequestPayload = (
    bytes | MifareRequestPayload | ColorRequestPayload | FelicaEncapRequestPayload
)


T = TypeVar("T", bound=AimeReaderRequestPayload, default=bytes)


class AimeReaderRequest(Protocol, Generic[T]):
    address: int
    sequence: int
    command: int
    payload: T


CardDetectResponsePayloadFormat = Struct(
    "count" / Int8ul,
    "cards"
    / Array(
        this.count,
        Struct(
            "type" / Int8ul,
            "id"
            / Prefixed(
                Int8ul,
                GreedyBytes,
                includelength=False,
            ),
        ),
    ),
)


class CardDetectInfo(TypedDict):
    type: int
    id: bytes


class CardDetectResponsePayload(TypedDict):
    count: int
    cards: list[CardDetectInfo]


class CardType(IntEnum):
    MIFARE = 0x10
    FELICA = 0x20


FelicaEncapResponseFormat = Prefixed(
    Int8ul,
    Struct(
        "command" / Int8ul,
        "payload"
        / Switch(
            this.command,
            {
                FelicaCommand.POLL.value + 1: Struct(
                    "idm" / Bytes(8),
                    "pmm" / Bytes(8),
                    "system_code" / Optional(Int16ub),
                ),
                FelicaCommand.READ_WITHOUT_ENCRYPTION.value + 1: Struct(
                    "idm" / Bytes(8),
                    "status_flag_1" / Int8ul,
                    "status_flag_2" / Int8ul,
                    "block_count" / If(this.status_flag_1 == 0x00, Int8ul),
                    "blocks"
                    / If(
                        this.status_flag_1 == 0x00, Array(this.block_count, Bytes(16))
                    ),
                ),
                FelicaCommand.WRITE_WITHOUT_ENCRYPTION.value + 1: Struct(
                    "idm" / Bytes(8),
                    "status_flag_1" / Int8ul,
                    "status_flag_2" / Int8ul,
                ),
                FelicaCommand.GET_SYSTEM_CODE.value + 1: Struct(
                    "idm" / Bytes(8),
                    "system_code_count" / Int8ul,
                    "system_codes" / Array(this.system_code_count, Int16ul),
                ),
                FelicaCommand.ACTIVE.value + 1: Struct(
                    "idm" / Bytes(8),
                    "value" / Int8ul,
                ),
            },
            GreedyBytes,
        ),
    ),
    includelength=True,
)

AimeReaderResponseFormat = Struct(
    "address" / Int8ul,
    "sequence" / Int8ul,
    "command" / Int8ul,
    "status" / Int8ul,
    "payload"
    / Prefixed(
        Int8ul,
        Switch(
            this.command,
            {
                AimeReaderCommand.CARD_DETECT.value: CardDetectResponsePayloadFormat,
                AimeReaderCommand.FELICA_ENCAP.value: FelicaEncapResponseFormat,
            },
            GreedyBytes,
        ),
        includelength=False,
    ),
)


class AimeReaderResponseDict(TypedDict):
    address: int
    sequence: int
    command: int
    status: int
    payload: bytes | CardDetectResponsePayload | dict[str, Any]


@dataclass
class ComioFrame:
    data: bytes
    valid: bool


class ComioFrameBuffer:
    def __init__(self) -> None:
        self._data: bytearray = bytearray()

    def add_data(self, data: bytes):
        self._data.extend(data)

    def __iter__(self):
        return self

    def __next__(self) -> ComioFrame:
        # First, we check if we have enough data to successfully parse the next frame.
        # This is at least 2 bytes: a sync byte (0xE0) and the request length. The length
        # byte is included in the frame length.
        if len(self._data) < 2:
            raise StopIteration

        if self._data[0] != 0xE0:
            msg = f"Received garbage on JVS: {self._data[0]}"
            raise ValueError(msg)

        length = self._data[1]

        # 256 wraps to 0, and this is valid for whatever reason
        if length == 0:
            length = 256

        # Check if we have enough data to parse the entire frame at all. This is not an
        # exhaustive check; escape bytes are not included in the frame's length. Assuming
        # no bytes are escaped, this means that the buffer should have at least (2 + length) bytes
        # (1 sync byte at the beginning, and 1 checksum byte at the end are not counted in the
        # frame length).
        if len(self._data) < 2 + length:
            raise StopIteration

        frame_length = length - 1
        frame = bytearray()
        escaping = False
        checksum = length % 256  # length byte is included in the checksum
        valid = False
        read = 0

        for b in self._data[2:]:
            read += 1

            if b == 0xD0:
                escaping = True
                continue

            if escaping:
                escaping = False
                b += 1

            # we've read the entire body and this is the checksum byte
            # remember the given length includes the length byte
            # however when there's a checksum error we need to communicate
            # this to the consumer so they can send a checksum error on
            # our behalf.
            if len(frame) == frame_length:
                valid = checksum == b
                break

            frame.append(b)
            checksum = (checksum + b) % 256

        # if we've read all of it, remove the frame from the internal buffer
        # and return the frame's data.
        if len(frame) == frame_length:
            self._data = self._data[2 + read :]
            return ComioFrame(bytes(frame), valid)

        # else we keep the frame for further parsing.
        raise StopIteration


class AimeReader:
    """
    Emulation of an official card reader. This is written as a pure state machine
    that takes in bytes and output bytes, leaving users free to use any I/O approach.
    """

    def __init__(self, generation: Literal[1, 2, 3]):
        self.generation: Literal[1, 2, 3] = generation

        self._card_lock: threading.Lock = threading.Lock()
        self._mifare_card: bytes | None = None
        self._mifare_card_authorized_key: str | None = None
        self._aic_card: AICCard | None = None
        self._card_valid_until: float = 0

        self._incoming_buffer: ComioFrameBuffer = ComioFrameBuffer()
        self._output_buffer: bytearray = bytearray()
        self._closed: bool = False
        self._handlers: dict[int, Callable[[AimeReaderRequest[Any]], Any]] = {
            AimeReaderCommand.GET_FW_VERSION.value: self._handle_get_fw_version,
            AimeReaderCommand.GET_HW_VERSION.value: self._handle_get_hw_version,
            AimeReaderCommand.START_POLLING.value: self._handle_start_polling,
            AimeReaderCommand.STOP_POLLING.value: self._handle_stop_polling,
            AimeReaderCommand.CARD_DETECT.value: self._handle_card_detect,
            # intended for games with card decks
            AimeReaderCommand.CARD_SELECT.value: self._handle_noop,
            # what's this?
            AimeReaderCommand.CARD_HALT.value: self._handle_noop,
            AimeReaderCommand.MIFARE_KEY_SET_A.value: self._handle_mifare_set_key,
            AimeReaderCommand.MIFARE_AUTHORIZE_A.value: self._handle_mifare_authorize,
            AimeReaderCommand.MIFARE_READ.value: self._handle_mifare_read,
            # do we want to support writing cards? do games use this?
            # AimeReaderCommand.MIFARE_WRITE.value
            AimeReaderCommand.MIFARE_KEY_SET_B.value: self._handle_mifare_set_key,
            AimeReaderCommand.MIFARE_AUTHORIZE_B.value: self._handle_mifare_authorize,
            AimeReaderCommand.ENTER_UPDATER_MODE.value: self._handle_noop,
            AimeReaderCommand.SEND_HEX_DATA.value: self._handle_noop,
            AimeReaderCommand.RESET.value: self._handle_noop,
            AimeReaderCommand.SEND_BINDATA_INIT.value: self._handle_noop,
            AimeReaderCommand.SEND_BINDATA_EXEC.value: self._handle_noop,
            AimeReaderCommand.FELICA_PUSH.value: self._handle_noop,
            AimeReaderCommand.FELICA_ENCAP.value: self._handle_felica_encap,
        }
        self._led_handlers: dict[int, Callable[[AimeReaderRequest[Any]], Any]] = {
            AimeReaderCommand.LED_SET_COLOR_RGB.value: self._handle_noop,
            AimeReaderCommand.LED_SET_COLOR_RGB_UNKNOWN.value: self._handle_noop,
            AimeReaderCommand.LED_GET_BOARD_INFO.value: self._handle_led_get_board_info,
            AimeReaderCommand.LED_FIRMWARE_SUM.value: self._handle_noop,
            AimeReaderCommand.LED_SEND_HEX_DATA.value: self._handle_noop,
            AimeReaderCommand.LED_ENTER_BOOT_MODE.value: self._handle_noop,
            AimeReaderCommand.LED_RESET.value: self._handle_noop,
        }

        self._radio: bool = False
        self._last_poll_time: float = 0
        self._mifare_key_a: bytes = bytes.fromhex("6090D00632F5")
        self._mifare_key_b: bytes = b"WCCFv2"

    @property
    def fw_version(self):
        """The firmware version of the reader, inferred from the generation."""

        return [b"TN32MSEC003S F/W Ver1.2", b"\x92", b"\x94"][self.generation - 1]

    @property
    def hw_version(self):
        """The hardware version of the reader, inferred from the generation."""

        return [
            b"TN32MSEC003S H/W Ver3.0",
            b"837-15286",
            b"837-15396",
        ][self.generation - 1]

    @property
    def led_info(self):
        """The info of the LED board associated with the reader, inferred from the generation."""

        return [
            b"15084\xff\x10\x00\x12",
            b"000-00000\xff\x11\x40",
            b"000-00000\xff\x11\x40",
        ][self.generation - 1]

    @property
    def baud_rate(self):
        """The baud rate of the reader serial communications, inferred from the generation."""

        return 9600 if self.generation == 1 else 115200

    @property
    def last_poll_time(self):
        return self._last_poll_time

    @property
    def card_valid_until(self):
        return self._card_valid_until

    @property
    def mifare_card(self):
        """
        The virtual MIFARE Classic card being used to card in to the reader.

        This contains the block 0 of the card.
        """
        return self._mifare_card

    @mifare_card.setter
    def mifare_card(self, value: bytes):
        with self._card_lock:
            self._mifare_card = value
            self._card_valid_until = time.monotonic() + 5

    @property
    def aic_card(self):
        """The virtual Amusement IC card being used to card in to the reader."""
        return self._aic_card

    @aic_card.setter
    def aic_card(self, value: AICCard):
        with self._card_lock:
            self._aic_card = value
            self._card_valid_until = time.monotonic() + 5

    def receive_data(self, data: bytes | bytearray):
        """
        Feed data to the internal buffer of the reader.

        If there is enough data to generate one or more events, they will be added to the list
        returned from this call.

        Sometimes this call generates outgoing data so it is important to call
        :meth:`.data_to_send` afterwards and write those bytes to the output.
        """
        self._incoming_buffer.add_data(data)

        try:
            for frame in self._incoming_buffer:
                try:
                    request = cast(  # pyright: ignore[reportInvalidCast]
                        AimeReaderRequest,
                        AimeReaderRequestFormat.parse(frame.data),
                    )
                except ConstructError as e:
                    logger.exception("invalid request", exc_info=e)
                    
                    if len(frame.data) < 3:
                        # we're just cooked
                        continue

                    request = cast(  # pyright: ignore[reportInvalidCast]
                        AimeReaderRequest,
                        Container(
                            address=frame.data[0],
                            sequence=frame.data[1],
                            command=frame.data[2],
                        )
                    )
                    self._prepare_for_sending(
                        request, AimeReaderStatus.INVALID_DATA, b""
                    )
                    continue

                if frame.valid:
                    if request.address == 8:  # address of the LED sub-board
                        handler = self._led_handlers.get(request.command)
                    else:
                        handler = self._handlers.get(request.command)

                    if handler is None:
                        logger.warning(
                            "unknown request",
                            address=request.address,
                            sequence=request.sequence,
                            command=request.command,
                            payload=request.payload.hex()
                            if isinstance(request.payload, bytes)
                            else request.payload,
                        )
                        self._prepare_for_sending(
                            request, AimeReaderStatus.INVALID_COMMAND, b""
                        )
                    else:
                        logger.info(
                            "received request",
                            address=request.address,
                            sequence=request.sequence,
                            command=AimeReaderCommand(request.command),
                            payload=request.payload.hex()
                            if isinstance(request.payload, bytes)
                            else request.payload,
                        )
                        handler(request)
                else:
                    logger.warning("checksum error", data=frame.data.hex())
                    self._prepare_for_sending(
                        request, AimeReaderStatus.CHECKSUM_ERROR, b""
                    )
        except ValueError as e:
            msg = "Received invalid data."
            raise ValueError(msg) from e

    def _handle_noop(self, request: AimeReaderRequest):
        self._prepare_for_sending(request, AimeReaderStatus.OK, b"")

    def _handle_get_fw_version(self, request: AimeReaderRequest):
        logger.debug("reporting firmware version", fw_version=self.fw_version)
        self._prepare_for_sending(request, AimeReaderStatus.OK, self.fw_version)

    def _handle_get_hw_version(self, request: AimeReaderRequest):
        logger.debug("reporting hardware version", hw_version=self.hw_version)
        self._prepare_for_sending(request, AimeReaderStatus.OK, self.hw_version)

    def _handle_start_polling(self, request: AimeReaderRequest):
        self._radio = True
        self._prepare_for_sending(request, AimeReaderStatus.OK, b"")

    def _handle_stop_polling(self, request: AimeReaderRequest):
        self._radio = False
        self._prepare_for_sending(request, AimeReaderStatus.OK, b"")

    def _handle_card_detect(self, request: AimeReaderRequest):
        self._last_poll_time = time.monotonic()

        if time.monotonic() > self._card_valid_until:
            self._mifare_card = None
            self._mifare_card_authorized_key = None
            self._aic_card = None

        cards: list[CardDetectInfo] = []

        if self._radio and self._mifare_card is not None:
            cards.append(
                {
                    "type": CardType.MIFARE.value,
                    "id": self._mifare_card[:4],
                }
            )
        elif self._radio and self._aic_card is not None:
            cards.append(
                {
                    "type": CardType.FELICA.value,
                    "id": self._aic_card.read_block(0x83),
                }
            )

        self._prepare_for_sending(
            request, AimeReaderStatus.OK, {"count": len(cards), "cards": cards}
        )

    def _handle_mifare_set_key(self, request: AimeReaderRequest):
        if request.command == AimeReaderCommand.MIFARE_KEY_SET_A:
            self._mifare_key_a = request.payload
        elif request.command == AimeReaderCommand.MIFARE_KEY_SET_B:
            self._mifare_key_b = request.payload

        self._prepare_for_sending(request, AimeReaderStatus.OK, b"")

    def _handle_mifare_authorize(
        self, request: AimeReaderRequest[MifareRequestPayload]
    ):
        block_no = request.payload.block_no

        if block_no > 3:
            logger.warning("block out of range", block_no=block_no)
            self._prepare_for_sending(request, AimeReaderStatus.CARD_ERROR, b"")
            return

        if self._mifare_card is None or len(self._mifare_card) < 64:
            logger.error("no cards are present")
            self._prepare_for_sending(request, AimeReaderStatus.CARD_ERROR, b"")
            return

        if request.payload.uid != self._mifare_card[:4]:
            logger.error(
                "uid mismatch",
                requested_uid=request.payload.uid,
                present_uid=self._mifare_card[:4],
            )
            self._prepare_for_sending(request, AimeReaderStatus.CARD_ERROR, b"")
            return

        if (
            request.command == AimeReaderCommand.MIFARE_AUTHORIZE_A
            and self._mifare_card[48:54] == self._mifare_key_a
        ):
            status = AimeReaderStatus.OK
            self._mifare_card_authorized_key = "a"
        elif (
            request.command == AimeReaderCommand.MIFARE_AUTHORIZE_B
            and self._mifare_card[58:64] == self._mifare_key_b
        ):
            status = AimeReaderStatus.OK
            self._mifare_card_authorized_key = "b"
        else:
            status = AimeReaderStatus.CARD_ERROR
            self._mifare_card_authorized_key = None

        self._prepare_for_sending(request, status, b"")

    def _handle_mifare_read(self, request: AimeReaderRequest[MifareRequestPayload]):
        block_no = request.payload.block_no

        if block_no > 3:
            logger.warning("block out of range", block_no=block_no)
            self._prepare_for_sending(request, AimeReaderStatus.CARD_ERROR, b"")
            return

        if self._mifare_card is None or len(self._mifare_card) < 64:
            logger.error("no cards are present")
            self._prepare_for_sending(request, AimeReaderStatus.CARD_ERROR, b"")
            return

        if request.payload.uid != self._mifare_card[:4]:
            logger.error(
                "uid mismatch",
                requested_uid=request.payload.uid,
                present_uid=self._mifare_card[:4],
            )
            self._prepare_for_sending(request, AimeReaderStatus.CARD_ERROR, b"")
            return

        acs = self._mifare_card[54:58]
        c3 = (acs[2] >> 4) & 0x0F
        c3_inv = acs[1] & 0x0F
        c2 = acs[2] & 0x0F
        c2_inv = (acs[0] >> 4) & 0x0F
        c1 = (acs[1] >> 4) & 0x0F
        c1_inv = acs[0] & 0x0F

        # invalid access conditions
        if c3 != (0x0F - c3_inv) or c2 != (0x0F - c2_inv) or c1 != (0x0F - c1_inv):
            self._prepare_for_sending(request, AimeReaderStatus.CARD_ERROR, b"")
            return

        ac = (
            ((c3 >> block_no) & 1) << 2
            | ((c2 >> block_no) & 1) << 1
            | ((c1 >> block_no) & 1)
        )

        # keyA|B for everything but 011 and 101
        # never read if 111
        if ac == 0b111 or (
            ac in (0b011, 0b101) and self._mifare_card_authorized_key == "a"
        ):
            self._prepare_for_sending(request, AimeReaderStatus.CARD_ERROR, b"")
            return

        self._prepare_for_sending(
            request,
            AimeReaderStatus.OK,
            self._mifare_card[16 * block_no : 16 * (block_no + 1)],
        )

    def _handle_felica_encap(
        self, request: AimeReaderRequest[FelicaEncapRequestPayload]
    ):
        if self._aic_card is None:
            logger.error("received felica request, but no AIC cards exist")
            self._prepare_for_sending(request, AimeReaderStatus.INTERNAL_ERROR, b"")
            return

        packet = request.payload.packet
        response_payload: dict[str, Any] = {
            "command": packet.command + 1,
            "payload": {},
        }

        if packet.command == FelicaCommand.POLL:
            logger.debug("felica poll", payload=packet.payload)

            payload = cast(FelicaPollRequestPayload, packet.payload)
            idm_pmm = self._aic_card.read_block(0x83)
            response_payload["payload"] = {
                "idm": idm_pmm[0:8],
                "pmm": idm_pmm[8:16],
                "system_code": 0x88B4,
            }

            # python typing bullshit made me do this instead of the natural
            # payload["system_code"] = 0x88B4, since if you add system_code
            # in later the payload gets inferred as dict[str, bytes] and int
            # is not bytes.
            if payload.request_code != 0x01:
                del response_payload["payload"]["system_code"]
        elif packet.command == FelicaCommand.READ_WITHOUT_ENCRYPTION:
            logger.debug("felica read without encryption", payload=packet.payload)

            payload = cast(FelicaReadWithoutEncryptionRequestPayload, packet.payload)
            idm_pmm = self._aic_card.read_block(0x83)
            response_payload["payload"] = {
                "idm": idm_pmm[0:8],
                "status_flag_1": 0,
                "status_flag_2": 0,
                "block_count": payload.read_block_count,
                "blocks": self._aic_card.read_blocks(
                    [x & 0xFF for x in payload.read_blocks]
                ),
            }
        elif packet.command == FelicaCommand.WRITE_WITHOUT_ENCRYPTION:
            logger.debug("felica write without encryption", payload=packet.payload)

            payload = cast(FelicaWriteWithoutEncryptionRequestPayload, packet.payload)
            idm_pmm = self._aic_card.read_block(0x83)
            response_payload["payload"] = {
                "idm": idm_pmm[0:8],
                "status_flag_1": 0,
                "status_flag_2": 0,
            }

            for block_num, block_data in zip(
                payload.write_blocks, payload.write_block_data
            ):
                self._aic_card.write_block(block_num & 0xFF, block_data)
        elif packet.command == FelicaCommand.GET_SYSTEM_CODE:
            logger.debug("felica get system code")

            idm_pmm = self._aic_card.read_block(0x83)
            sys_c = self._aic_card.read_block(0x85)
            response_payload["payload"] = {
                "idm": idm_pmm[0:8],
                "system_code_count": 1,
                "system_codes": [int.from_bytes(sys_c[0:2], "big")],
            }
        elif packet.command == FelicaCommand.ACTIVE:
            logger.debug("felica active", payload=packet.payload)

            payload = cast(FelicaActiveRequestPayload, packet.payload)
            idm_pmm = self._aic_card.read_block(0x83)
            response_payload["payload"] = {
                "idm": idm_pmm[0:8],
                "value": 0,
            }

            if payload.value == 0:  # Alive check
                response_payload["payload"]["value"] = 0
            elif payload.value == 1:  # OS version
                response_payload["payload"]["value"] = 0
            elif payload.value == 2:  # something
                response_payload["payload"]["value"] = 0xFF

        self._prepare_for_sending(request, AimeReaderStatus.OK, response_payload)

    def _handle_led_get_board_info(self, request: AimeReaderRequest):
        self._prepare_for_sending(request, AimeReaderStatus.OK, self.led_info)

    def _prepare_for_sending(
        self,
        request: AimeReaderRequest[Any],
        status: AimeReaderStatus,
        payload: bytes | CardDetectResponsePayload | dict[str, Any],
    ):
        response: AimeReaderResponseDict = {
            "address": request.address,
            "sequence": request.sequence,
            "command": request.command,
            "status": status.value,
            "payload": payload,
        }
        logger.info(
            "sending response",
            address=response["address"],
            sequence=response["sequence"],
            command=AimeReaderCommand(response["command"]),
            status=response["status"],
            payload=payload.hex() if isinstance(payload, bytes) else payload,
        )
        data = AimeReaderResponseFormat.build(cast(dict[str, Any], response))  # pyright: ignore[reportInvalidCast]

        self._output_buffer.append(0xE0)
        self._output_buffer.append((len(data) + 1) % 256)
        checksum = self._output_buffer[-1]

        for c in data:
            if c in (0xE0, 0xD0):
                self._output_buffer.append(0xD0)
                self._output_buffer.append(c - 1)
            else:
                self._output_buffer.append(c)

            checksum = (c + checksum) % 256

        self._output_buffer.append(checksum)

    def data_to_send(self, amount: int | None = None):
        """
        Returns some data for sending out of the internal data buffer.
        """
        if amount is None:
            data = bytes(self._output_buffer)
            self._output_buffer.clear()
            return data

        data = bytes(self._output_buffer[:amount])
        self._output_buffer = self._output_buffer[amount:]
        return data


class AimeReaderManager:
    def __init__(self, port: str, generation: Literal[1, 2, 3]) -> None:
        self.reader: AimeReader = AimeReader(generation)
        self._serial: serial.Serial = serial.Serial(port, self.reader.baud_rate)

        self._keep_running: bool = True

    def start(self):
        while self._keep_running:
            sleep(0.0075 if self.reader.baud_rate == 9600 else 0.002)
            self.poll()
        self._serial.close()

    def close(self):
        self._keep_running = False

    def poll(self):
        in_waiting = self._serial.in_waiting

        if not self._serial.is_open or in_waiting <= 0:
            return

        data = self._serial.read(in_waiting)
        # logger.debug("incoming data", data=data.hex())
        self.reader.receive_data(data)

        outgoing_data = self.reader.data_to_send()

        if outgoing_data:
            # logger.debug("outgoing data", data=outgoing_data.hex())
            _ = self._serial.write(outgoing_data)


async def amnet_info(request: Request):
    started_at = cast(float, request.app.state.started_at)
    manager = cast(AimeReaderManager, request.app.state.manager)

    return JSONResponse(
        {
            "apiVersion": 1,
            "gameId": "SBSD",
            "serverName": "amnet-aime-reader",
            "sessionUptime": int((time.monotonic() - started_at) * 1000),
            "timeSinceLastPoll": int(
                (time.monotonic() - manager.reader.last_poll_time) * 1000
            ),
        }
    )


async def amnet_signin(request: Request):
    manager = cast(AimeReaderManager, request.app.state.manager)
    current_time = time.time()

    if manager.reader.card_valid_until > current_time:
        return JSONResponse(
            {"message": "Too many requests."},
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            headers={
                "Retry-After": f"{int(manager.reader.card_valid_until - current_time)}"
            },
        )

    data = await request.json()

    if not isinstance(data, dict):
        return JSONResponse(
            {"message": "Bad Request"},
            status_code=HTTP_400_BAD_REQUEST,
        )

    access_code = data.get("cardId")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType]

    if access_code is None:
        return JSONResponse(
            {"message": "Access Code not provided."}, status_code=HTTP_400_BAD_REQUEST
        )

    if not isinstance(access_code, str):
        return JSONResponse(
            {"message": "Bad Request"}, status_code=HTTP_400_BAD_REQUEST
        )

    if len(access_code) != 20 or any(c not in string.digits for c in access_code):
        return JSONResponse(
            {"message": "Invalid Access Code."}, status_code=HTTP_400_BAD_REQUEST
        )

    if access_code == "00000000000000000000":
        return JSONResponse(
            {"message": "All-zero access codes are forbidden."},
            status_code=HTTP_400_BAD_REQUEST,
        )

    if (physical_card_idm := data.get("physicalCardIDm")) is not None:  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if not isinstance(physical_card_idm, str):
            return JSONResponse(
                {"message": "Bad Request"}, status_code=HTTP_400_BAD_REQUEST
            )

        if len(physical_card_idm) != 16 or any(
            c not in string.hexdigits for c in physical_card_idm
        ):
            return JSONResponse(
                {"message": "Invalid card IDm."}, status_code=HTTP_400_BAD_REQUEST
            )

        if physical_card_idm == "0000000000000000":
            return JSONResponse(
                {"message": "All-zero IDms are forbidden."},
                status_code=HTTP_400_BAD_REQUEST,
            )

        manager.reader.aic_card = AICCard(
            bytes.fromhex(physical_card_idm), bytes.fromhex(access_code)
        )
    else:
        manager.reader.mifare_card = bytes.fromhex(
            (
                "0102030426880400C819002000000018"
                # HACK: the serial at the end of block1 should be replaced with the serial from the actual AC
                # but it seems to card in so...
                "5342534400000000000000000050665B"
                f"000000000000{access_code}"
                "57434346763270F87811574343467632"
            )
        )

    return Response(status_code=HTTP_202_ACCEPTED)


async def signin(request: Request):
    manager = cast(AimeReaderManager, request.app.state.manager)
    current_time = time.monotonic()

    if manager.reader.card_valid_until > current_time:
        return JSONResponse(
            {"message": "Too many requests."},
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            headers={
                "Retry-After": f"{int(manager.reader.card_valid_until - current_time)}"
            },
        )

    content_type = request.headers.get("content-type")

    if content_type is not None and content_type.startswith("text/plain"):
        txt = (await request.body()).decode()
        txt = re.sub(r"\+Sector: \d+\s*", "", txt)
        data = bytes.fromhex(txt)
    else:
        data = await request.body()

    if len(data) < 64:
        return JSONResponse(
            {"message": "Invalid MIFARE block 0. Must be at least 64 bytes."},
            status_code=HTTP_400_BAD_REQUEST,
        )

    manager.reader.mifare_card = data

    return Response(status_code=HTTP_202_ACCEPTED)


routes: list[BaseRoute] = [
    Route("/amnet/info", amnet_info, methods=["GET"]),
    Route("/amnet/signin", amnet_signin, methods=["POST"]),
    Route("/signin", signin, methods=["POST"]),
]
middleware = [
    Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=("GET", "POST"))
]
app = Starlette(debug=False, routes=routes, middleware=middleware)


def main():
    manager = AimeReaderManager("COM31", 1)

    _ = signal.signal(signal.SIGTERM, lambda s, f: manager.close())
    _ = signal.signal(signal.SIGINT, lambda s, f: manager.close())
    threading.Thread(target=manager.start).start()

    app.state.started_at = time.monotonic()
    app.state.manager = manager

    uvicorn.run(app)


if __name__ == "__main__":
    main()
