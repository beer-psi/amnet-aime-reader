# pyright: reportAny=false
import re
import signal
import string
import threading
import time
from enum import IntEnum
from time import sleep
from typing import Any, Generic, Literal, Protocol, TypeGuard, TypeVar, TypedDict, cast

import serial
import structlog
import uvicorn
from construct import (
    Array,
    Bytes,
    Const,
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

    TO_UPDATER_MODE = 0x60
    SEND_HEX_DATA = 0x61
    TO_NORMAL_MODE = 0x62
    SEND_BINDATA_INIT = 0x63
    SEND_BINDATA_EXEC = 0x64

    FELICA_PUSH = 0x70
    FELICA_ENCAP = 0x71

    EXT_BOARD_LED_RGB = 0x81
    EXT_BOARD_LED_RGB_UNKNOWN = 0x82
    EXT_BOARD_INFO = 0xF0
    EXT_FIRM_SUM = 0xF2
    EXT_SEND_HEX_DATA = 0xF3
    EXT_TO_BOOT_MODE = 0xF4
    EXT_TO_NORMAL_MODE = 0xF5


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

AimeReaderRequestFormat = Prefixed(
    Int8ul,
    Struct(
        "address" / Int8ul,
        "sequence" / Int8ul,
        "command" / Int8ul,
        "payload"
        / Prefixed(
            Int8ul,
            Switch(
                this.command,
                {
                    AimeReaderCommand.MIFARE_AUTHORIZE_A.value: MifareCardRequestFormat,
                    AimeReaderCommand.MIFARE_AUTHORIZE_B.value: MifareCardRequestFormat,
                    AimeReaderCommand.MIFARE_READ.value: MifareCardRequestFormat,
                    AimeReaderCommand.EXT_BOARD_LED_RGB.value: ColorFormat,
                    AimeReaderCommand.EXT_BOARD_LED_RGB_UNKNOWN.value: ColorFormat,
                    AimeReaderCommand.FELICA_ENCAP.value: FelicaEncapRequestFormat,
                },
                GreedyBytes,
            ),
        ),
    ),
    includelength=True,
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


def is_mifare_request(
    request: AimeReaderRequest,
) -> TypeGuard[AimeReaderRequest[MifareRequestPayload]]:
    return request.command in (
        AimeReaderCommand.MIFARE_AUTHORIZE_A,
        AimeReaderCommand.MIFARE_AUTHORIZE_B,
        AimeReaderCommand.MIFARE_READ,
    )


def is_led_request(
    request: AimeReaderRequest,
) -> TypeGuard[AimeReaderRequest[ColorRequestPayload]]:
    return request.command in (
        AimeReaderCommand.EXT_BOARD_LED_RGB,
        AimeReaderCommand.EXT_BOARD_LED_RGB_UNKNOWN,
    )


def is_felica_request(
    request: AimeReaderRequest,
) -> TypeGuard[AimeReaderRequest[FelicaEncapRequestPayload]]:
    return request.command == AimeReaderCommand.FELICA_ENCAP


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

AimeReaderResponseFormat = Prefixed(
    Int8ul,
    Struct(
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
    ),
    includelength=True,
)


class AimeReaderResponseDict(TypedDict):
    address: int
    sequence: int
    command: int
    status: int
    payload: bytes | CardDetectResponsePayload | dict[str, Any]  # pyright: ignore[reportExplicitAny]


class AimeReader:
    def __init__(self, port: str, generation: Literal[0, 1, 2]) -> None:
        self.fw_version: bytes = [b"TN32MSEC003S F/W Ver1.2", b"\x94", b"\x94"][
            generation
        ]
        self.hw_version: bytes = [
            b"TN32MSEC003S H/W Ver3.0",
            b"837-15286",
            b"837-15396",
        ][generation]
        self.led_info: bytes = [
            b"15084\xff\x10\x00\x12",
            b"000-00000\xff\x11\x40",
            b"000-00000\xff\x11\x40",
        ][generation]
        self.baud_rate: int = [9600, 115200, 115200][generation]

        self.lock: threading.Lock = threading.Lock()
        self.mifare_card_dump: bytes | None = None
        self.aic_card: AICCard | None = None
        self.card_valid_until: float = 0

        self._serial: serial.Serial = serial.Serial(port, self.baud_rate)

        self._command_sequence: int = 0
        self._request_active: bool = False
        self._request_len: int = 0
        self._request_checksum: int = 0
        self._request_escaping: bool = False
        self._request_data: bytearray = bytearray()

        self._mifare_key_a: bytes = b""
        self._mifare_key_b: bytes = b""

        self._is_polling: bool = False
        self._last_poll_time: float = 0

        self._keep_running: bool = True

    @property
    def last_poll_time(self):
        return self._last_poll_time

    def set_mifare_card(self, dump: bytes):
        with self.lock:
            self.mifare_card_dump = dump
            self.card_valid_until = time.time() + 5

    def set_aic_card(self, aic_card: AICCard):
        with self.lock:
            self.aic_card = aic_card
            self.card_valid_until = time.time() + 5

    def start(self):
        while self._keep_running:
            sleep(0.0075 if self.baud_rate == 9600 else 0.002)
            self.poll()
        self._serial.close()

    def close(self):
        self._keep_running = False

    def poll(self):
        in_waiting = self._serial.in_waiting

        if not self._serial.is_open or in_waiting <= 0:
            return

        data = self._serial.read(in_waiting)

        for c in data:
            if c == 0xE0:
                self._request_active = True
                self._request_len = 0
                self._request_checksum = 0
                self._request_escaping = False
                self._request_data.clear()
                continue

            if not self._request_active:
                continue

            if c == 0xD0:
                self._request_escaping = True
                continue

            if self._request_escaping:
                c += 1
                self._request_escaping = False

            if (
                len(self._request_data) > 0
                and len(self._request_data) == self._request_data[0]
            ):
                request = cast(
                    AimeReaderRequest,
                    AimeReaderRequestFormat.parse(self._request_data),
                )  # pyright: ignore[reportInvalidCast]
                if self._request_checksum == c:
                    self.handle_request(request)
                else:
                    self.send_response(request, AimeReaderStatus.CHECKSUM_ERROR, b"")

                self._request_active = False

                continue

            self._request_data.append(c)
            self._request_checksum = (self._request_checksum + c) % 256

    def handle_request(self, request: AimeReaderRequest):
        if request.sequence <= self._command_sequence and self._command_sequence != 255:
            logger.warning(
                "requests out of order",
                current_sequence=self._command_sequence,
                request_sequence=request.sequence,
            )

        self._command_sequence = request.sequence
        _ = structlog.contextvars.bind_contextvars(sequence=request.sequence)

        if is_mifare_request(request):
            # return AimeReaderStatus.CARD_ERROR if the keys don't match
            if request.command in (
                AimeReaderCommand.MIFARE_AUTHORIZE_A,
                AimeReaderCommand.MIFARE_AUTHORIZE_B,
            ):
                logger.debug(
                    "mifare authorize keyA",
                    uid=request.payload.uid.hex(),
                    block_no=request.payload.block_no,
                )

                if self.mifare_card_dump is None or len(self.mifare_card_dump) < 64:
                    self.send_response(request, AimeReaderStatus.CARD_ERROR, b"")
                    return

                if request.command == AimeReaderCommand.MIFARE_AUTHORIZE_A:
                    card_key = self.mifare_card_dump[48:54]
                    expected_key = self._mifare_key_a
                else:
                    card_key = self.mifare_card_dump[58:64]
                    expected_key = self._mifare_key_b

                # HACK: it's a lot more complicated than this but for our intents and purposes
                # it should work for now
                status = (
                    AimeReaderStatus.OK
                    if card_key == expected_key
                    else AimeReaderStatus.CARD_ERROR
                )
                self.send_response(request, status, b"")
                return

            # return mifare card dump
            if request.command == AimeReaderCommand.MIFARE_READ:
                block_no = request.payload.block_no

                logger.debug(
                    "mifare read", uid=request.payload.uid.hex(), block_no=block_no
                )

                if self.mifare_card_dump is None or len(self.mifare_card_dump) < 64:
                    self.send_response(request, AimeReaderStatus.CARD_ERROR, b"")
                    return

                self.send_response(
                    request,
                    AimeReaderStatus.OK,
                    self.mifare_card_dump[16 * block_no : 16 * (block_no + 1)],
                )
                return

            logger.warning(
                "unhandled mifare command",
                command=request.command,
                payload=request.payload,
            )
            self.send_response(request, AimeReaderStatus.INVALID_COMMAND, b"")

            return

        # set reader LED, does not need a response
        if is_led_request(request):
            logger.debug(
                "set LED",
                command=AimeReaderCommand(request.command),
                r=request.payload.r,
                g=request.payload.g,
                b=request.payload.b,
            )
            return

        if is_felica_request(request):
            if self.aic_card is None:
                logger.error("received felica request, but no AIC cards exist")
                self.send_response(request, AimeReaderStatus.INTERNAL_ERROR, b"")
                return

            packet = request.payload.packet
            response_payload = {"command": packet.command + 1, "payload": {}}

            if packet.command == FelicaCommand.POLL:
                logger.debug("felica poll", payload=packet.payload)

                payload = cast(FelicaPollRequestPayload, packet.payload)
                idm_pmm = self.aic_card.read_block(0x83)
                response_payload["payload"] = {
                    "idm": idm_pmm[0:8],
                    "pmm": idm_pmm[8:16],
                }

                if payload.request_code == 0x01:
                    response_payload["payload"]["system_code"] = 0x88B4
            elif packet.command == FelicaCommand.READ_WITHOUT_ENCRYPTION:
                logger.debug("felica read without encryption", payload=packet.payload)

                payload = cast(
                    FelicaReadWithoutEncryptionRequestPayload, packet.payload
                )
                idm_pmm = self.aic_card.read_block(0x83)
                response_payload["payload"] = {
                    "idm": idm_pmm[0:8],
                    "status_flag_1": 0,
                    "status_flag_2": 0,
                    "block_count": payload.read_block_count,
                    "blocks": self.aic_card.read_blocks(
                        [x & 0xFF for x in payload.read_blocks]
                    ),
                }
            elif packet.command == FelicaCommand.WRITE_WITHOUT_ENCRYPTION:
                logger.debug("felica write without encryption", payload=packet.payload)

                payload = cast(
                    FelicaWriteWithoutEncryptionRequestPayload, packet.payload
                )
                idm_pmm = self.aic_card.read_block(0x83)
                response_payload["payload"] = {
                    "idm": idm_pmm[0:8],
                    "status_flag_1": 0,
                    "status_flag_2": 0,
                }

                for block_num, block_data in zip(
                    payload.write_blocks, payload.write_block_data
                ):
                    self.aic_card.write_block(block_num & 0xFF, block_data)
            elif packet.command == FelicaCommand.GET_SYSTEM_CODE:
                logger.debug("felica get system code")

                idm_pmm = self.aic_card.read_block(0x83)
                sys_c = self.aic_card.read_block(0x85)
                response_payload["payload"] = {
                    "idm": idm_pmm[0:8],
                    "system_code_count": 1,
                    "system_codes": [int.from_bytes(sys_c[0:2], "big")],
                }
            elif packet.command == FelicaCommand.ACTIVE:
                logger.debug("felica active", payload=packet.payload)

                payload = cast(FelicaActiveRequestPayload, packet.payload)
                idm_pmm = self.aic_card.read_block(0x83)
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

            self.send_response(request, AimeReaderStatus.OK, response_payload)
            return

        if request.command == AimeReaderCommand.TO_NORMAL_MODE:
            logger.debug("to normal mode")
            self.send_response(request, AimeReaderStatus.INVALID_COMMAND, b"")
            return

        if request.command == AimeReaderCommand.GET_FW_VERSION:
            logger.debug("get firmware version")
            self.send_response(request, AimeReaderStatus.OK, self.fw_version)
            return

        if request.command == AimeReaderCommand.GET_HW_VERSION:
            logger.debug("get hardware version")
            self.send_response(request, AimeReaderStatus.OK, self.hw_version)
            return

        if request.command == AimeReaderCommand.START_POLLING:
            logger.debug("start polling")
            self._is_polling = True
            self._last_poll_time = time.time()
            self.send_response(request, AimeReaderStatus.OK, b"")
            return

        if request.command == AimeReaderCommand.STOP_POLLING:
            logger.debug("stop polling")
            self._is_polling = False
            self.send_response(request, AimeReaderStatus.OK, b"")
            return

        # return the UID of the detected card using the CardInfo struct
        # if there are no cards, return 0
        if request.command == AimeReaderCommand.CARD_DETECT:
            logger.debug("card detect")

            if time.time() > self.card_valid_until:
                self.mifare_card_dump = None
                self.aic_card = None

            cards: list[CardDetectInfo] = []

            if self.mifare_card_dump is not None:
                cards.append(
                    {
                        "type": CardType.MIFARE.value,
                        "id": self.mifare_card_dump[:4],
                    }
                )
            elif self.aic_card is not None:
                cards.append(
                    {
                        "type": CardType.FELICA.value,
                        "id": self.aic_card.read_block(0x83),
                    }
                )

            self.send_response(
                request,
                AimeReaderStatus.OK,
                {"count": len(cards), "cards": cards},
            )
            return

        if request.command in (
            AimeReaderCommand.CARD_SELECT,
            AimeReaderCommand.CARD_HALT,
        ):
            logger.debug("card select/halt", command=AimeReaderCommand(request.command))
            self.send_response(request, AimeReaderStatus.OK, b"")
            return

        if request.command == AimeReaderCommand.MIFARE_KEY_SET_A:
            logger.debug("mifare set keyA", payload=request.payload.hex())
            self._mifare_key_a = request.payload[:6]
            self.send_response(request, AimeReaderStatus.OK, b"")
            return

        if request.command == AimeReaderCommand.MIFARE_KEY_SET_B:
            logger.debug("mifare set keyB", payload=request.payload.hex())
            self._mifare_key_b = request.payload[:6]
            self.send_response(request, AimeReaderStatus.OK, b"")
            return

        if request.command == AimeReaderCommand.EXT_BOARD_INFO:
            logger.debug("get LED info")
            self.send_response(request, AimeReaderStatus.OK, self.led_info)
            return

        if request.command in (
            AimeReaderCommand.TO_UPDATER_MODE,
            AimeReaderCommand.EXT_TO_NORMAL_MODE,
            AimeReaderCommand.SEND_BINDATA_INIT,
        ):
            logger.debug(
                "updater mode stuff", command=AimeReaderCommand(request.command)
            )
            self.send_response(request, AimeReaderStatus.OK, b"")
            return

        if request.command == AimeReaderCommand.SEND_BINDATA_EXEC:
            logger.debug("sending update data", payload_length=len(request.payload))
            self.send_response(request, AimeReaderStatus.FIRM_UPDATE_SUCCESS, b"")
            return

        if request.command == AimeReaderCommand.SEND_HEX_DATA:
            logger.debug("sending hex data", payload_length=len(request.payload))
            self.send_response(request, AimeReaderStatus.COMP_DUMMY_3RD, b"")
            return

        try:
            logger.warning(
                "unimplemented command",
                command=AimeReaderCommand(request.command),
                payload=request.payload.hex(),
            )
        except ValueError:
            logger.warning(
                "unknown command",
                command=request.command,
                payload=request.payload.hex(),
            )

        self.send_response(request, AimeReaderStatus.INVALID_COMMAND, b"")

    def send_response(
        self,
        request: AimeReaderRequest[Any],  # pyright: ignore[reportExplicitAny]
        status: AimeReaderStatus,
        payload: bytes | CardDetectResponsePayload | dict[str, Any],  # pyright: ignore[reportExplicitAny]
    ):
        response: AimeReaderResponseDict = {
            "address": request.address,
            "sequence": request.sequence,
            "command": request.command,
            "status": status.value,
            "payload": payload,
        }

        logger.debug(
            "sending response",
            status=status,
            payload=payload.hex() if isinstance(payload, bytes) else payload,
        )

        data = AimeReaderResponseFormat.build(cast(dict[str, Any], response))  # pyright: ignore[reportInvalidCast, reportExplicitAny]

        logger.debug(
            "raw data",
            data=data.hex(),
        )

        escaped_data = bytearray([0xE0])
        checksum = 0

        for c in data:
            if c in (0xE0, 0xD0):
                escaped_data.append(0xD0)
                escaped_data.append(c - 1)
            else:
                escaped_data.append(c)

            checksum = (c + checksum) % 256

        escaped_data.append(checksum)
        _ = self._serial.write(escaped_data)


async def amnet_info(request: Request):
    started_at = cast(float, request.app.state.started_at)
    reader = cast(AimeReader, request.app.state.reader)

    return JSONResponse(
        {
            "apiVersion": 1,
            "gameId": "SBSD",
            "serverName": "amnet-aime-reader",
            "sessionUptime": int((time.time() - started_at) * 1000),
            "timeSinceLastPoll": int((time.time() - reader.last_poll_time) * 1000),
        }
    )


async def amnet_signin(request: Request):
    reader = cast(AimeReader, request.app.state.reader)
    current_time = time.time()

    if reader.card_valid_until > current_time:
        return JSONResponse(
            {"message": "Too many requests."},
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": f"{int(reader.card_valid_until - current_time)}"},
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

    if (physical_card_idm := data.get("physicalCardIDm")) is not None:  # pyright: ignore[reportUnknownMemberType]
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

        reader.set_aic_card(
            AICCard(bytes.fromhex(physical_card_idm), bytes.fromhex(access_code))
        )
    else:
        reader.set_mifare_card(
            bytes.fromhex(
                (
                    "0102030426880400C819002000000018"
                    # HACK: the serial at the end of block1 should be replaced with the serial from the actual AC
                    # but it seems to card in so...
                    "5342534400000000000000000050665B"
                    f"000000000000{access_code}"
                    "57434346763270F87811574343467632"
                )
            )
        )

    return Response(status_code=HTTP_202_ACCEPTED)


async def signin(request: Request):
    reader = cast(AimeReader, request.app.state.reader)
    current_time = time.time()

    if reader.card_valid_until > current_time:
        return JSONResponse(
            {"message": "Too many requests."},
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": f"{int(reader.card_valid_until - current_time)}"},
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

    reader.set_mifare_card(data)

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
    reader = AimeReader("COM31", 2)

    _ = signal.signal(signal.SIGTERM, lambda s, f: reader.close())
    _ = signal.signal(signal.SIGINT, lambda s, f: reader.close())
    threading.Thread(target=reader.start).start()

    app.state.started_at = time.time()
    app.state.reader = reader

    uvicorn.run(app)


if __name__ == "__main__":
    main()
