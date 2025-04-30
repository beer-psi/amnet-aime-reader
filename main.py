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
from construct import Array, Bytes, Struct, Int8ul, Switch, this
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
    FELICA_THROUGH = 0x71

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


MifareCardRequest = Struct(
    "uid" / Bytes(4),
    "block_no" / Int8ul,
)

Color = Struct(
    "r" / Int8ul,
    "g" / Int8ul,
    "b" / Int8ul,
)

AimeReaderRequestFormat = Struct(
    "length" / Int8ul,
    "address" / Int8ul,
    "sequence" / Int8ul,
    "command" / Int8ul,
    "payload_length" / Int8ul,
    "payload"
    / Switch(
        this.command,
        {
            AimeReaderCommand.CARD_SELECT.value: MifareCardRequest,
            AimeReaderCommand.MIFARE_AUTHORIZE_A.value: MifareCardRequest,
            AimeReaderCommand.MIFARE_AUTHORIZE_B.value: MifareCardRequest,
            AimeReaderCommand.MIFARE_READ.value: MifareCardRequest,
            AimeReaderCommand.EXT_BOARD_LED_RGB.value: Color,
            AimeReaderCommand.EXT_BOARD_LED_RGB_UNKNOWN.value: Color,
        },
        Bytes(this.payload_length),
    ),
)


class MifareRequestPayload(Protocol):
    uid: bytes
    block_no: int


class ColorRequestPayload(Protocol):
    r: int
    g: int
    b: int


AimeReaderRequestPayload = bytes | MifareRequestPayload | ColorRequestPayload


T = TypeVar("T", bound=AimeReaderRequestPayload, default=bytes)


class AimeReaderRequest(Protocol, Generic[T]):
    length: int
    address: int
    sequence: int
    command: int
    payload_length: int
    payload: T


def is_mifare_request(
    request: AimeReaderRequest,
) -> TypeGuard[AimeReaderRequest[MifareRequestPayload]]:
    return request.command in (
        AimeReaderCommand.CARD_SELECT,
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


CardInfoFormat = Struct(
    "count" / Int8ul,
    "cards"
    / Array(
        this.count,
        Struct(
            "type" / Int8ul,
            "id_length" / Int8ul,
            "id" / Bytes(this.id_length),
        ),
    ),
)


class CardInfoCard(TypedDict):
    type: int
    id_length: int
    id: bytes


class CardSelectResponsePayload(TypedDict):
    count: int
    cards: list[CardInfoCard]


class CardType(IntEnum):
    MIFARE = 0x10
    FELICA = 0x20


AimeReaderResponseFormat = Struct(
    "length" / Int8ul,
    "address" / Int8ul,
    "sequence" / Int8ul,
    "command" / Int8ul,
    "status" / Int8ul,
    "payload_length" / Int8ul,
    "payload"
    / Switch(
        this.command,
        {
            AimeReaderCommand.CARD_DETECT.value: CardInfoFormat,
        },
        Bytes(this.payload_length),
    ),
)


class AimeReaderResponseDict(TypedDict):
    length: int
    address: int
    sequence: int
    command: int
    status: int
    payload_length: int
    payload: bytes | CardSelectResponsePayload


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
        self.card_dump: bytes | None = None
        self.card_dump_valid_until: float = 0

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

    def start(self):
        while self._keep_running:
            sleep(0.0075 if self.baud_rate == 9600 else 0.002)
            self.poll()

    def close(self):
        self._keep_running = False
        self._serial.close()

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
                    self._request_active = False
                else:
                    self.send_response(request, AimeReaderStatus.CHECKSUM_ERROR, b"")

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

                if self.card_dump is None or len(self.card_dump) < 64:
                    self.send_response(request, AimeReaderStatus.CARD_ERROR, b"")
                    return

                if request.command == AimeReaderCommand.MIFARE_AUTHORIZE_A:
                    card_key = self.card_dump[48:54]
                    expected_key = self._mifare_key_a
                else:
                    card_key = self.card_dump[58:64]
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

                if self.card_dump is None or len(self.card_dump) < 64:
                    self.send_response(request, AimeReaderStatus.CARD_ERROR, b"")
                    return

                self.send_response(
                    request,
                    AimeReaderStatus.OK,
                    self.card_dump[16 * block_no : 16 * (block_no + 1)],
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
                command=request.command,
                r=request.payload.r,
                g=request.payload.g,
                b=request.payload.b,
            )
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

            if time.time() > self.card_dump_valid_until:
                self.card_dump = None

            if self.card_dump is None:
                self.send_response(
                    request,
                    AimeReaderStatus.OK,
                    {"count": 0, "cards": []},
                )
                return

            self.send_response(
                request,
                AimeReaderStatus.OK,
                {
                    "count": 1,
                    "cards": [
                        {
                            "type": CardType.MIFARE.value,
                            "id_length": 4,
                            "id": self.card_dump[:4],
                        }
                    ],
                },
            )
            return

        if request.command in (
            AimeReaderCommand.CARD_SELECT,
            AimeReaderCommand.CARD_HALT,
        ):
            logger.debug("card select/halt")
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
            logger.debug("updater mode stuff", command=request.command)
            self.send_response(request, AimeReaderStatus.OK, b"")
            return

        if request.command == AimeReaderCommand.SEND_BINDATA_EXEC:
            logger.debug("sending update data", payload_length=request.payload_length)
            self.send_response(request, AimeReaderStatus.FIRM_UPDATE_SUCCESS, b"")
            return

        if request.command == AimeReaderCommand.SEND_HEX_DATA:
            logger.debug("sending hex data", payload_length=request.payload_length)
            self.send_response(request, AimeReaderStatus.COMP_DUMMY_3RD, b"")
            return

        logger.debug(
            "unknown command",
            command=request.command,
            payload=request.payload.hex(),
        )
        self.send_response(request, AimeReaderStatus.INVALID_COMMAND, b"")

    def send_response(
        self,
        request: AimeReaderRequest[Any],  # pyright: ignore[reportExplicitAny]
        status: AimeReaderStatus,
        payload: bytes | CardSelectResponsePayload,
    ):
        response: AimeReaderResponseDict = {
            "length": len(payload) + 6,
            "address": request.address,
            "sequence": request.sequence,
            "command": request.command,
            "status": status.value,
            "payload_length": len(payload),
            "payload": payload,
        }

        logger.debug(
            "sending response",
            status=status,
            payload=payload.hex() if isinstance(payload, bytes) else payload,
        )

        data = AimeReaderResponseFormat.build(cast(dict[str, Any], response))  # pyright: ignore[reportInvalidCast, reportExplicitAny]
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
    reader_lock = cast(threading.Lock, request.app.state.reader_lock)
    current_time = time.time()

    if reader.card_dump_valid_until > current_time:
        return JSONResponse(
            {"message": "Too many requests."},
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            headers={
                "Retry-After": f"{int(reader.card_dump_valid_until - current_time)}"
            },
        )

    data = await request.json()

    if not isinstance(data, dict):
        return JSONResponse(
            {"message": "Bad Request"},
            status_code=HTTP_400_BAD_REQUEST,
        )

    access_code = data.get("cardId")

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

    if data.get("physicalCardIDm") is not None:
        return JSONResponse(
            {"message": "FeliCa cards from AMNet are not supported."},
            status_code=HTTP_400_BAD_REQUEST,
        )
        # if not isinstance(physical_card_idm, str):
        #     return JSONResponse({"message": "Bad Request"}, status_code=HTTP_400_BAD_REQUEST)

        # if len(physical_card_idm) != 16 or any(c not in string.hexdigits for c in physical_card_idm):
        #     return JSONResponse({"message": "Invalid card IDm."}, status_code=HTTP_400_BAD_REQUEST)

        # if physical_card_idm == "0000000000000000":
        #     return JSONResponse({"message": "All-zero IDms are forbidden."}, status_code=HTTP_400_BAD_REQUEST)

    with reader_lock:
        reader.card_dump = bytes.fromhex(
            (
                "0102030426880400C819002000000018"
                # HACK: the serial at the end of block1 should be replaced with the serial from the actual AC
                # but it seems to card in so...
                "5342534400000000000000000050665B"
                f"000000000000{access_code}"
                "57434346763270F87811574343467632"
            )
        )
        reader.card_dump_valid_until = time.time() + 5

    return Response(status_code=HTTP_202_ACCEPTED)


async def signin(request: Request):
    reader = cast(AimeReader, request.app.state.reader)
    reader_lock = cast(threading.Lock, request.app.state.reader_lock)
    current_time = time.time()

    if reader.card_dump_valid_until > current_time:
        return JSONResponse(
            {"message": "Too many requests."},
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            headers={
                "Retry-After": f"{int(reader.card_dump_valid_until - current_time)}"
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

    with reader_lock:
        reader.card_dump = data
        reader.card_dump_valid_until = time.time() + 5

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
    reader_lock = threading.Lock()

    _ = signal.signal(signal.SIGTERM, lambda s, f: reader.close())
    _ = signal.signal(signal.SIGINT, lambda s, f: reader.close())
    threading.Thread(target=reader.start).start()

    app.state.started_at = time.time()
    app.state.reader = reader
    app.state.reader_lock = reader_lock
    uvicorn.run(app)


if __name__ == "__main__":
    main()
