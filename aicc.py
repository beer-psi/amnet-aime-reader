import struct
from Crypto.Cipher import DES3


_SPAD0_TABLE = [
    bytes.fromhex("""
    afa863a924c0f1bee7b3ac1685b9116f103132aeb17823d2a2caf92b45b83c621a6d828c00d9e27a46192acc13a7e4b7849b8efffb8b03893029d38701bf35da
    595ccd097f7041816c5f53c272d4794895b45b39449dfd5171f6d7d52d9fed33eaaa5a176ababde99cce4d7c183b0dee0c80a10a8fb56bf73fd14725c636e87d
    7b3ef39975051ce0cf34bb9eeb91ad268dc76608e6584014a6c5fa12ecc4f0218a86d6e106b660742ee3fe272f5ef4b2682856ef9a6122a3c90b02964fdbe590
    4a4c92cb9869d057640e3750abbcde7607c83d49fc7794f8c197653a4b836e73881e5d045467df15b0c3932c38ddf5a4550f4e1da01f20a5dc43f2d87e521b42
    """),
    bytes.fromhex("""
    034bb897b78f0d71dc49a790ffa09df8235f206c11f9698eefcbf014df1b7ac6365bc593b62835b23bd1ecf39f80642505cf54af463f9606e510fbaade624151
    59e729b54d3df2376ae8168b5ca81e57e209eb32c92eb4f1a476d3c1a5706012b1ea66e14a92a16d3af4d56fdad80a5818632ba35d67776b39c3db4c02bacebb
    5501178527e43072c88dfc7819b9432d089b1ad9cd26fa82cc7f75799e65feed91c731d0522a488474dd7de9ae6e3347d6500c53a6bd22ac8a04894240b3455a
    44e6a91dc481e3151f5687d43e0f95d7e094ab246807a2987beef5b088c0389c995eadd23c2c21ca8c7e1c61c2347c2f0b839a4fbe4ebc731300f60e86bffdf7
    """),
    bytes.fromhex("""
    4107938a40ff0e2f54fcacd41eb0c889df00644ff3cb2cc08f6e17bf95992a0d51ad4bcaf76955384cc668c3a31f833e0b70c7b24ecffe4dfd8bb496cef9f1d3
    4360aed5b3db4ab9e5ea6a485da787dab8062d94c1662426b19a25085c59a6af279288f2ed1b1c11d22216765667149fee5fdc5ba446dd1033297f5ac9978485
    42bcab773ca1c2aa374961359c8619575ee6e2a0046dd1a89dec02bdd847621a057d013f186f7544e47af6a9e872f46bfb7eeb3652de79238de77163986cd9e9
    3b13900378742081ba3432fa7b31d63d300ae3128e0f1dbba573538280b5d7e13a2bd0e021becd1565b6efcc91f50cc42e9e58f0c59b3909a27c45b7288cf850
    """),
    bytes.fromhex("""
    76cd167fe96b953a4ebb6eccd2b369a972afc782386fbc37a62836bdc3cf85460a996397835688a10264ac795565ffc2ef7a592b1ce08c8f5ae4b49ffcf74547
    4aeac00debc878c96703053114ded373fa1fb6501304b77b491af9174d4f8620c1fda0a548e13c60f20b300f4cee8d6dbe8ec6f6d808941b2ab59ea293f522a8
    3426a77cec3f0e3bb2f429ce2e428132255f66db7dd7e72d436a5b19ad3e9bc5ab84c46c33dafb8a1154fe574b3d7e09a39140bf68e5b9f396f851ca9ab098ae
    1e9c5ee8003912dc0c108b5dd62c27d5618753ba23712f1d74899ddd3515d044b1cbf06258a477e318d4e680d1aa90700124f121d90675b8415c92dfed07e252
    """),
    bytes.fromhex("""
    aa94997492d61c4647792f567af7b50ac906d7fa4011a5ff1fe8008cddb7426e35f0bec21dcab68ee2444e9f51818b4c5d5938d38f25b30931ad0b6b0e50bbd8
    9688de49eab44a9a306d2c0fcdf67e4f52d9fb28076319a4ee01f8ebd2f53d0d915b67b857f32be668167b6f65c376e33c2e413ecf54e117a7452d5afcc682ef
    cb78ac34ba712722f2123f1a24a8c19ec718e45ffe6cafc837c577bd02297dfd5e83e9bf2a5c73e5dae7ec806a03583b2113d1537093bca110f4648587b061b1
    f14362c4f9a2aed40486df26d0ab361e4be06090cc98953a9c9b151b338d4d239d84ceb205a60cb91448d5a375087ced7fdc8966a9c0397220978aa05569db32
    """),
    bytes.fromhex("""
    de5a1b693c42a3514038f117281cb8ace89945a01268ce15c9476dc8464e1ea611f83e31fae62dfd32149c01b1ed5771e330cf0ee7cc374a78ab1d96ea258520
    494d7552eeefaf5433f9099e81e1732af23d2213928bf0c0840da804dc8dbb2c9403f5d1d02e5deb5e626f21b091fecb0aecb72f3424d6e96682c6191fd9c1a7
    f688028707ddd867c5b929a4c265d353aa3b79e072d7061a58937e0c906e740f4c0be46c43d24136bddb35595fa99f5580398ef3d5e563c377a25b7b7faebaa1
    10df4b2b9b16bc00c718fb64fff4f7be0556cd084f6a9a767ab595ca507d7c6ba5c43a8a27dab66123867048979dfc8f5c44b2ad83bf26d4b36098e23f8cb489
    """),
    bytes.fromhex("""
    192e5d7a5b7c7e39ef8b2fcc861bc28c20fb595f21cd9f94a70bba0e477ba506b7d8c926f09d68f25e123a65b05ce222998210f5445074a1f942a8254dea083e
    9692c42da22334a9456b797fc84c43672904fab51e05c6b4af1dbbf730edecab40e098e94b11871518beee78b1025790328e61cb3ce6d77531b95436e1dd6c97
    62ac41899c60f663bc147d77d50995df174a0c2b5238feb633a451736d4fb3bf71eb693f13001c6f9b35caa32a768d800116033de583708f5a5888f3e30fc307
    46ff49fde8ce85d1dcf1b8d36ed4a0ad72dae73b84f8d228dec11a64910ae4c5246ad653c7812cc093d90da6dbaecff455661f37fcbd48aa4e56279ed08ab29a
    """),
    bytes.fromhex("""
    54d94250b874ab32a624486ff07ed730b46d06a288d659394c2caf6ea82b665cb91ce75319568a11d8615f0703dab5b008d0274500c3f5b1796bc45b21e2553d
    a0fe319a360feccbbb72291af976876aaec952b7eb7bf305940401c6a1f437e3fbc14fba9e80282f5af6913ecf41adbeb6339bfccec068ee3f51bf4ed249a9f7
    8f86c82a6738e44dc72e637fefdf97aa5d620b70d1e6139992f8d3123c6484a70ab29cea1bcc5e431ecd8d93e1713bf2a323e9c2dd988b73965722350ea5ac0c
    d49f09db3a1660e589852d771d8120c57aedca1483fa1f2618479d02e05810fd2575bc46dea4154078344a17d50d6965dc4b7c95e88eff7d908c826cb3bd44f1
    """),
    bytes.fromhex("""
    c30bb81500a43dd9fd16e90820e68dc4473825935eaaec2a106e58952653041e929e2f8bbd0a69a93b41f0d0da6aa1711363ef9094b0ebe7dc73b9787ae4c76d
    7fa3ac8550f391ea36fa9b8ef7aec1431cc0ca8f4ea23112742c9df1ad3f68bb359a7c03fb092327d44d17de4cee769ca0e175db5b11a721af02424b83d3ce9f
    cdcc302b5222cb597d14f9b17054e0815a1d0e4af484ed961ad7c982892d8733e25c513a1bf6e5d8320d5f7288d6b7c6dd1f803764b57bdfffd240fc6005b666
    61c82899bca53419f8fe2448d10c55626b86b3ba8a2e6fa6676501e8183e7e77298cf2076ca8794f444606c2ab0fb4b2be98d549e3f5cf975dbf573c39c54556
    """),
]
_SPAD0_INV_TABLE: list[bytes] = []
_N_TABLES = len(_SPAD0_TABLE) - 1
_ITER_ADD = 5

for table in _SPAD0_TABLE:
    inv_table = bytearray(256)

    for i in range(256):
        inv_table[table[i]] = i

    _SPAD0_INV_TABLE.append(bytes(inv_table))


def rotate_right(data: bytearray, n_bytes: int, n_bits: int):
    prior = data[n_bytes - 1]
    for i in range(n_bytes):
        prior, data[i] = (
            data[i],
            (data[i] >> n_bits) | ((prior & ((1 << n_bits) - 1)) << (8 - n_bits)),
        )


def rotate_left(data: bytearray, n_bytes: int, n_bits: int):
    prior = data[0]
    for i in range(n_bytes - 1, -1, -1):
        prior, data[i] = (
            data[i],
            ((data[i] & ((1 << (8 - n_bits)) - 1)) << n_bits) | (prior >> (8 - n_bits)),
        )


def spad0_encrypt(spad: bytes):
    spad = bytearray(spad)

    count = (spad[15] >> 4) + 7
    table = spad[15]

    for _ in range(count):
        for i in range(15):
            spad[i] = _SPAD0_TABLE[table % _N_TABLES][spad[i]]
        rotate_left(spad, 15, 5)
        table += _ITER_ADD

    return bytearray(_SPAD0_TABLE[_N_TABLES][i] for i in spad)


def spad0_decrypt(spad: bytes):
    spad = bytearray(_SPAD0_INV_TABLE[_N_TABLES][i] for i in spad)

    count = (spad[15] >> 4) + 7
    table = spad[15] + _ITER_ADD * count

    for _ in range(count):
        table -= _ITER_ADD
        rotate_right(spad, 15, 5)
        for i in range(15):
            spad[i] = _SPAD0_INV_TABLE[table % _N_TABLES][spad[i]]

    return spad


CK_GEN_KEY = [
    0x1223491CAF37206D.to_bytes(8, "little"),
    0x5F3F1D16BADD58A2.to_bytes(8, "little"),
    0xC2F2EA946A755EE7.to_bytes(8, "little"),
]


def aicc_generate_card_key_inner(data: bytes, id_key: int):
    cipher = DES3.new(CK_GEN_KEY[0] + CK_GEN_KEY[1] + CK_GEN_KEY[2], DES3.MODE_ECB)
    data = cipher.encrypt(data)

    data = (int.from_bytes(data, "little") ^ id_key).to_bytes(8, "little")

    cipher = DES3.new(CK_GEN_KEY[0] + CK_GEN_KEY[1] + CK_GEN_KEY[2], DES3.MODE_ECB)
    data = cipher.encrypt(data)

    return data[::-1]


def aicc_generate_card_key(id: bytearray):
    cipher = DES3.new(CK_GEN_KEY[0] + CK_GEN_KEY[1] + CK_GEN_KEY[2], DES3.MODE_ECB)
    data = bytearray(cipher.encrypt(b"\x00" * 8))

    will_overflow = (data[0] & 0x80) != 0

    for i in range(8):
        if i != 0 and (data[i] & 0x80) != 0:
            data[i - 1] |= 1
        data[i] = (data[i] << 1) % 256

    if will_overflow:
        data[7] ^= 0x1B

    id_key = int.from_bytes(data, "little") ^ int.from_bytes(id[8:16], "little")
    key0 = aicc_generate_card_key_inner(id[0:8], id_key)

    id[0] ^= 0x80

    key1 = aicc_generate_card_key_inner(id[0:8], id_key)

    id[0] ^= 0x80

    return key0 + key1


def felica_generate_mac(data: bytes, key: bytes, iv: bytes, *, flip_key: bool = False):
    assert len(data) % 8 == 0 and len(key) == 16 and len(iv) == 8
    key = bytes(key[8:] + key[:8]) if flip_key else bytes(key)
    txt = b"".join(
        [
            struct.pack("{}B".format(len(x)), *reversed(x))
            if isinstance(x[0], int)
            else b"".join(reversed(x))
            for x in zip(*[iter(bytes(data))] * 8)
        ]
    )

    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(txt)[:-9:-1]


class AICCard:
    def __init__(self, idm: bytes, access_code: bytes) -> None:
        self.idm: bytes = idm
        self.access_code: bytes = access_code

        self.spads: list[bytearray] = [bytearray(16)] * 14
        self.spads.append(bytearray(b"\xff" * 16))

        self._rc: bytearray = bytearray(16)
        self._mac: bytearray = bytearray(16)
        self._id: bytearray = bytearray(idm + b"\x00" * 8)
        self._d_id: bytearray = bytearray(idm + b"\x00" * 8)
        self._ser_c: bytearray = bytearray(16)
        self._sys_c: bytearray = bytearray(16)
        self._ckv: bytearray = bytearray(16)
        self._ck: bytearray = bytearray(16)
        self._mc: bytearray = bytearray(16)

        # Felica Lite/Felica LiteS
        self._sys_c[0] = 0x88
        self._sys_c[1] = 0xB4

        # felica chip type LiteS, written to PMm
        self._d_id[9] = 0xF1

        # PMm timings
        self._d_id[10] = 0x00
        self._d_id[11] = 0x00
        self._d_id[12] = 0x00
        self._d_id[13] = 0x01
        self._d_id[14] = 0x43
        self._d_id[15] = 0x00

        # determine the DFC of the card based on the access code prefix
        # kinda crude, but whatever
        access_code_str = self.access_code.hex()

        # SEGA
        if access_code_str.startswith(("500", "501")):
            self._id[8] = 0x00
            self._id[9] = 0x78
        # Bandai Namco Entertainment
        elif access_code_str.startswith("510"):
            self._id[8] = 0x00
            self._id[9] = 0x2A
        # KONAMI
        elif access_code_str.startswith("520"):
            self._id[8] = 0x00
            self._id[9] = 0x68
        # TAiTO
        elif access_code_str.startswith("530"):
            self._id[8] = 0x00
            self._id[9] = 0x79
        # Testing
        else:
            self._id[8] = self._id[9] = 0x00

        # arbitrary data
        self._id[10] = 0x05
        self._id[11] = 0x73
        self._id[12] = 0x02
        self._id[13] = 0x01
        self._id[14] = 0x02
        self._id[15] = 0x00

        # finally, encrypt the access code to spad0
        self.spads[0] = spad0_encrypt(b"\x00\x00\x00\x00\x00\x00" + self.access_code)

    def read_blocks(self, block_numbers: list[int]):
        result: list[bytearray | bytes] = []

        if block_numbers[-1] == 0x81:
            mode = "with_mac"
            block_numbers = block_numbers[:-1]
        elif block_numbers[-1] == 0x91:
            mode = "with_mac_a"
            block_numbers = block_numbers[:-1]
        else:
            mode = "without_mac"

        for block_number in block_numbers:
            result.append(self.read_block(block_number))

        if mode == "without_mac":
            return result

        rc = self._rc[7::-1] + self._rc[15:7:-1]
        card_key = aicc_generate_card_key(self._id)
        session_key = DES3.new(card_key, DES3.MODE_CBC, b"\x00" * 8).encrypt(rc)
        data = b"".join(result)

        if mode == "with_mac":
            mac = felica_generate_mac(data, session_key, rc[0:8]) + b"\x00" * 8

            result.append(mac)

        if mode == "with_mac_a":
            mac_data = b""

            for block_number in block_numbers:
                mac_data += block_number.to_bytes(2, "little")

            mac_data += b"\x91\x00"
            mac_data = mac_data.ljust(8, b"\xff") + data

            # technically the next 3 bytes of MAC_A is write count, but we already return write count 0.
            maca = (
                felica_generate_mac(mac_data, session_key, rc[0:8])
                + self.read_block(0x90)[:3]
                + b"\x00" * 5
            )

            result.append(maca)

        return result

    def read_block(self, block_number: int):
        # TODO: Proper access controls
        if block_number < 0x0F:
            return self.spads[block_number]

        if block_number == 0x82:
            return self._id

        if block_number == 0x83:
            return self._d_id

        if block_number == 0x84:
            return self._ser_c

        if block_number == 0x85:
            return self._sys_c

        if block_number == 0x86:
            return self._ckv

        if block_number == 0x88:
            return self._mc

        if block_number == 0x90:  # WCNT
            return b"\x02\x00\x00" + b"\x00" * 13

        # We return an empty bytearray for CK/RC/MAC/MAC_A and unknown blocks.
        return bytearray(16)

    def write_block(self, block_number: int, data: bytes | bytearray):
        # TODO: Proper access controls
        if block_number < 0x0F:
            self.spads[block_number] = bytearray(data)

        if block_number == 0x80:
            self._rc = bytearray(data)

        if block_number == 0x82:
            self._id = bytearray(data)

        if block_number == 0x83:
            self._d_id = bytearray(data)

        if block_number == 0x84:
            self._ser_c = bytearray(data)

        if block_number == 0x85:
            self._sys_c = bytearray(data)

        if block_number == 0x86:
            self._ckv = bytearray(data)

        if block_number == 0x87:
            self._ck = bytearray(data)

        if block_number == 0x88:
            self._mc = bytearray(data)
