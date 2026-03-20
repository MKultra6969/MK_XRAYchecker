import asyncio
import base64
import hashlib
import hmac
import os
import random
import re
import socket
import time

from telethon.network.connection.tcpmtproxy import ConnectionTcpMTProxyRandomizedIntermediate

__version__ = "1.3.2"

P25519 = 2 ** 255 - 19
BASE64_URLSAFE_RE = re.compile(r"[^a-zA-Z0-9+/_-]+")
SYSTEM_RANDOM = random.SystemRandom()


def _gen_sha256_digest(key, msg):
    return hmac.new(key=key, msg=msg, digestmod=hashlib.sha256).digest()


def _decode_b64(secret):
    cleaned = BASE64_URLSAFE_RE.sub("", secret)
    cleaned += "=" * (-len(cleaned) % 4)
    return base64.urlsafe_b64decode(cleaned)


def _coerce_faketls_secret(secret):
    if isinstance(secret, (bytes, bytearray)):
        full_secret = bytes(secret)
    else:
        secret_text = str(secret).strip()
        full_secret = None

        for candidate in (secret_text, f"ee{secret_text}"):
            try:
                full_secret = bytes.fromhex(candidate)
            except ValueError:
                continue
            if full_secret[:1] == b"\xEE":
                break
        else:
            for candidate in (secret_text, f"7{secret_text}"):
                try:
                    full_secret = _decode_b64(candidate)
                except Exception:
                    continue
                if full_secret[:1] == b"\xEE":
                    break
            else:
                full_secret = b""
    if len(full_secret) < 18:
        raise ValueError("FakeTLS secret is too short")
    if full_secret[0] != 0xEE:
        raise ValueError("FakeTLS secret must start with ee")
    return full_secret


def _gen_x25519_public_key():
    n = SYSTEM_RANDOM.randrange(P25519)
    return int.to_bytes((n * n) % P25519, length=32, byteorder="little")


class FakeTLSStreamReader:
    __slots__ = ("upstream", "buf")

    def __init__(self, upstream):
        self.upstream = upstream
        self.buf = bytearray()

    async def read(self, n, ignore_buf=False):
        if self.buf and not ignore_buf:
            data = self.buf
            self.buf = bytearray()
            return bytes(data)

        while True:
            tls_rec_type = await self.upstream.readexactly(1)
            if not tls_rec_type:
                return b""

            if tls_rec_type not in (b"\x14", b"\x17"):
                return b""

            version = await self.upstream.readexactly(2)
            if version != b"\x03\x03":
                return b""

            data_len = int.from_bytes(await self.upstream.readexactly(2), "big")
            data = await self.upstream.readexactly(data_len)
            if tls_rec_type == b"\x14":
                continue
            return data

    async def readexactly(self, n):
        while len(self.buf) < n:
            tls_data = await self.read(1, ignore_buf=True)
            if not tls_data:
                return b""
            self.buf += tls_data
        data, self.buf = self.buf[:n], self.buf[n:]
        return bytes(data)

    async def read_server_hello(self):
        server_hello = await self.upstream.readexactly(127 + 6 + 3 + 2)
        http_data_len = int.from_bytes(server_hello[-2:], "big")
        return server_hello + await self.upstream.readexactly(http_data_len)


class FakeTLSStreamWriter:
    __slots__ = ("upstream",)

    def __init__(self, upstream):
        self.upstream = upstream

    def write(self, data, extra=None):
        max_chunk_size = 16384 + 24
        for start in range(0, len(data), max_chunk_size):
            end = min(start + max_chunk_size, len(data))
            self.upstream.write(b"\x17\x03\x03" + int.to_bytes(end - start, 2, "big"))
            self.upstream.write(data[start:end])
        return len(data)

    def write_eof(self):
        return self.upstream.write_eof()

    async def drain(self):
        return await self.upstream.drain()

    def close(self):
        return self.upstream.close()

    def abort(self):
        return self.upstream.transport.abort()

    def get_extra_info(self, name):
        return self.upstream.get_extra_info(name)

    @property
    def transport(self):
        return self.upstream.transport


class MTProxyFakeTLSClientCodec:
    def __init__(self, secret):
        full_secret = _coerce_faketls_secret(secret)

        self.domain = full_secret[17:]
        self.secret = full_secret[1:17]
        if not self.domain:
            raise ValueError("FakeTLS secret is missing domain")

        self.client_hello_dict = {
            "content_type": b"\x16",
            "version": b"\x03\x01",
            "len": b"\x02\x00",
            "handshake_type": b"\x01",
            "handshake_len": b"\x00\x01\xfc",
            "handshake_version": b"\x03\x03",
            "random": b"\x00" * 32,
            "session_id_len": b"\x20",
            "session_id": b"\x00" * 32,
            "cipher_suites_len": b"\x00\x20",
            "cipher_suites": (
                b"\xfa\xfa\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30"
                b"\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35"
            ),
            "compression_methods_len": b"\x01",
            "compression_methods": b"\x00",
            "extensions_len": b"\x01\x93",
            "ext_reserved_1": b"\x4a\x4a\x00\x00",
            "ext_server_name_type": b"\x00\x00",
            "ext_server_name_len": b"\x00\x00",
            "ext_server_name_indication_list_len": b"\x00\x00",
            "ext_server_name_indication_type": b"\x00",
            "ext_server_name_indication_len": b"\x00\x00",
            "ext_server_name_indication": b"\x00",
            "ext_extended_master_secret": b"\x00\x17\x00\x00",
            "ext_renegotiation_info": b"\xff\x01\x00\x01\x00",
            "ext_supported_groups": b"\x00\x0a\x00\x0a\x00\x08\xba\xba\x00\x1d\x00\x17\x00\x18",
            "ext_ec_point_formats": b"\x00\x0b\x00\x02\x01\x00",
            "ext_session_ticket": b"\x00\x23\x00\x00",
            "ext_alpn": b"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31",
            "ext_status_request": b"\x00\x05\x00\x05\x01\x00\x00\x00\x00",
            "ext_signature_algorithms": (
                b"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01"
            ),
            "ext_signature_cert_timestamp": b"\x00\x12\x00\x00",
            "ext_key_share_type": b"\x00\x33",
            "ext_key_share_len": b"\x00\x2b",
            "ext_key_share_client_key_len": b"\x00\x29",
            "ext_key_share_reserved": b"\xba\xba\x00\x01\x00",
            "ext_key_share_group": b"\x00\x1d",
            "ext_key_share_exchange_len": b"\x00\x20",
            "ext_key_share_exchange": b"\x00",
            "ext_psk_key_exchange_modes": b"\x00\x2d\x00\x02\x01\x01",
            "ext_supported_tls_versions": b"\x00\x2b\x00\x0b\x0a\x9a\x9a\x03\x04\x03\x03\x03\x02\x03\x01",
            "ext_compress_cert": b"\x00\x1b\x00\x03\x02\x00\x02",
            "ext_reserved_2": b"\x1a\x1a\x00\x01\x00",
            "ext_padding_type": b"\x00\x15",
            "ext_padding_len": b"\x00\x00",
            "ext_padding": b"",
        }
        self.is_pkt_changed = True
        self.pkt = b""

    def client_hello(self, key, value=None):
        if value is None:
            return self.client_hello_dict[key]
        if isinstance(value, str):
            value = value.encode("utf-8")
        elif isinstance(value, int):
            value = value.to_bytes(length=len(self.client_hello_dict[key]), byteorder="big")
        self.client_hello_dict[key] = value
        self.is_pkt_changed = True

    def glue_pkt(self):
        if self.is_pkt_changed:
            self.pkt = b"".join(self.client_hello_dict.values())
            self.is_pkt_changed = False
        return self.pkt

    def gen_set_session_id(self):
        self.client_hello("session_id", os.urandom(32))

    def set_domain(self):
        domain_len = len(self.domain)
        self.client_hello("ext_server_name_len", 2 + 1 + 2 + domain_len)
        self.client_hello("ext_server_name_indication_list_len", 1 + 2 + domain_len)
        self.client_hello("ext_server_name_indication_len", domain_len)
        self.client_hello("ext_server_name_indication", self.domain)

    def gen_set_key_share(self):
        self.client_hello("ext_key_share_exchange", _gen_x25519_public_key())

    def fix_padding(self):
        self.client_hello("ext_padding", b"")
        padding_len = 517 - len(self.glue_pkt())
        self.client_hello("ext_padding_len", padding_len)
        self.client_hello("ext_padding", b"\x00" * padding_len)

    def gen_set_random(self):
        self.client_hello("random", b"\x00" * 32)
        digest = _gen_sha256_digest(self.secret, self.glue_pkt())
        current_time = int(time.time()).to_bytes(length=4, byteorder="little")
        xored_time = bytes(current_time[i] ^ digest[28 + i] for i in range(4))
        digest = digest[:28] + xored_time
        self.client_hello("random", digest)

    def build_new_client_hello_packet(self):
        self.gen_set_session_id()
        self.set_domain()
        self.gen_set_key_share()
        self.fix_padding()
        self.gen_set_random()
        return self.glue_pkt()

    def verify_server_hello(self, server_hello):
        if len(server_hello) < 127 + 6:
            return False
        if not server_hello.startswith(b"\x16\x03\x03"):
            return False
        if server_hello[127:136] != b"\x14\x03\x03\x00\x01\x01\x17\x03\x03":
            return False
        if server_hello[44:76] != self.client_hello_dict["session_id"]:
            return False

        client_digest = self.client_hello_dict["random"]
        server_digest = server_hello[11:43]
        server_hello = server_hello[:11] + (b"\x00" * 32) + server_hello[43:]
        computed_digest = _gen_sha256_digest(self.secret, client_digest + server_hello)
        return server_digest == computed_digest


class ConnectionTcpMTProxyFakeTLS(ConnectionTcpMTProxyRandomizedIntermediate):
    def __init__(self, ip, port, dc_id, *, loggers, proxy=None, local_addr=None):
        self.fake_tls_codec = MTProxyFakeTLSClientCodec(proxy[2])

        proxy_host = proxy[0]
        if len(proxy_host) > 60:
            proxy_host = socket.gethostbyname(proxy[0])

        proxy = (proxy_host, proxy[1], self.fake_tls_codec.secret.hex())
        super().__init__(ip, port, dc_id, loggers=loggers, proxy=proxy, local_addr=local_addr)

    async def _connect(self, timeout=None, ssl=None):
        if self._local_addr is not None:
            if isinstance(self._local_addr, tuple) and len(self._local_addr) == 2:
                local_addr = self._local_addr
            elif isinstance(self._local_addr, str):
                local_addr = (self._local_addr, 0)
            else:
                raise ValueError(f"Unknown local address format: {self._local_addr}")
        else:
            local_addr = None

        if not self._proxy:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=self._ip,
                    port=self._port,
                    ssl=ssl,
                    local_addr=local_addr,
                ),
                timeout=timeout,
            )
        else:
            sock = await self._proxy_connect(timeout=timeout, local_addr=local_addr)
            if ssl:
                sock = self._wrap_socket_ssl(sock)
            self._reader, self._writer = await asyncio.open_connection(sock=sock)

        self._writer.write(self.fake_tls_codec.build_new_client_hello_packet())
        await self._writer.drain()
        self._writer = FakeTLSStreamWriter(self._writer)
        self._reader = FakeTLSStreamReader(self._reader)

        if not self.fake_tls_codec.verify_server_hello(await self._reader.read_server_hello()):
            raise ConnectionError("FakeTLS server hello verification failed")

        self._codec = self.packet_codec(self)
        self._init_conn()
        await self._writer.drain()
