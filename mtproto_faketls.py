import asyncio
import base64
import hashlib
import hmac
import os
import random
import re
import socket
import sys
import time

from telethon.network.connection.tcpabridged import AbridgedPacketCodec
from telethon.network.connection.tcpintermediate import IntermediatePacketCodec
from telethon.network.connection.tcpmtproxy import ConnectionTcpMTProxyRandomizedIntermediate

__version__ = "1.4.1"

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
    __slots__ = ("upstream", "buf", "trace_enabled", "trace_prefix")

    def __init__(self, upstream, trace_enabled=False, trace_prefix=""):
        self.upstream = upstream
        self.buf = bytearray()
        self.trace_enabled = trace_enabled
        self.trace_prefix = trace_prefix

    def _trace(self, message):
        if not self.trace_enabled:
            return
        prefix = f" {self.trace_prefix}" if self.trace_prefix else ""
        print(f"[FakeTLS-TRACE]{prefix} {message}", file=sys.stderr, flush=True)

    async def _read_tls_record(self, timeout=None):
        header = await asyncio.wait_for(self.upstream.readexactly(5), timeout=timeout)
        tls_rec_type = header[:1]
        version = header[1:3]
        if version != b"\x03\x03":
            raise ConnectionError(f"Unexpected TLS version: {version.hex()}")

        data_len = int.from_bytes(header[3:5], "big")
        payload = await asyncio.wait_for(self.upstream.readexactly(data_len), timeout=timeout)
        return tls_rec_type, header + payload

    async def read(self, n, ignore_buf=False):
        if self.buf and not ignore_buf:
            data = self.buf
            self.buf = bytearray()
            return bytes(data)

        while True:
            tls_rec_type, tls_record = await self._read_tls_record()
            if tls_rec_type == b"\x14":
                continue
            if tls_rec_type != b"\x17":
                raise ConnectionError(f"Unexpected TLS record type: {tls_rec_type.hex()}")
            return tls_record[5:]

    async def readexactly(self, n):
        while len(self.buf) < n:
            tls_data = await self.read(1, ignore_buf=True)
            self.buf += tls_data
        data = bytes(self.buf[:n])
        self.buf = self.buf[n:]
        return data

    async def read_server_hello(self, timeout=None):
        record_timeout = 10.0 if timeout is None else max(float(timeout), 10.0)
        try:
            records = []
            app_data_records = 0
            record_index = 0
            self._trace(f"read_server_hello start timeout={record_timeout}")
            tls_rec_type, record = await self._read_tls_record(timeout=record_timeout)
            record_index += 1
            self._trace(
                f"record#{record_index}: type=0x{tls_rec_type.hex()} len={int.from_bytes(record[3:5], 'big')}"
            )
            if tls_rec_type != b"\x16":
                raise ConnectionError(f"Unexpected first TLS record type: {tls_rec_type.hex()}")
            records.append(record)

            while True:
                tls_rec_type, record = await self._read_tls_record(timeout=record_timeout)
                record_index += 1
                self._trace(
                    f"record#{record_index}: type=0x{tls_rec_type.hex()} len={int.from_bytes(record[3:5], 'big')}"
                )
                records.append(record)
                if tls_rec_type == b"\x17":
                    app_data_records += 1
                    self.buf += record[5:]
                    self._trace(
                        f"handoff after {record_index} TLS records; app_data_records_before_handoff={app_data_records}"
                    )
                    self._trace(
                        f"consumed app_data#{app_data_records}: payload_len={len(record) - 5} preview={record[5:21].hex()}"
                    )
                    return b"".join(records)
                if tls_rec_type != b"\x14":
                    raise ConnectionError(f"Unexpected TLS record type in server hello: {tls_rec_type.hex()}")
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError) as e:
            raise ConnectionError(f"Failed to read ServerHello: {e}") from e


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
    CIPHER_SUITES = (
        b"\xfa\xfa\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30"
        b"\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35"
    )
    FIXED_EXTENSIONS = (
        b"\x4a\x4a\x00\x00",
        b"\x00\x17\x00\x00",
        b"\xff\x01\x00\x01\x00",
        b"\x00\x0a\x00\x0a\x00\x08\xba\xba\x00\x1d\x00\x17\x00\x18",
        b"\x00\x0b\x00\x02\x01\x00",
        b"\x00\x23\x00\x00",
        b"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31",
        b"\x00\x05\x00\x05\x01\x00\x00\x00\x00",
        b"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01",
        b"\x00\x12\x00\x00",
        b"\x00\x2d\x00\x02\x01\x01",
        b"\x00\x2b\x00\x0b\x0a\x9a\x9a\x03\x04\x03\x03\x03\x02\x03\x01",
        b"\x00\x1b\x00\x03\x02\x00\x02",
        b"\x1a\x1a\x00\x01\x00",
    )

    def __init__(self, secret):
        full_secret = _coerce_faketls_secret(secret)

        self.domain = full_secret[17:]
        self.secret = full_secret[1:17]
        self.trace_enabled = os.environ.get("MK_XRAY_FAKE_TLS_TRACE") == "1"
        if not self.domain:
            raise ValueError("FakeTLS secret is missing domain")

        self.client_random = b"\x00" * 32
        self.session_id = b"\x00" * 32
        self.key_share = b"\x00" * 32
        self.ech_grease_flag = b"\x00"
        self.ech_grease_random = b"\x00" * 32
        self.pkt = b""

    @staticmethod
    def _pack_extension(ext_type, payload):
        return ext_type + len(payload).to_bytes(2, "big") + payload

    @staticmethod
    def _padding_extension_length(current_size):
        tls_record_header_size = 5
        if current_size <= tls_record_header_size:
            return 0

        message_length = current_size - tls_record_header_size
        if message_length <= 0xFF or message_length >= 0x200:
            return 0

        padding_length = 0x200 - message_length
        return padding_length if padding_length < 5 else padding_length - 4

    @staticmethod
    def _iter_tls_records(data):
        records = []
        offset = 0
        while offset < len(data):
            if len(data) - offset < 5:
                raise ValueError("Incomplete TLS record header")

            record_len = int.from_bytes(data[offset + 3:offset + 5], "big")
            next_offset = offset + 5 + record_len
            if next_offset > len(data):
                raise ValueError("Incomplete TLS record payload")

            records.append(data[offset:next_offset])
            offset = next_offset

        return records

    def _build_server_name_extension(self):
        host_name = bytes(self.domain)
        server_name = b"\x00" + len(host_name).to_bytes(2, "big") + host_name
        payload = len(server_name).to_bytes(2, "big") + server_name
        return self._pack_extension(b"\x00\x00", payload)

    def _build_key_share_extension(self):
        payload = b"\x00\x29\xba\xba\x00\x01\x00\x00\x1d\x00\x20" + self.key_share
        return self._pack_extension(b"\x00\x33", payload)

    def _build_ech_grease_extension(self):
        payload = (
            b"\x00\x01\x00\x01"
            + self.ech_grease_flag
            + b"\x00\x20"
            + self.ech_grease_random
            + len(self.key_share).to_bytes(2, "big")
            + self.key_share
        )
        return self._pack_extension(b"\xfe\x0d", payload)

    def _build_padding_extension(self, current_size):
        padding_len = self._padding_extension_length(current_size)
        if padding_len <= 0:
            return b""
        return self._pack_extension(b"\x00\x15", b"\x00" * padding_len)

    def _build_extensions(self, base_only=False):
        extensions = [self.FIXED_EXTENSIONS[0], self._build_server_name_extension()]
        extensions.extend(self.FIXED_EXTENSIONS[1:10])
        extensions.append(self._build_key_share_extension())
        extensions.extend(self.FIXED_EXTENSIONS[10:13])
        extensions.append(self._build_ech_grease_extension())
        extensions.append(self.FIXED_EXTENSIONS[13])

        encoded = b"".join(extensions)
        if base_only:
            return encoded

        packet_without_padding = self._build_packet(self.client_random, encoded)
        return encoded + self._build_padding_extension(len(packet_without_padding))

    def _build_packet(self, random_bytes, extensions):
        handshake_body = (
            b"\x03\x03"
            + random_bytes
            + len(self.session_id).to_bytes(1, "big")
            + self.session_id
            + len(self.CIPHER_SUITES).to_bytes(2, "big")
            + self.CIPHER_SUITES
            + b"\x01\x00"
            + len(extensions).to_bytes(2, "big")
            + extensions
        )
        handshake = b"\x01" + len(handshake_body).to_bytes(3, "big") + handshake_body
        return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    def gen_set_session_id(self):
        self.session_id = os.urandom(32)

    def gen_set_key_share(self):
        self.key_share = _gen_x25519_public_key()

    def gen_set_ech_grease(self):
        self.ech_grease_flag = os.urandom(1)
        self.ech_grease_random = os.urandom(32)

    def gen_set_random(self):
        base_extensions = self._build_extensions(base_only=False)
        digest = _gen_sha256_digest(self.secret, self._build_packet(b"\x00" * 32, base_extensions))
        current_time = int(time.time()).to_bytes(length=4, byteorder="little")
        xored_time = bytes(current_time[i] ^ digest[28 + i] for i in range(4))
        self.client_random = digest[:28] + xored_time

    def build_new_client_hello_packet(self):
        self.gen_set_session_id()
        self.gen_set_key_share()
        self.gen_set_ech_grease()
        self.gen_set_random()
        self.pkt = self._build_packet(self.client_random, self._build_extensions())
        return self.pkt

    def verify_server_hello(self, server_hello):
        try:
            records = self._iter_tls_records(server_hello)
        except ValueError:
            return False

        if len(records) < 2:
            return False
        if records[0][:3] != b"\x16\x03\x03":
            return False
        if any(record[1:3] != b"\x03\x03" for record in records):
            return False
        if records[-1][:1] != b"\x17":
            return False
        if any(record[:1] not in (b"\x14", b"\x17") for record in records[1:]):
            return False
        if len(records[0]) < 44:
            return False

        handshake_payload = records[0][5:]
        if len(handshake_payload) < 39 or handshake_payload[:1] != b"\x02":
            return False

        session_id_len = handshake_payload[38]
        session_id = handshake_payload[39:39 + session_id_len]
        if session_id != self.session_id:
            return False
        if len(records[0]) < 43:
            return False

        client_digest = self.client_random
        server_digest = server_hello[11:43]
        zeroed_server_hello = bytearray(server_hello)
        zeroed_server_hello[11:43] = b"\x00" * 32
        computed_digest = _gen_sha256_digest(self.secret, client_digest + bytes(zeroed_server_hello))
        return server_digest == computed_digest


class ConnectionTcpMTProxyFakeTLS(ConnectionTcpMTProxyRandomizedIntermediate):
    def __init__(self, ip, port, dc_id, *, loggers, proxy=None, local_addr=None):
        self.fake_tls_codec = MTProxyFakeTLSClientCodec(proxy[2])

        proxy_host = proxy[0]
        if len(proxy_host) > 60:
            proxy_host = socket.gethostbyname(proxy[0])

        self._trace_label = f"{proxy_host}:{proxy[1]}"
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
        self._reader = FakeTLSStreamReader(
            self._reader,
            trace_enabled=self.fake_tls_codec.trace_enabled,
            trace_prefix=self._trace_label,
        )

        if not self.fake_tls_codec.verify_server_hello(await self._reader.read_server_hello(timeout=timeout)):
            raise ConnectionError("FakeTLS server hello verification failed")

        self._codec = self.packet_codec(self)
        self._init_conn()
        await self._writer.drain()

        # Give the proxy a brief chance to reject an incompatible packet codec
        # right after the initial payload, mirroring Telethon's MTProxy logic.
        try:
            await asyncio.wait_for(self._reader.upstream._wait_for_data("proxy"), 2)
        except asyncio.TimeoutError:
            pass
        except Exception:
            await asyncio.sleep(2)

        if self._reader.upstream.at_eof():
            await self.disconnect()
            raise ConnectionError("Proxy closed the connection after sending initial payload")


class ConnectionTcpMTProxyFakeTLSIntermediate(ConnectionTcpMTProxyFakeTLS):
    packet_codec = IntermediatePacketCodec


class ConnectionTcpMTProxyFakeTLSAbridged(ConnectionTcpMTProxyFakeTLS):
    packet_codec = AbridgedPacketCodec
