from __future__ import annotations

import logging
import os
import socket
import ssl
import sys
import threading
import typing
import warnings


from urllib3.exceptions import HTTPWarning
from urllib3.util import ALPN_PROTOCOLS, resolve_cert_reqs, resolve_ssl_version
from urllib3.util.ssltransport import SSLTransport

if typing.TYPE_CHECKING:
    from typing_extensions import ParamSpec

    P = ParamSpec("P")


if typing.TYPE_CHECKING:
    from typing_extensions import Literal


log = logging.getLogger(__name__)

CERTS_PATH = os.path.join(os.path.dirname(__file__), "certs")
DEFAULT_CERTS: dict[str, typing.Any] = {
    "certfile": os.path.join(CERTS_PATH, "server.crt"),
    "keyfile": os.path.join(CERTS_PATH, "server.key"),
    "cert_reqs": ssl.CERT_OPTIONAL,
    "ca_certs": os.path.join(CERTS_PATH, "cacert.pem"),
    "alpn_protocols": ALPN_PROTOCOLS,
}
DEFAULT_CA = os.path.join(CERTS_PATH, "cacert.pem")
DEFAULT_CA_KEY = os.path.join(CERTS_PATH, "cacert.key")


def _resolves_to_ipv6(host: str) -> bool:
    """Returns True if the system resolves host to an IPv6 address by default."""
    resolves_to_ipv6 = False
    try:
        for res in socket.getaddrinfo(host, None, socket.AF_UNSPEC):
            af, _, _, _, _ = res
            if af == socket.AF_INET6:
                resolves_to_ipv6 = True
    except socket.gaierror:
        pass

    return resolves_to_ipv6


def _has_ipv6(host: str) -> bool:
    """Returns True if the system can bind an IPv6 address."""
    sock = None
    has_ipv6 = False

    if socket.has_ipv6:
        # has_ipv6 returns true if cPython was compiled with IPv6 support.
        # It does not tell us if the system has IPv6 support enabled. To
        # determine that we must bind to an IPv6 address.
        # https://github.com/urllib3/urllib3/pull/611
        # https://bugs.python.org/issue658327
        try:
            sock = socket.socket(socket.AF_INET6)
            sock.bind((host, 0))
            has_ipv6 = _resolves_to_ipv6("localhost")
        except Exception:
            pass

    if sock:
        sock.close()
    return has_ipv6


# Some systems may have IPv6 support but DNS may not be configured
# properly. We can not count that localhost will resolve to ::1 on all
# systems. See https://github.com/urllib3/urllib3/pull/611 and
# https://bugs.python.org/issue18792
HAS_IPV6_AND_DNS = _has_ipv6("localhost")
HAS_IPV6 = _has_ipv6("::1")


# Different types of servers we have:


class NoIPv6Warning(HTTPWarning):
    "IPv6 is not available"


class SocketServerThread(threading.Thread):
    """
    :param socket_handler: Callable which receives a socket argument for one
        request.
    :param ready_event: Event which gets set when the socket handler is
        ready to receive requests.
    """

    USE_IPV6 = HAS_IPV6_AND_DNS

    def __init__(
        self,
        socket_handler: typing.Callable[[socket.socket], None],
        host: str = "localhost",
        ready_event: threading.Event | None = None,
    ) -> None:
        super().__init__()
        self.daemon = True

        self.socket_handler = socket_handler
        self.host = host
        self.ready_event = ready_event

    def _start_server(self) -> None:
        if self.USE_IPV6:
            sock = socket.socket(socket.AF_INET6)
        else:
            warnings.warn("No IPv6 support. Falling back to IPv4.", NoIPv6Warning)
            sock = socket.socket(socket.AF_INET)
        if sys.platform != "win32":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, 0))
        self.port = sock.getsockname()[1]

        # Once listen() returns, the server socket is ready
        sock.listen(1)

        if self.ready_event:
            self.ready_event.set()

        self.socket_handler(sock)
        sock.close()

    def run(self) -> None:
        self._start_server()


def ssl_options_to_context(  # type: ignore[no-untyped-def]
    keyfile=None,
    certfile=None,
    server_side=None,
    cert_reqs=None,
    ssl_version: str | int | None = None,
    ca_certs=None,
    do_handshake_on_connect=None,
    suppress_ragged_eofs=None,
    ciphers=None,
    alpn_protocols=None,
) -> ssl.SSLContext:
    """Return an equivalent SSLContext based on ssl.wrap_socket args."""
    ssl_version = resolve_ssl_version(ssl_version)
    cert_none = resolve_cert_reqs("CERT_NONE")
    if cert_reqs is None:
        cert_reqs = cert_none
    else:
        cert_reqs = resolve_cert_reqs(cert_reqs)

    ctx = ssl.SSLContext(ssl_version)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.verify_mode = cert_reqs
    if ctx.verify_mode != cert_none:
        ctx.load_verify_locations(cafile=ca_certs)
    if alpn_protocols and hasattr(ctx, "set_alpn_protocols"):
        try:
            ctx.set_alpn_protocols(alpn_protocols)
        except NotImplementedError:
            pass
    return ctx


def get_unreachable_address() -> tuple[str, int]:
    # reserved as per rfc2606
    return ("something.invalid", 54321)


# consume_socket can iterate forever, we add timeouts to prevent halting.
PER_TEST_TIMEOUT = 60


def server_client_ssl_contexts() -> tuple[ssl.SSLContext, ssl.SSLContext]:
    if hasattr(ssl, "PROTOCOL_TLS_SERVER"):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(DEFAULT_CERTS["certfile"], DEFAULT_CERTS["keyfile"])

    if hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    client_context.load_verify_locations(DEFAULT_CA)
    return server_context, client_context


@typing.overload
def sample_request(binary: Literal[True] = ...) -> bytes:
    ...


@typing.overload
def sample_request(binary: Literal[False]) -> str:
    ...


def sample_request(binary: bool = True) -> bytes | str:
    request = (
        b"GET http://www.testing.com/ HTTP/1.1\r\n"
        b"Host: www.testing.com\r\n"
        b"User-Agent: awesome-test\r\n"
        b"\r\n"
    )
    return request if binary else request.decode("utf-8")


def validate_request(
    provided_request: bytearray, binary: Literal[False, True] = True
) -> None:
    assert provided_request is not None
    expected_request = sample_request(binary)
    assert provided_request == expected_request


@typing.overload
def sample_response(binary: Literal[True] = ...) -> bytes:
    ...


@typing.overload
def sample_response(binary: Literal[False]) -> str:
    ...


@typing.overload
def sample_response(binary: bool = ...) -> bytes | str:
    ...


def sample_response(binary: bool = True) -> bytes | str:
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    return response if binary else response.decode("utf-8")


def validate_response(
    provided_response: bytes | bytearray | str, binary: bool = True
) -> None:
    assert provided_response is not None
    expected_response = sample_response(binary)
    assert provided_response == expected_response


def validate_peercert(ssl_socket: SSLTransport) -> None:

    binary_cert = ssl_socket.getpeercert(binary_form=True)
    assert type(binary_cert) == bytes
    assert len(binary_cert) > 0

    cert = ssl_socket.getpeercert()
    assert type(cert) == dict
    assert "serialNumber" in cert
    assert cert["serialNumber"] != ""


def consume_socket(
    sock: SSLTransport | socket.socket, chunks: int = 65536
) -> bytearray:
    consumed = bytearray()
    while True:
        b = sock.recv(chunks)
        assert isinstance(b, bytes)
        consumed += b
        if b.endswith(b"\r\n\r\n"):
            break
    return consumed


class SingleTLSLayerTestCase:
    """
    Uses the SocketDummyServer to validate a single TLS layer can be
    established through the SSLTransport.
    """
    """
    A simple socket-based server is created for this class that is good for
    exactly one request.
    """

    scheme = "http"
    host = "localhost"

    server_thread: typing.ClassVar[SocketServerThread]
    port: typing.ClassVar[int]

    tmpdir: typing.ClassVar[str]
    ca_path: typing.ClassVar[str]
    cert_combined_path: typing.ClassVar[str]
    cert_path: typing.ClassVar[str]
    key_path: typing.ClassVar[str]
    password_key_path: typing.ClassVar[str]

    server_context: typing.ClassVar[ssl.SSLContext]
    client_context: typing.ClassVar[ssl.SSLContext]

    proxy_server: typing.ClassVar[SocketDummyServerTestCase]

    @classmethod
    def _start_server(
        cls, socket_handler: typing.Callable[[socket.socket], None]
    ) -> None:
        ready_event = threading.Event()
        cls.server_thread = SocketServerThread(
            socket_handler=socket_handler, ready_event=ready_event, host=cls.host
        )
        cls.server_thread.start()
        ready_event.wait(5)
        if not ready_event.is_set():
            raise Exception("most likely failed to start server")
        cls.port = cls.server_thread.port

    @classmethod
    def start_response_handler(
        cls, response: bytes, num: int = 1, block_send: threading.Event | None = None
    ) -> threading.Event:
        ready_event = threading.Event()

        def socket_handler(listener: socket.socket) -> None:
            for _ in range(num):
                ready_event.set()

                sock = listener.accept()[0]
                consume_socket(sock)
                if block_send:
                    block_send.wait()
                    block_send.clear()
                sock.send(response)
                sock.close()

        cls._start_server(socket_handler)
        return ready_event

    @classmethod
    def start_basic_handler(
        cls, num: int = 1, block_send: threading.Event | None = None
    ) -> threading.Event:
        return cls.start_response_handler(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            num,
            block_send,
        )

    @classmethod
    def teardown_class(cls) -> None:
        if hasattr(cls, "server_thread"):
            cls.server_thread.join(0.1)

    def assert_header_received(
        self,
        received_headers: typing.Iterable[bytes],
        header_name: str,
        expected_value: str | None = None,
    ) -> None:
        header_name_bytes = header_name.encode("ascii")
        if expected_value is None:
            expected_value_bytes = None
        else:
            expected_value_bytes = expected_value.encode("ascii")
        header_titles = []
        for header in received_headers:
            key, value = header.split(b": ")
            header_titles.append(key)
            if key == header_name_bytes and expected_value_bytes is not None:
                assert value == expected_value_bytes
        assert header_name_bytes in header_titles

    @classmethod
    def setup_class(cls) -> None:
        cls.server_context, cls.client_context = server_client_ssl_contexts()

    def start_dummy_server(
        self, handler: typing.Callable[[socket.socket], None] | None = None
    ) -> None:
        def socket_handler(listener: socket.socket) -> None:
            sock = listener.accept()[0]
            try:
                with self.server_context.wrap_socket(sock, server_side=True) as ssock:
                    request = consume_socket(ssock)
                    validate_request(request)
                    ssock.send(sample_response())
            except (ConnectionAbortedError, ConnectionResetError):
                return

        chosen_handler = handler if handler else socket_handler
        self._start_server(chosen_handler)

    def test_unwrap_existing_socket(self) -> None:
        """
        Validates we can break up the TLS layer
        A full request/response is sent over TLS, and later over plain text.
        """

        def shutdown_handler(listener: socket.socket) -> None:
            sock = listener.accept()[0]
            ssl_sock = self.server_context.wrap_socket(sock, server_side=True)

            request = consume_socket(ssl_sock)
            validate_request(request)
            ssl_sock.sendall(sample_response())

            unwrapped_sock = ssl_sock.unwrap()

            request = consume_socket(unwrapped_sock)
            validate_request(request)
            unwrapped_sock.sendall(sample_response())

        self.start_dummy_server(shutdown_handler)
        sock = socket.create_connection((self.host, self.port))
        ssock = SSLTransport(sock, self.client_context, server_hostname="localhost")

        # request/response over TLS.
        ssock.sendall(sample_request())
        response = consume_socket(ssock)
        validate_response(response)

        # request/response over plaintext after unwrap.
        ssock.unwrap()
        sock.sendall(sample_request())
        response = consume_socket(sock)
        validate_response(response)
