from __future__ import annotations

import platform
import select
import socket
import ssl
import typing
from unittest import mock

import pytest

from dummyserver.server import DEFAULT_CA, DEFAULT_CERTS
from urllib3.util import ssl_
from urllib3.util.ssltransport import SSLTransport
import asyncio
import contextlib
import socket
import ssl
import threading
import typing

import pytest
from tornado import httpserver, ioloop, web

from dummyserver.proxy import ProxyHandler
from dummyserver.server import (
    DEFAULT_CERTS,
    HAS_IPV6,
    SocketServerThread,
    run_loop_in_thread,
    run_tornado_app,
)
from urllib3.connection import HTTPConnection
from urllib3.util.ssltransport import SSLTransport

if typing.TYPE_CHECKING:
    from typing_extensions import Literal

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


class SocketDummyServerTestCase:
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


class SingleTLSLayerTestCase(SocketDummyServerTestCase):
    """
    Uses the SocketDummyServer to validate a single TLS layer can be
    established through the SSLTransport.
    """

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
