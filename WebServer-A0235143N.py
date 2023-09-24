import sys, socket, os
from typing import Literal, TypeAlias
from dataclasses import dataclass, field

HOST = "127.0.0.1"
MAX_NUM_CONCURRENT_CONNECTIONS = 1
MAX_SEGMENT_DELAY_MS = 1000
MAX_BODY_BYTES = 5 * (10**6)
MAX_REQUEST_BYTES = 2 * MAX_BODY_BYTES  # With some leeway for header size.

Method: TypeAlias = Literal["GET", "POST", "DELETE"]
VALID_METHODS: list[Method] = ["GET", "POST", "DELETE"]


def main():
    key_value_store: dict[str, bytes] = {}
    counter_store: dict[str, int] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, get_port()))
        s.listen(MAX_NUM_CONCURRENT_CONNECTIONS)

        while True:
            connection, address = s.accept()
            with connection:
                buffer = b""
                while True:
                    chunk = connection.recv(1024)
                    if not chunk:
                        break  # Client disconnected
                    buffer += chunk
                    req_list, buffer = SimpleHTTPRequest.process_chunk(chunk)
                    for req in req_list:
                        res = handle_request(req, key_value_store, counter_store)
                        connection.send(res.encode())


def test_process_chunks(chunks: list[bytes]) -> list[bytes]:
    key_value_store: dict[str, bytes] = {}
    counter_store: dict[str, int] = {}

    buffer = b""
    output: list[bytes] = []
    while len(chunks) > 0:
        chunk = chunks.pop(0)
        buffer += chunk
        req_list, buffer = SimpleHTTPRequest.process_chunk(buffer)
        for req in req_list:
            res = handle_request(req, key_value_store, counter_store)
            output.append(res.encode())

    return output


# ==============================================================================
#                                HELPER FUNCTIONS
# ==============================================================================
def get_port() -> int:
    return int(sys.argv[1])


def handle_request(
    req: "SimpleHTTPRequest",
    key_value_store: dict[str, bytes],
    counter_store: dict[str, int],
) -> "SimpleHTTPResponse":
    prefix, key = os.path.dirname(req.path), os.path.basename(req.path)
    assert prefix[0] == "/" and prefix.count("/") == 1
    assert "/" not in key

    res: SimpleHTTPResponse = None  # type: ignore
    match prefix:
        case "/key":
            res = handle_key_requests(req, key, key_value_store, counter_store)
        case "/counter":
            res = handle_counter_requests(req, key, key_value_store, counter_store)
        case "_":
            raise Exception(f'Expected prefix to be "/key" or "/counter", got {prefix}')
    return res


def handle_key_requests(
    req: "SimpleHTTPRequest",
    key: str,
    key_value_store: dict[str, bytes],
    counter_store: dict[str, int],
) -> "SimpleHTTPResponse":
    match req.method:
        case "POST":
            assert len(req.body) > 0
            assert "Content-Length" in req.headers
            assert int(req.headers["Content-Length"]) == len(req.body)

            # Insertion.
            if key not in key_value_store:
                key_value_store[key] = req.body
                return SimpleHTTPResponse(200, "OK")

            # Update.
            is_temp_key = key in counter_store
            assert counter_store[key] > 0
            if is_temp_key:
                return SimpleHTTPResponse(405, "MethodNotAllowed")

            key_value_store[key] = req.body
            return SimpleHTTPResponse(200, "OK")

        case "GET":
            assert len(req.body) == 0

            if key not in key_value_store:
                return SimpleHTTPResponse(404, "NotFound")

            is_temp_key = key in counter_store
            assert counter_store[key] > 0
            if is_temp_key:
                counter_store[key] -= 1
                if counter_store[key] <= 0:
                    del counter_store[key]
                    del key_value_store[key]

            data = key_value_store[key]
            return SimpleHTTPResponse(200, "OK").with_body(data)

        case "DELETE":
            assert len(req.body) == 0

            if key not in key_value_store:
                return SimpleHTTPResponse(404, "NotFound")

            is_temp_key = key in counter_store
            assert counter_store[key] > 0
            if is_temp_key:
                return SimpleHTTPResponse(405, "MethodNotAllowed")

            data = key_value_store[key]
            del key_value_store[key]
            return SimpleHTTPResponse(200, "OK").with_body(data)


def handle_counter_requests(
    req: "SimpleHTTPRequest",
    key: str,
    key_value_store: dict[str, bytes],
    counter_store: dict[str, int],
) -> "SimpleHTTPResponse":
    match req.method:
        case "POST":
            assert len(req.body) > 0
            assert "Content-Length" in req.headers
            assert int(req.headers["Content-Length"]) == len(req.body)
            assert int(req.body) > 0

            # Insertion.
            if key not in key_value_store:
                return SimpleHTTPResponse(405, "MethodNotAllowed")
            if key not in counter_store:
                counter_store[key] = int(req.body)
                return SimpleHTTPResponse(200, "OK")

            # Update.
            counter_store[key] += int(req.body)
            return SimpleHTTPResponse(200, "OK")

        case "GET":
            assert len(req.body) == 0

            if key not in key_value_store:
                return SimpleHTTPResponse(404, "NotFound")

            if key in counter_store:
                count = counter_store[key]
                return SimpleHTTPResponse(200, "OK").with_body(str(count).encode())

            return SimpleHTTPResponse(200, "OK").with_body(b"Infinity")

        case "DELETE":
            assert len(req.body) == 0

            if key not in counter_store:
                return SimpleHTTPResponse(404, "NotFound")

            count = counter_store[key]
            del counter_store[key]
            del key_value_store[key]
            return SimpleHTTPResponse(200, "OK").with_body(str(count).encode())


# ==============================================================================
#                                 CUSTOM CLASSES
# ==============================================================================
@dataclass
class SimpleHTTPRequest:
    method: Method
    path: str
    headers: dict[str, str]
    body: bytes

    def _with_body(self, body: bytes) -> "SimpleHTTPRequest":
        self.body = body
        return self

    @classmethod
    def _decode_headers_only(cls, raw_header: bytes) -> "SimpleHTTPRequest":
        header_fields = raw_header.decode().split(" ")
        assert len(header_fields) >= 2

        method = header_fields[0].upper()  # Case-insensitive
        assert method in VALID_METHODS
        path = header_fields[1]  # Case-sensitive
        optional_header_substrings = header_fields[2:]

        return SimpleHTTPRequest(
            method=method,
            path=path,
            headers=dict(
                zip(optional_header_substrings[0::2], optional_header_substrings[1::2])
            ),
            body=b"",
        )

    @classmethod
    def process_chunk(cls, chunk: bytes) -> tuple[list["SimpleHTTPRequest"], bytes]:
        req_list: list[SimpleHTTPRequest] = []
        splitted_chunk = chunk.split(b"  ", 1)
        while len(splitted_chunk) > 1:
            raw_header, rest = splitted_chunk
            bodiless_req = cls._decode_headers_only(raw_header)

            # Request has complete header, with no additional body.
            if "Content-Length" not in bodiless_req.headers:
                req_list.append(bodiless_req)
                splitted_chunk = rest.split(b"  ", 1)
                continue

            # Last request's body is incomplete.
            body_len = int(bodiless_req.headers["Content-Length"])
            if len(rest) < body_len:
                return req_list, raw_header + rest

            # Request has complete header + body.
            raw_body, rest = rest[:body_len], rest[body_len:]
            req = bodiless_req._with_body(raw_body)
            req_list.append(req)
            splitted_chunk = rest.split(b"  ", 1)

        return req_list, splitted_chunk[0]


@dataclass
class SimpleHTTPResponse:
    status: int
    status_text: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def with_body(self, body: bytes) -> "SimpleHTTPResponse":
        self.body = body
        self.headers["Content-Length"] = str(len(body))
        return self

    def encode(self) -> bytes:
        assert " " not in self.status_text
        encoded_headers = " ".join(
            f"{key} {value}" for key, value in self.headers.items()
        )
        return (
            f"{self.status} {self.status_text}{(' ' + encoded_headers) if encoded_headers else ''}  {self.body.decode()}"
        ).encode()


if __name__ == "__main__":
    main()
