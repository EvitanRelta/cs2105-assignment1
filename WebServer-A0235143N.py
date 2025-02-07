import sys, socket
from typing import Literal, TypeAlias
from dataclasses import dataclass, field

HOST = "127.0.0.1"
MAX_NUM_CONCURRENT_CONNECTIONS = 1

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
            buffer = b""
            while True:
                chunk = connection.recv(1024)
                if not chunk:
                    connection.close()  # Client disconnected
                    break
                buffer += chunk
                req_list, buffer = SimpleHTTPRequest.parse_chunk(buffer)
                for req in req_list:
                    res = handle_request(req, key_value_store, counter_store)
                    connection.send(res.encode())


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
    prefix, key = req.path[1:].split("/", 1)
    assert prefix.count("/") == 0
    prefix = "/" + prefix

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
            assert "CONTENT-LENGTH" in req.headers
            assert int(req.headers["CONTENT-LENGTH"]) == len(req.body)

            # Insertion.
            if key not in key_value_store:
                key_value_store[key] = req.body
                return SimpleHTTPResponse(200, "OK")

            # Update.
            is_temp_key = key in counter_store
            if is_temp_key:
                assert counter_store[key] > 0
                return SimpleHTTPResponse(405, "MethodNotAllowed")

            key_value_store[key] = req.body
            return SimpleHTTPResponse(200, "OK")

        case "GET":
            assert len(req.body) == 0

            if key not in key_value_store:
                return SimpleHTTPResponse(404, "NotFound")

            data = key_value_store[key]

            is_temp_key = key in counter_store
            if is_temp_key:
                assert counter_store[key] > 0
                counter_store[key] -= 1
                if counter_store[key] <= 0:
                    del counter_store[key]
                    del key_value_store[key]

            return SimpleHTTPResponse(200, "OK").with_body(data)

        case "DELETE":
            assert len(req.body) == 0

            if key not in key_value_store:
                return SimpleHTTPResponse(404, "NotFound")

            is_temp_key = key in counter_store
            if is_temp_key:
                assert counter_store[key] > 0
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
            assert "CONTENT-LENGTH" in req.headers
            assert int(req.headers["CONTENT-LENGTH"]) == len(req.body)
            assert int(req.body) >= 0

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
        opt_header_names = [
            x.upper() for x in optional_header_substrings[0::2]
        ]  # Case-insensitive
        opt_header_values = optional_header_substrings[1::2]

        return SimpleHTTPRequest(
            method=method,
            path=path,
            headers=dict(zip(opt_header_names, opt_header_values)),
            body=b"",
        )

    @classmethod
    def parse_chunk(cls, chunk: bytes) -> tuple[list["SimpleHTTPRequest"], bytes]:
        """Parse a chunk (or multiple concatenated chunks), converting all the
        completed requests into `SimpleHTTPRequest` instances and returns them
        along with the bytes of the last incomplete request (if any).

        Returns:
            tuple[list[SimpleHTTPRequest], bytes]: A list of all the completed \
                request, the bytes of the last incomplete request (if any).
        """
        req_list: list[SimpleHTTPRequest] = []
        splitted_chunk = chunk.split(b"  ", 1)
        while len(splitted_chunk) > 1:
            raw_header, rest = splitted_chunk
            bodiless_req = cls._decode_headers_only(raw_header)

            # Request has complete header, with no additional body.
            if "CONTENT-LENGTH" not in bodiless_req.headers:
                req_list.append(bodiless_req)
                splitted_chunk = rest.split(b"  ", 1)
                continue

            # Last request's body is incomplete.
            body_len = int(bodiless_req.headers["CONTENT-LENGTH"])
            if len(rest) < body_len:
                return req_list, raw_header + b"  " + rest

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
        self.headers["CONTENT-LENGTH"] = str(len(body))
        return self

    def encode(self) -> bytes:
        assert " " not in self.status_text
        encoded_headers = " ".join(
            f"{key} {value}" for key, value in self.headers.items()
        )
        return (
            f"{self.status} {self.status_text}{(' ' + encoded_headers) if encoded_headers else ''}  "
        ).encode() + self.body


if __name__ == "__main__":
    main()
