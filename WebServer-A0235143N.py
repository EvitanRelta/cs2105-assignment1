import sys, socket, os
from typing import Literal, TypeAlias
from dataclasses import dataclass

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
                data = connection.recv(1024)
                if not data:
                    break
                req = SimpleHTTPRequest.decode(data)

                prefix, key = os.path.dirname(req.path), os.path.basename(req.path)
                assert prefix[0] == "/" and prefix.count("/") == 1
                assert "/" not in key

                res: SimpleHTTPResponse = None  # type:ignore
                match prefix:
                    case "/key":
                        res = handle_key_requests(
                            req, key, key_value_store, counter_store
                        )
                    case "/counter":
                        res = handle_counter_requests(
                            req, key, key_value_store, counter_store
                        )
                    case "_":
                        raise Exception(
                            f'Expected prefix to be "/key" or "/counter", got {prefix}'
                        )

                connection.send(res.encode())


# ==============================================================================
#                                HELPER FUNCTIONS
# ==============================================================================
def get_port() -> int:
    return int(sys.argv[1])


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
                return SimpleHTTPResponse(200, "OK").with_body(bytes(count))

            return SimpleHTTPResponse(200, "OK").with_body(b"Infinity")

        case "DELETE":
            assert len(req.body) == 0

            if key not in counter_store:
                return SimpleHTTPResponse(404, "NotFound")

            count = counter_store[key]
            del counter_store[key]
            del key_value_store[key]
            return SimpleHTTPResponse(200, "OK").with_body(bytes(count))


# ==============================================================================
#                                 CUSTOM CLASSES
# ==============================================================================
@dataclass
class SimpleHTTPRequest:
    method: Method
    path: str
    headers: dict[str, str]
    body: bytes

    @staticmethod
    def decode(encoded_req: bytes) -> "SimpleHTTPRequest":
        raw_header, raw_body = encoded_req.decode().split("  ", 1)
        header_fields = raw_header.split(" ")
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
            body=raw_body.encode(),
        )


@dataclass
class SimpleHTTPResponse:
    status: int
    status_text: str
    headers: dict[str, str] = {}
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
            f"{self.status} {self.status_text} {encoded_headers}  {self.body.decode()}"
        ).encode()


if __name__ == "__main__":
    main()
