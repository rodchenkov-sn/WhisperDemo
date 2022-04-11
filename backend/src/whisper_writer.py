from typing import Protocol


class WhisperWriter(Protocol):
    def send_message(self, message: bytes) -> None:
        ...
