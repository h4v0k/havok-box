"""Tiny serial CLI session helper (Flipper / Marauder USB-CLI boards).

pyserial is imported lazily inside the class so this module, and the helpers built on it, import
fine in test environments where pyserial is not installed (tests inject a fake session object
with the same write/read interface).
"""
from __future__ import annotations

import time


class SerialSession:
    def __init__(self, port: str, baud: int = 115200, prompt: str = "", _serial=None):
        if not isinstance(port, str) or not port.startswith("/dev/"):
            raise ValueError("serial port must be a /dev/ path")
        self.port, self.baud, self.prompt = port, baud, prompt
        if _serial is not None:          # injected (tests)
            self._ser = _serial
        else:
            import serial                # lazy import: pyserial not installed in CI
            self._ser = serial.Serial(port, baud, timeout=0.1)

    def _read_chunk(self) -> str:
        data = self._ser.read(4096)
        if not data:
            return ""
        if isinstance(data, (bytes, bytearray)):
            return data.decode("utf-8", "replace")
        return str(data)

    def send(self, line: str) -> None:
        self._ser.write((line.rstrip("\r\n") + "\r\n").encode())

    def read_for(self, seconds: float) -> str:
        end = time.monotonic() + seconds
        buf = []
        while time.monotonic() < end:
            chunk = self._read_chunk()
            if chunk:
                buf.append(chunk)
            else:
                time.sleep(0.02)
        return "".join(buf)

    def read_until(self, prompt: str | None = None, timeout: float = 10.0) -> str:
        prompt = prompt if prompt is not None else self.prompt
        end = time.monotonic() + timeout
        buf = ""
        while time.monotonic() < end:
            chunk = self._read_chunk()
            if chunk:
                buf += chunk
                if prompt and prompt in buf:
                    break
            else:
                time.sleep(0.02)
        return buf

    def send_ctrl_c(self) -> None:
        self._ser.write(b"\x03")

    def close(self) -> None:
        try:
            self._ser.close()
        except Exception:
            pass
