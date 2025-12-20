import asyncio
import time

from const import CLAMD_CNX_TIMEOUT, MAX_CHUNK_SIZE
from models import ClamAVResult
from monitor import Monitor
from mylogging import mylogging

logger = mylogging.getLogger("clamav")


class ClamAVException(Exception):
    """Custom exception for scan result fetch errors."""


class ClamAVConnectException(ClamAVException):
    """Scan Exception"""


class ClamAVSizeExceeded(ClamAVException):
    """Scan Exception"""


class ClamAVNoStatusException(ClamAVException):
    """Scan Exception"""


class ClamAVSendException(ClamAVException):
    """Scan Exception"""


class ClamAVTimeoutException(ClamAVException):
    """Scan Exception"""


class ClamAVResponseException(ClamAVException):
    """Scan Exception"""


class ClamAVScanner:
    """ClamAV Scanner class to scan files with clamd instance."""

    host: str
    port: int
    host_key: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

    def __init__(self, monitor: Monitor) -> None:
        """Initialize ClamAVScanner."""
        self.monitor = monitor
        self._statistics = {
            "scanned": 0,
            "cleaned": 0,
            "infected": 0,
            "errors": 0,
        }

    @property
    def statistics(self) -> dict[str, int]:
        """Return statis."""
        return self._statistics

    async def async_connect(self, host: str, port: int, host_key: str) -> None:
        """Test connection to clamd instance."""
        try:
            self.host = host
            self.port = port
            self.host_key = host_key
            logger.debug("Connecting to clamd %s:%d", self.host, self.port)
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=float(CLAMD_CNX_TIMEOUT),
            )
        except Exception as e:
            raise ClamAVConnectException(f"clamd-conn-error:{e}") from e

    async def async_scan(self, key: str, bucket: str, body) -> ClamAVResult:
        """Scan file with clamd instance."""

        start_time = time.monotonic()
        logger.debug("Scanning %s/%s", bucket, key)

        self._statistics["scanned"] += 1

        async def close_writer():
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass

        async def mark_error_and_close():
            await self.monitor.mark_host_done(
                self.host_key, elapsed=time.monotonic() - start_time, success=False
            )
            await close_writer()

        # send INSTREAM command and stream file
        try:
            self.writer.write(b"nINSTREAM\0")
            await self.writer.drain()

            async for chunk in body.iter_chunks(MAX_CHUNK_SIZE):
                if not chunk:
                    continue
                self.writer.write(len(chunk).to_bytes(4, "big") + chunk)
                await self.writer.drain()

            self.writer.write((0).to_bytes(4, "big"))
            await self.writer.drain()
        except BrokenPipeError as e:
            await mark_error_and_close()
            raise ClamAVSizeExceeded("[clamd-size-exceeded]") from e
        except Exception as e:
            await mark_error_and_close()
            raise ClamAVSendException(f"[clamd-send-error] {e}") from e
        else:
            # read response
            try:
                resp_bytes = await asyncio.wait_for(
                    self.reader.read(4096), timeout=float(CLAMD_CNX_TIMEOUT)
                )
                response = resp_bytes.decode(errors="ignore").strip()

                logger.debug("Clamd response for %s/%s: %s", bucket, key, response)

                self.writer.close()
                await self.writer.wait_closed()
            except asyncio.TimeoutError as e:
                await close_writer()
                raise ClamAVTimeoutException(
                    f"[clamd-response-timeout-{key}] {e}"
                ) from e
            except Exception as e:
                await close_writer()
                raise ClamAVResponseException(
                    f"[clamd-response-error-{key}] {e}"
                ) from e

            else:
                await close_writer()

            # Parse response
            elapsed = time.monotonic() - start_time
            if "OK" in response:
                self._statistics["cleaned"] += 1
                return ClamAVResult(
                    key=key,
                    bucket=bucket,
                    status="CLEAN",
                    instance=f"{self.host}:{self.port}",
                    analyse=round(elapsed, 3),
                )

            if "FOUND" in response:
                self._statistics["infected"] += 1
                infos = response.split("FOUND")[0].split(":")[-1].strip()
                return ClamAVResult(
                    key=key,
                    bucket=bucket,
                    status="INFECTED",
                    infos=infos,
                    instance=f"{self.host}:{self.port}",
                    analyse=round(elapsed, 3),
                )

            self._statistics["errors"] += 1
            return ClamAVResult(
                key=key,
                bucket=bucket,
                status="ERROR",
                infos="Not response",
                analyse=0,
                instance=f"{self.host}:{self.port}",
            )
