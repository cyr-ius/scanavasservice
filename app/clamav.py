import asyncio
import time

from const import CLAMD_CHUNK_SIZE, CLAMD_CNX_TIMEOUT, CLAMD_HOSTS
from models import ClamAVResult, ClamAVStatsResponse
from monitor import Monitor
from mylogging import mylogging

logger = mylogging.getLogger("clamav")


class ClamAVException(Exception):
    """Base ClamAV Exception."""


class ClamAVConnectException(ClamAVException):
    """Error while connecting to clamd."""


class ClamAVSizeExceeded(ClamAVException):
    """File size exceeded exception."""


class ClamAVNoStatusException(ClamAVException):
    """No status received from clamd."""


class ClamAVSendException(ClamAVException):
    """Error while sending data to clamd."""


class ClamAVTimeoutException(ClamAVException):
    """Timeout Exception"""


class ClamAVResponseException(ClamAVException):
    """Error while receiving response from clamd."""


class ClamAVScanner:
    """ClamAV Scanner class to scan files with clamd instance."""

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

    async def async_connect(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Test connection to clamd instance."""
        try:
            logger.debug("Connecting to clamd %s:%d", host, port)
            return await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=float(CLAMD_CNX_TIMEOUT),
            )
        except Exception as e:
            self._statistics["errors"] += 1
            raise ClamAVConnectException(f"clamd-conn-error:{e}") from e

    async def async_scan(self, key: str, bucket: str, body) -> ClamAVResult:
        """Scan file with clamd instance."""

        start_time = time.monotonic()
        logger.debug("Scanning %s/%s", bucket, key)

        self._statistics["scanned"] += 1

        host, port, host_key = await self.monitor.select_best_host()
        await self.monitor.mark_host_busy(host_key)

        # connect to clamd
        reader, writer = await self.async_connect(host, port)

        async def close_writer():
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        async def mark_error_and_close():
            await self.monitor.mark_host_done(
                host_key, elapsed=time.monotonic() - start_time, success=False
            )
            await close_writer()

        try:
            # send INSTREAM command and stream file
            try:
                writer.write(b"nINSTREAM\n")
                await writer.drain()

                async for chunk in body.iter_chunks(CLAMD_CHUNK_SIZE):
                    if not chunk:
                        continue
                    writer.write(len(chunk).to_bytes(4, "big") + chunk)
                    await writer.drain()

                writer.write((0).to_bytes(4, "big"))
                await writer.drain()
            except BrokenPipeError as e:
                self._statistics["errors"] += 1
                await close_writer()
                raise ClamAVSizeExceeded("[clamd-size-exceeded]") from e
            except Exception as e:
                self._statistics["errors"] += 1
                await mark_error_and_close()
                raise ClamAVSendException(f"[clamd-send-error] {e}") from e

            # read response
            try:
                resp_bytes = await asyncio.wait_for(
                    reader.read(4096), timeout=float(CLAMD_CNX_TIMEOUT)
                )
                response = resp_bytes.decode(errors="ignore").strip()

                logger.debug("Clamd response for %s/%s: %s", bucket, key, response)

            except asyncio.TimeoutError as e:
                self._statistics["errors"] += 1
                await close_writer()
                raise ClamAVTimeoutException(
                    f"[clamd-response-timeout-{key}] {e}"
                ) from e
            except Exception as e:
                self._statistics["errors"] += 1
                await close_writer()
                raise ClamAVResponseException(
                    f"[clamd-response-error-{key}] {e}"
                ) from e

            # Parse response
            elapsed = time.monotonic() - start_time
            await self.monitor.mark_host_done(host_key, elapsed=elapsed, success=True)
            logger.debug(
                "Scan completed for %s/%s in %.3f seconds (%s)",
                bucket,
                key,
                elapsed,
                response,
            )

            if "OK" in response:
                self._statistics["cleaned"] += 1
                return ClamAVResult(
                    key=key,
                    bucket=bucket,
                    status="CLEAN",
                    instance=f"{host}:{port}",
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
                    instance=f"{host}:{port}",
                    analyse=round(elapsed, 3),
                )

            self._statistics["errors"] += 1
            return ClamAVResult(
                key=key,
                bucket=bucket,
                status="ERROR",
                infos="Not response",
                analyse=0,
                instance=f"{host}:{port}",
            )
        finally:
            await close_writer()

    async def async_stats(self) -> dict[str, ClamAVStatsResponse]:
        """Get ClamAV STATS."""
        response = {}
        for host, port in CLAMD_HOSTS:
            r, w = await self.async_connect(host, port)
            w.write(b"zSTATS\0")
            await w.drain()

            resp_bytes = await asyncio.wait_for(
                r.read(4096), timeout=float(CLAMD_CNX_TIMEOUT)
            )
            rslt = resp_bytes.decode(errors="ignore").strip()

            w.close()
            await w.wait_closed()
            response[f"{host}:{port}"] = ClamAVStatsResponse.parse_stats(
                rslt
            ).model_dump()
        return response
