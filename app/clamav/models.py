from typing import Literal

from pydantic import BaseModel, field_validator


class ClamAVResult(BaseModel):
    status: Literal["ERROR", "PENDING", "CLEAN", "INFECTED", "ERROR"] = "PENDING"
    instance: str | None = None
    infos: str | None = None
    analyse: float | None = None

    @field_validator("analyse", mode="before")
    @classmethod
    def round_analyse(cls, v):
        """Round analyse to 2 decimal places."""
        if v is None:
            return None
        return round(float(v), 2)


class ClamAVStatsResponse(BaseModel):
    """ClamAV STATS response model."""

    pools: int
    state: str
    threads_live: int
    threads_idle: int
    threads_max: int
    threads_idle_timeout: int
    queue_items: int
    stats_time: float

    @classmethod
    def parse_stats(cls, response: str) -> "ClamAVStatsResponse":
        """Parse ClamAV STATS response string."""
        lines = response.strip().split("\n")

        pools = 0
        state = ""
        threads_live = 0
        threads_idle = 0
        threads_max = 0
        threads_idle_timeout = 0
        queue_items = 0
        stats_time = 0.0

        for line in lines:
            line = line.strip()

            if line.startswith("POOLS:"):
                pools = int(line.split(":")[1].strip())

            elif line.startswith("STATE:"):
                state = line.split(":", 1)[1].strip()

            elif line.startswith("THREADS:"):
                # THREADS: live 1  idle 0 max 10 idle-timeout 30
                parts = line.split()
                threads_live = int(parts[2])
                threads_idle = int(parts[4])
                threads_max = int(parts[6])
                threads_idle_timeout = int(parts[8])

            elif line.startswith("QUEUE:"):
                # QUEUE: 0 items
                queue_items = int(line.split()[1])

            elif line.startswith("STATS"):
                # STATS 0.000077
                stats_time = float(line.split()[1])

        return cls(
            pools=pools,
            state=state,
            threads_live=threads_live,
            threads_idle=threads_idle,
            threads_max=threads_max,
            threads_idle_timeout=threads_idle_timeout,
            queue_items=queue_items,
            stats_time=stats_time,
        )
