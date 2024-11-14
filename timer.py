import time
from typing import Optional


class Timer:
    def __init__(self) -> None:
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

    def start(self) -> None:
        self.start_time = time.time()

    def stop(self) -> None:
        self.end_time = time.time()

    def start_stop(self) -> None:
        self.start_time = time.time()
        self.end_time = self.start_time

    def duration(self) -> str:
        if self.start_time is None:
            raise ValueError("Timer not started")
        if self.end_time is None:
            raise ValueError("Timer not stopped")
        duration = self.end_time - self.start_time
        days = int(duration // 86400)
        hours = int((duration % 86400) // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = round(duration % 60, 2)
        duration_str = ""
        if days > 0:
            duration_str += f"{days}d"
        if hours > 0:
            duration_str += f"{hours}h"
        if minutes > 0:
            duration_str += f"{minutes}m"
        duration_str += f"{seconds:.2f}s"
        return duration_str
