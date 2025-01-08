import time
import re


class StopWatch:
    def __init__(self, init_time: str = "0s") -> None:
        self.start_time = time.time()
        self.end_time = self.start_time
        self.set_duration_from_string(init_time)

    def start(self) -> None:
        self.start_time = time.time()

    def stop(self) -> None:
        self.end_time = time.time()

    def duration(self) -> str:
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

    def set_duration_from_string(self, time_format: str) -> None:
        pattern = r'(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?'
        match = re.fullmatch(pattern, time_format)
        if not match:
            raise ValueError("Invalid time format. Expected format like '1d2h30m15.5s'.")
        days, hours, minutes, seconds = (float(x or 0) for x in match.groups())
        self.end_time = self.start_time + int(days * 86400 + hours * 3600 + minutes * 60 + seconds)


class Timer:
    def __init__(self, duration: str) -> None:
        self.stopwatch = StopWatch(duration)

    def start(self, duration: str) -> None:
        self.stopwatch = StopWatch(duration)

    def triggered(self) -> bool:
        if not self.stopwatch:
            raise ValueError("Timer has not been started.")
        current_time = time.time()
        elapsed_time = current_time - self.stopwatch.start_time
        return elapsed_time >= (self.stopwatch.end_time - self.stopwatch.start_time)
