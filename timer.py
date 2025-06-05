import time
import re
from typing import Callable, Optional
import types
import signal


def duration_to_str(duration: float) -> str:
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


def str_to_duration(duration: str) -> tuple[int, int, int, float]:
    pattern = r'(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?'
    match = re.fullmatch(pattern, duration)
    if not match:
        raise ValueError("Invalid time format. Expected format like '1d2h30m15.5s'.")
    days, hours, minutes, seconds = (float(x or 0) for x in match.groups())
    return int(days), int(hours), int(minutes), seconds


def str_to_duration_float(duration: str) -> float:
    days, hours, minutes, seconds = str_to_duration(duration)
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


class StopWatch:
    start_time: float
    end_time: float

    def __init__(self) -> None:
        pass

    @staticmethod
    def started() -> 'StopWatch':
        s = StopWatch()
        s.start()
        return s

    def start(self) -> None:
        self.start_time = time.time()
        self.end_time = self.start_time
        self.stopped = False

    def stop(self) -> None:
        self.end_time = time.time()
        self.stopped = True

    def __str__(self) -> str:
        current = time.time()
        return duration_to_str(current - self.start_time)

    def elapsed(self) -> float:
        if self.stopped:
            return self.end_time - self.start_time
        else:
            current = time.time()
            return current - self.start_time

    def set_duration_from_string(self, duration: str) -> None:
        self.end_time = self.start_time + str_to_duration_float(duration)


class Timer:
    stopwatch: StopWatch
    d: float

    def __init__(self, target_duration: str) -> None:
        self.start(target_duration)

    def reset(self) -> None:
        self.stopwatch = StopWatch.started()

    def start(self, target_duration: str) -> None:
        self.stopwatch = StopWatch.started()
        self.d = str_to_duration_float(target_duration)

    def triggered(self) -> bool:
        return self.stopwatch.elapsed() >= self.d

    def elapsed(self) -> str:
        return duration_to_str(min(self.stopwatch.elapsed(), self.d))

    def target_duration(self) -> str:
        return duration_to_str(self.d)

    def __str__(self) -> str:
        return self.elapsed()

    def run_with_timeout(self, func: Callable[[], None]) -> None:
        def handler(signum: int, frame: Optional[types.FrameType]) -> None:
            signum = signum
            frame = frame
            raise TimeoutError(f"Timed out after {self.target_duration()}")

        signal.signal(signal.SIGALRM, handler)
        signal.alarm(int(self.d))
        try:
            return func()
        except TimeoutError as e:
            raise e
        finally:
            signal.alarm(0)
