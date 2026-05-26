from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable

from .config import settings
from .schema import SysmonEvent, SysmonEvents

logger = logging.getLogger(__name__)

DetectionHandler = Callable[[SysmonEvents], Awaitable[None]]


class HostWindowBuffer:
    def __init__(self, on_window_close: DetectionHandler) -> None:
        self._on_window_close = on_window_close
        self._windows: dict[str, SysmonEvents] = {}
        self._timers: dict[str, asyncio.Task[None]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def add(self, host_key: str, events: list[SysmonEvent]) -> None:
        if not events:
            return
        lock = await self._lock_for(host_key)
        async with lock:
            window = self._windows.get(host_key)
            if window is None:
                window = SysmonEvents(host_key=host_key)
                self._windows[host_key] = window
                self._timers[host_key] = asyncio.create_task(self._close_after_delay(host_key))
            remaining = settings.max_buffered_events_per_host - len(window.events)
            if remaining <= 0:
                logger.warning("host=%s buffer full, dropping %d events", host_key, len(events))
                return
            if len(events) > remaining:
                logger.warning(
                    "host=%s buffer near full, truncating %d -> %d",
                    host_key,
                    len(events),
                    remaining,
                )
                events = events[:remaining]
            window.events.extend(events)

    async def _lock_for(self, host_key: str) -> asyncio.Lock:
        async with self._global_lock:
            lock = self._locks.get(host_key)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[host_key] = lock
            return lock

    async def _close_after_delay(self, host_key: str) -> None:
        try:
            await asyncio.sleep(settings.window_seconds)
        except asyncio.CancelledError:
            return
        await self._close(host_key)

    async def _close(self, host_key: str) -> None:
        lock = await self._lock_for(host_key)
        async with lock:
            window = self._windows.pop(host_key, None)
            self._timers.pop(host_key, None)
        if window is None or not window.events:
            return
        logger.info("host=%s window closed with %d events", host_key, len(window.events))
        try:
            await self._on_window_close(window)
        except Exception:
            logger.exception("host=%s detection pipeline failed", host_key)

    async def shutdown(self) -> None:
        pending_timers = list(self._timers.values())
        for timer in pending_timers:
            timer.cancel()
        for timer in pending_timers:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await timer
        pending_hosts = list(self._windows.keys())
        for host_key in pending_hosts:
            await self._close(host_key)
