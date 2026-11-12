"""Network helpers with an SSRF guard for connections to user-supplied hosts."""

from __future__ import annotations

import asyncio
import ipaddress
import socket

import httpx

from ..config import get_settings


class BlockedTarget(Exception):
    """Raised when a target resolves to a non-public address."""


async def resolve_host(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host.strip("[]"), None, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


async def ensure_public_host(host: str) -> list[str]:
    """Resolve a host and refuse it if any address is private, loopback, link-local or reserved."""
    addresses = await resolve_host(host)
    if get_settings().allow_private_targets:
        return addresses
    for addr in addresses:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
        if not ip.is_global or ip.is_multicast:
            raise BlockedTarget(f"{host} resolves to non-public address {addr}")
    return addresses


def http_client(*, verify: bool = True, timeout: float | None = None) -> httpx.AsyncClient:
    settings = get_settings()
    return httpx.AsyncClient(
        timeout=timeout or settings.http_timeout,
        verify=verify,
        follow_redirects=False,
        headers={"User-Agent": settings.user_agent, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
    )
