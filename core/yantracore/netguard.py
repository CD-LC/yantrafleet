"""Outbound-URL guard (SSRF defence) shared by every component that calls a
URL somebody other than the process owner can influence.

THE THREAT
----------
Several outbound targets are not fixed at deploy time: ``WEBHOOK_URL`` and the
Twilio credentials live in ``public.app_settings`` and ``CONNECTOR_MQTT_HOST``
in ``public.app_config``; both tables are editable by a console ``admin``. A
compromised or malicious admin account (or an XSS in the console) could
otherwise make the *server* issue a request to places the admin cannot reach
directly: the cloud metadata service (``169.254.169.254`` -- instance
credentials), loopback services (the sandbox door, the copilot, a database
admin port) or the VPC. That is server-side request forgery.

WHAT THIS DOES
--------------
* Only ``https`` (and ``http`` when the caller allows it) URLs with a host and
  no embedded ``user:pass@`` credentials.
* The host is **resolved** and *every* address it resolves to must be
  acceptable, so numeric tricks (``2130706433``, ``0x7f.1``, ``[::ffff:127.0.0.1]``)
  and DNS names that point at internal addresses are caught by what they
  resolve to, not by how they are spelled. Fail closed: a name that does not
  resolve is rejected.
* Never allowed, whatever the operator configures: link-local (which contains
  the metadata endpoints), the unspecified address, multicast, reserved
  ranges, and the IPv6/Alibaba metadata addresses.
* Private ranges (RFC 1918, loopback, ULA, CGNAT) are refused by default and
  allowed only when the operator opts in -- a self-hosted Mattermost on the
  LAN is a legitimate webhook target, an unreviewed admin edit is not. Opt in
  per host with ``YANTRA_OUTBOUND_ALLOW_HOSTS=chat.corp.lan,...`` or for the
  whole process with ``YANTRA_OUTBOUND_ALLOW_PRIVATE=1``.

KNOWN LIMIT (stated, not hidden)
--------------------------------
The check resolves the name, then the HTTP client resolves it again to
connect. A hostile DNS server can answer differently the second time (DNS
rebinding). The check shrinks the window to a single lookup race and, with
redirects disabled, removes the redirect route entirely; closing it fully
needs connecting to the vetted IP, which ``httpx`` does not expose publicly.
For a high-assurance deployment also deny the metadata address at the network
layer (IMDSv2 with hop limit 1, or an egress firewall) -- defence in depth.

Pure standard library; the resolver is injectable so tests stay offline.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from typing import Callable, Iterable
from urllib.parse import urlsplit

ENV_ALLOW_PRIVATE = "YANTRA_OUTBOUND_ALLOW_PRIVATE"
ENV_ALLOW_HOSTS = "YANTRA_OUTBOUND_ALLOW_HOSTS"

#: Addresses that are never acceptable, even with the private opt-in. Most are
#: already caught by ``is_link_local``; they are listed so the intent survives
#: a change in how Python classifies a range.
_ALWAYS_BLOCKED = tuple(ipaddress.ip_network(n) for n in (
    "169.254.0.0/16",       # IPv4 link-local: AWS/GCP/Azure/OpenStack metadata
    "fe80::/10",            # IPv6 link-local
    "fd00:ec2::/32",        # AWS IPv6 metadata (fd00:ec2::254)
    "100.100.100.200/32",   # Alibaba Cloud metadata
    "192.0.0.192/32",       # Oracle Cloud metadata
    "0.0.0.0/8",
    "224.0.0.0/4",
    "240.0.0.0/4",
))

Resolver = Callable[[str, int], Iterable[str]]


class UnsafeURL(ValueError):
    """The URL (or host) is not an acceptable outbound target."""


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def _default_resolve(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def _host_allowed(host: str, allow_hosts: Iterable[str] | None) -> bool:
    if allow_hosts is None:
        allow_hosts = [h for h in os.environ.get(ENV_ALLOW_HOSTS, "").split(",")]
    wanted = {h.strip().lower().rstrip(".") for h in allow_hosts if h.strip()}
    return host.lower().rstrip(".") in wanted


def _classify(raw: str, allow_private: bool) -> str | None:
    """Return a reason the address is unacceptable, or None if it is fine."""
    try:
        ip = ipaddress.ip_address(raw.split("%", 1)[0])  # drop IPv6 zone id
    except ValueError:
        return f"{raw!r} is not an IP address"
    # ::ffff:a.b.c.d and the 6to4 / NAT64 wrappers hide an IPv4 address.
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None:
            ip = ip.sixtofour
    if any(ip in net for net in _ALWAYS_BLOCKED) or ip.is_unspecified \
            or ip.is_multicast or ip.is_link_local:
        return f"{ip} is a link-local / metadata / reserved address"
    if ip.is_global:
        return None
    if allow_private:
        return None
    return f"{ip} is a private or loopback address (set {ENV_ALLOW_HOSTS} or " \
           f"{ENV_ALLOW_PRIVATE}=1 to allow it)"


def check_host(host: str, port: int = 443, *, allow_private: bool | None = None,
               allow_hosts: Iterable[str] | None = None,
               resolver: Resolver | None = None,
               require_resolution: bool = True) -> None:
    """Raise :class:`UnsafeURL` unless every address ``host`` resolves to is OK.

    ``require_resolution=False`` lets an unresolvable name through (nothing
    can connect to it either); use it where no request is made on the caller's
    behalf until the name resolves, e.g. an MQTT reconnect.
    """
    if not host:
        raise UnsafeURL("no host")
    if allow_private is None:
        allow_private = _truthy(os.environ.get(ENV_ALLOW_PRIVATE))
    if not allow_private and _host_allowed(host, allow_hosts):
        allow_private = True
    try:
        addrs = list((resolver or _default_resolve)(host.strip("[]"), port))
    except (OSError, UnicodeError) as exc:
        if not require_resolution:
            return
        raise UnsafeURL(f"cannot resolve {host!r}: {exc}") from exc
    if not addrs:
        if not require_resolution:
            return
        raise UnsafeURL(f"{host!r} resolved to nothing")
    for addr in addrs:
        reason = _classify(addr, allow_private)
        if reason:
            raise UnsafeURL(f"{host!r} -> {reason}")


def check_outbound_url(url: str, *, schemes: Iterable[str] = ("https", "http"),
                       allow_private: bool | None = None,
                       allow_hosts: Iterable[str] | None = None,
                       resolver: Resolver | None = None) -> str:
    """Validate ``url`` as an outbound HTTP target; return it unchanged.

    Plain ``http`` is accepted only for a host the operator has opted in as
    internal (``YANTRA_OUTBOUND_ALLOW_HOSTS`` / ``YANTRA_OUTBOUND_ALLOW_PRIVATE``):
    a public endpoint over cleartext would leak the payload and invite a
    downgrade, a LAN one is the operator's call.
    """
    if not isinstance(url, str) or not url.strip():
        raise UnsafeURL("empty URL")
    if any(ch in url for ch in "\r\n\t\x00") or url != url.strip():
        raise UnsafeURL("control characters or whitespace in URL")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UnsafeURL(f"malformed URL: {exc}") from exc
    if parts.scheme.lower() not in {s.lower() for s in schemes}:
        raise UnsafeURL(f"scheme {parts.scheme!r} not allowed "
                        f"(allowed: {', '.join(schemes)})")
    if parts.username is not None or parts.password is not None:
        raise UnsafeURL("credentials in URL are not allowed")
    host = parts.hostname
    if not host:
        raise UnsafeURL("URL has no host")
    scheme = parts.scheme.lower()
    if allow_private is None:
        allow_private = _truthy(os.environ.get(ENV_ALLOW_PRIVATE))
    if scheme == "http" and not (allow_private or _host_allowed(host, allow_hosts)):
        raise UnsafeURL("plain http is only allowed to hosts the operator has "
                        f"opted in ({ENV_ALLOW_HOSTS} / {ENV_ALLOW_PRIVATE})")
    check_host(host, port or (443 if scheme == "https" else 80),
               allow_private=allow_private, allow_hosts=allow_hosts,
               resolver=resolver)
    return url
