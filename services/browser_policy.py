"""Exact web origin policy for the chain facade. Core authentication stays private."""
import re
from urllib.parse import urlsplit


def authority(value):
    if not isinstance(value, str) or len(value) > 260:
        return False
    parts = value.split(":")
    if len(parts) > 2:
        return False
    host = parts[0]
    if not host or len(host) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        return False
    return len(parts) == 1 or (re.fullmatch(r"[1-9][0-9]{0,4}", parts[1]) is not None
                               and int(parts[1]) <= 65535)


def origin(value):
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    if not authority(parsed.netloc) or value != f"{parsed.scheme}://{parsed.netloc}":
        return False
    if parsed.scheme == "https":
        return not parsed.netloc.endswith(":443")
    return (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")
            and not parsed.netloc.endswith(":80"))


class BrowserPolicy:
    def __init__(self, origins=(), hosts=()):
        if (len(origins) > 32 or len(set(origins)) != len(origins)
                or not all(origin(value) for value in origins)):
            raise ValueError("invalid browser origins")
        if (len(hosts) > 16 or len(set(hosts)) != len(hosts)
                or not all(authority(value) for value in hosts) or (origins and not hosts)):
            raise ValueError("invalid browser hosts")
        self.origins, self.hosts = frozenset(origins), frozenset(hosts)

    def allows(self, headers):
        origins, hosts = headers.get_all("Origin", []), headers.get_all("Host", [])
        return (len(origins) == len(hosts) == 1 and origins[0] in self.origins
                and hosts[0] in self.hosts)
