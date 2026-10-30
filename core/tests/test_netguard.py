"""SSRF guard: offline (injected resolver), every bypass class covered."""
import pytest

from yantracore.netguard import UnsafeURL, check_host, check_outbound_url


def res(*addrs):
    return lambda host, port: list(addrs)


PUBLIC = res("93.184.216.34")


def ok(url, **kw):
    kw.setdefault("resolver", PUBLIC)
    return check_outbound_url(url, **kw)


def bad(url, **kw):
    kw.setdefault("resolver", PUBLIC)
    with pytest.raises(UnsafeURL):
        check_outbound_url(url, **kw)


def test_public_https_is_allowed():
    assert ok("https://hooks.slack.com/services/T/B/X")


@pytest.mark.parametrize("url", [
    "http://hooks.example.com/x",          # cleartext to a public host
    "ftp://example.com/x", "file:///etc/passwd", "gopher://example.com/",
    "javascript:alert(1)", "//example.com/x", "example.com/x", "",
    "https://user:pw@example.com/x", "https://user@example.com/x",
    "https:///nohost", "https://example.com:99999/x",
    "https://example.com/x\r\nHost: evil", " https://example.com/x",
])
def test_bad_shapes_refused(url):
    bad(url)


def test_plain_http_to_a_public_host_is_refused():
    bad("http://hooks.example.com/x")
    assert ok("http://hooks.example.com/x", schemes=("https", "http"),
              allow_hosts=["hooks.example.com"])


def test_plain_http_allowed_to_opted_in_lan_host():
    ok("http://chat.corp.lan:8065/hook", resolver=res("10.0.0.7"),
       allow_hosts=["chat.corp.lan"])
    ok("http://10.0.0.7/hook", resolver=res("10.0.0.7"), allow_private=True)


@pytest.mark.parametrize("addr", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1",
    "169.254.169.254", "169.254.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1",
    "::1", "fe80::1", "fc00::1", "fd00:ec2::254", "100.100.100.200",
    "192.0.0.192", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::",
    "2002:7f00:0001::",                     # 6to4 wrapper around 127.0.0.1
    "fe80::1%eth0",
])
def test_internal_addresses_refused_by_default(addr):
    bad("https://webhook.example.com/x", resolver=res(addr))


def test_any_bad_answer_in_a_multi_record_reply_refuses():
    bad("https://x.example.com/", resolver=res("93.184.216.34", "10.0.0.5"))


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/latest/",
    "https://[::ffff:7f00:1]/",
])
def test_ip_literal_urls_refused(url):
    # the resolver returns the literal itself, as getaddrinfo does
    import ipaddress
    bad(url, resolver=lambda h, p: [str(ipaddress.ip_address(h))])


@pytest.mark.parametrize("addr", ["169.254.169.254", "fd00:ec2::254", "0.0.0.0",
                                  "::ffff:169.254.169.254"])
def test_metadata_never_allowed_even_with_private_opt_in(addr):
    bad("https://x.example.com/", resolver=res(addr), allow_private=True)


def test_private_opt_in_allows_lan_but_not_metadata():
    ok("https://chat.corp.lan/hook", resolver=res("10.0.0.7"), allow_private=True)
    ok("https://chat.corp.lan/hook", resolver=res("::1"), allow_private=True)


def test_per_host_allowlist_exempts_only_that_host():
    ok("https://chat.corp.lan/x", resolver=res("10.0.0.7"),
       allow_hosts=["chat.corp.lan"])
    bad("https://other.corp.lan/x", resolver=res("10.0.0.7"),
        allow_hosts=["chat.corp.lan"])


def test_env_opt_ins(monkeypatch):
    monkeypatch.setenv("YANTRA_OUTBOUND_ALLOW_PRIVATE", "1")
    ok("https://chat.corp.lan/x", resolver=res("10.0.0.7"))
    monkeypatch.delenv("YANTRA_OUTBOUND_ALLOW_PRIVATE")
    bad("https://chat.corp.lan/x", resolver=res("10.0.0.7"))
    monkeypatch.setenv("YANTRA_OUTBOUND_ALLOW_HOSTS", "a.lan, chat.corp.lan")
    ok("https://chat.corp.lan/x", resolver=res("10.0.0.7"))


def test_unresolvable_name_fails_closed():
    def boom(host, port):
        raise OSError("nxdomain")
    bad("https://nope.example.com/", resolver=boom)
    bad("https://nope.example.com/", resolver=res())


def test_check_host_can_tolerate_unresolvable_for_mqtt():
    def boom(host, port):
        raise OSError("nxdomain")
    check_host("broker.lan", 1883, allow_private=True, resolver=boom,
               require_resolution=False)
    with pytest.raises(UnsafeURL):
        check_host("169.254.169.254", 1883, allow_private=True,
                   resolver=res("169.254.169.254"), require_resolution=False)
