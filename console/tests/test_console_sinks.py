"""Sink guard (YFSafe): every innerHTML assignment is sanitised, whatever built
the string. These tests bypass the read-path sanitiser on purpose -- they hand
the sink hostile markup directly, the situation where an escape was missed.

A payload that executes sets ``window.__pwn``; the assertions check both that
it stayed unset and that the dangerous construct is gone from the DOM, and that
the markup the app really uses survives (so the guard is not "safe" by
deleting everything).
"""
from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")
pytest.importorskip("pytest_playwright")

from playwright.sync_api import Page  # noqa: E402


@pytest.fixture()
def con(page: Page, console_server: str) -> Page:
    page.route("**/*", lambda r: r.continue_() if r.request.url.startswith(
        console_server) else r.abort())
    page.goto(f"{console_server}/index.html#demo")
    page.wait_for_function("typeof YFSafe !== 'undefined'")
    return page


def render(page: Page, html: str, tag: str = "div") -> str:
    """Assign ``html`` to a fresh element's innerHTML; return what it became."""
    return page.evaluate(
        """([html, tag]) => {
            const el = document.createElement(tag);
            document.body.appendChild(el);
            el.innerHTML = html;
            return el.innerHTML;
        }""", [html, tag])


def pwned(page: Page) -> bool:
    page.wait_for_timeout(150)
    return bool(page.evaluate("window.__pwn === 1"))


@pytest.mark.parametrize("payload", [
    '<img src=x onerror="window.__pwn=1">',
    '<img src=x onerror=window.__pwn=1>',
    '<svg onload="window.__pwn=1"></svg>',
    '<svg><script>window.__pwn=1</script></svg>',
    '<script>window.__pwn=1</script>',
    '<iframe srcdoc="<script>parent.__pwn=1</script>"></iframe>',
    '<iframe src="javascript:parent.__pwn=1"></iframe>',
    '<object data="javascript:window.__pwn=1"></object>',
    '<embed src="javascript:window.__pwn=1">',
    '<body onload="window.__pwn=1">',
    '<input autofocus onfocus="window.__pwn=1">',
    '<details open ontoggle="window.__pwn=1">',
    '<video><source onerror="window.__pwn=1"></video>',
    '<button onclick="window.__pwn=1" id=b>x</button><script>b.click()</script>',
    '<math><mtext><table><mglyph><style><img src=x onerror="window.__pwn=1">',
    '<noscript><p title="</noscript><img src=x onerror=window.__pwn=1>">',
    '<svg><animate attributeName="onclick" to="window.__pwn=1"/></svg>',
    '<base href="//evil.example/"><meta http-equiv="refresh" content="0;//evil.example">',
])
def test_hostile_markup_never_executes_or_survives(con: Page, payload: str):
    out = render(con, payload)
    low = out.lower()
    for bad in ("<script", "<iframe", "<object", "<embed", "<base", "<meta",
                "onerror", "onload", "onfocus", "ontoggle", "<style", "<math"):
        assert bad not in low, (bad, out)
    assert not pwned(con)


@pytest.mark.parametrize("handler", [
    "alert(1)", "fetch('//evil.example')", "window.__pwn=1", "eval('1')",
    "openRobot('a');alert(1)", "openRobot(alert(1))", "openRobot('a'+alert(1))",
    "openRobot(`x`)", "openRobot('x')//", "document.location='//evil.example'",
    "Function('1')()", "constructor.constructor('1')()", "setTimeout('1')",
    "location='javascript:1'", "openRobot('<x>')",
])
def test_event_handlers_outside_the_apps_own_calls_are_dropped(con: Page, handler: str):
    out = render(con, f'<button onclick="{handler}">x</button>')
    assert "onclick" not in out, out


@pytest.mark.parametrize("handler", [
    "openRobot('AMR-07')", "openIncident('INC-1042')", "go('liveops')",
    "Workspace.tab('keys');return false", "Copilot.toggle()",
    "cmdRobot('AMR-01','stop')", "replaySeek(42.5)",
])
def test_the_apps_own_handlers_survive(con: Page, handler: str):
    out = render(con, f'<button onclick="{handler}">x</button>')
    assert "onclick" in out, out


def test_static_handler_with_inline_logic_survives(con: Page):
    out = render(con, "<input onkeydown=\"if(event.key==='Enter')Copilot.ask(this.value)\">")
    assert "onkeydown" in out


@pytest.mark.parametrize("url", [
    "javascript:window.__pwn=1", "JaVaScRiPt:window.__pwn=1",
    "java\tscript:window.__pwn=1", "java\nscript:window.__pwn=1",
    " javascript:window.__pwn=1", "\x01javascript:window.__pwn=1",
    "data:text/html,<script>parent.__pwn=1</script>", "vbscript:x",
    "data:image/svg+xml;base64,PHN2Zz48c2NyaXB0Pg==",
])
def test_dangerous_urls_are_dropped(con: Page, url: str):
    for attr in ("href", "src"):
        out = render(con, f'<a {attr}="{url}">x</a><img {attr}="{url}">')
        assert "javascript" not in out.lower().replace("\t", "").replace("\n", ""), out
        assert f'{attr}=' not in out, out
    assert not pwned(con)


def test_ordinary_urls_survive_and_blank_targets_get_noopener(con: Page):
    out = render(con, '<a href="https://example.com/x" target="_blank">a</a>'
                      '<a href="#frag">b</a><a href="/rel">c</a><a href="mailto:a@b.c">d</a>'
                      '<img src="data:image/png;base64,iVBORw0KGgo=">')
    for keep in ('href="https://example.com/x"', 'href="#frag"', 'href="/rel"',
                 'href="mailto:a@b.c"', 'src="data:image/png;base64,iVBORw0KGgo="'):
        assert keep in out, (keep, out)
    assert "noopener" in out


def test_svg_context_keeps_namespace(con: Page):
    kind = con.evaluate("""() => {
        const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        document.body.appendChild(s);
        s.innerHTML = '<g><circle r="5"/><text x="1">t</text></g>';
        return [s.firstChild.namespaceURI, s.querySelector('circle').namespaceURI,
                s.querySelector('circle') instanceof SVGElement];
    }""")
    assert kind == ["http://www.w3.org/2000/svg"] * 2 + [True]


def test_svg_animation_the_map_uses_survives(con: Page):
    out = con.evaluate("""() => {
        const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        document.body.appendChild(s);
        s.innerHTML = '<circle r="17"><animate attributeName="r" values="12;22" dur="1s"/></circle>';
        return s.innerHTML;
    }""")
    assert "<animate" in out


def test_table_contexts_parse_correctly(con: Page):
    out = con.evaluate("""() => {
        const t = document.createElement('table'); document.body.appendChild(t);
        const b = document.createElement('tbody'); t.appendChild(b);
        b.innerHTML = '<tr><td>1</td><td>2</td></tr><tr><td>3</td></tr>';
        const r = document.createElement('tr'); b.appendChild(r);
        r.innerHTML = '<td>x</td><td>y</td>';
        const sel = document.createElement('select'); document.body.appendChild(sel);
        sel.innerHTML = '<option value="a">A</option><option value="b">B</option>';
        return [b.querySelectorAll('tr').length, r.children.length, sel.options.length];
    }""")
    assert out == [3, 2, 2]


def test_empty_and_text_only_assignments_work(con: Page):
    assert render(con, "") == ""
    assert render(con, "plain &amp; text") == "plain &amp; text"
    got = con.evaluate("""() => { const t = document.createElement('textarea');
        t.innerHTML = 'a<b'; return t.value; }""")
    assert got == "a<b"


def test_the_guard_covers_a_real_render_path_end_to_end(con: Page):
    # Drive the app's own toast + a modal with hostile text through real code.
    con.evaluate("""() => Modal.show('<img src=x onerror="window.__pwn=1">'
                                   + '<button onclick="alert(1)">x</button>')""")
    html = con.evaluate("document.querySelector('#modal .box').innerHTML")
    assert "onerror" not in html and "onclick" not in html
    assert not pwned(con)


def test_guard_denies_dangerous_heads_even_if_the_source_mentions_them(con: Page):
    heads = con.evaluate("Array.from(YFSafe.heads)")
    for never in ("alert", "fetch", "eval", "window", "document", "setTimeout",
                  "open", "localStorage"):
        assert not any(h == never or h.startswith(never + ".") for h in heads), never
    assert "openRobot" in heads
