"""Autofill origin parsing and site matching (daemon/autofill.py).

The origin is the one thing the daemon takes from the browser, so these tests try to spoof it:
other schemes, userinfo, look-alike Unicode, IP literals, trailing dots, paths. Matching must
never cross a dot boundary, never climb to a public suffix, and never use names or inferred
aliases.
"""

import unittest

from icp.daemon import autofill
from icp.daemon.protocol import OpError
from icp.vstore import Meta


def meta(domain="github.com", sites=(), username="me", title="GitHub", nickname="",
         apple_title="", aliases=(), mdat=0.0, id="e1"):
    return Meta(id=id, title=title, domain=domain, sites=list(sites), username=username,
                nickname=nickname, has_totp=False, has_notes=False, mdat=mdat,
                history_count=0, apple_title=apple_title, aliases=list(aliases))


class ParseOriginTests(unittest.TestCase):
    def code(self, origin):
        with self.assertRaises(OpError) as cm:
            autofill.parse_origin(origin)
        return cm.exception.code

    def test_accepts_plain_https_origins(self):
        self.assertEqual(autofill.parse_origin("https://github.com"), "github.com")
        self.assertEqual(autofill.parse_origin("https://gist.github.com:8443"), "gist.github.com")
        self.assertEqual(autofill.parse_origin("HTTPS://GitHub.COM"), "github.com")
        self.assertEqual(autofill.parse_origin("https://xn--bcher-kva.de"), "xn--bcher-kva.de")
        self.assertEqual(autofill.parse_origin("https://a-b.c0.example"), "a-b.c0.example")

    def test_strips_one_www(self):
        self.assertEqual(autofill.parse_origin("https://www.github.com"), "github.com")
        self.assertEqual(autofill.parse_origin("https://www.www.github.com"), "www.github.com")
        # www.com is a real registrable name; stripping would leave a bare TLD.
        self.assertEqual(autofill.parse_origin("https://www.com"), "www.com")

    def test_other_schemes_are_insecure(self):
        for o in ("http://github.com", "ftp://github.com", "moz-extension://abc.def",
                  "chrome-extension://abcdefghijklmnop", "file://host.example",
                  "ws://github.com", "javascript://github.com"):
            self.assertEqual(self.code(o), "insecure-origin", o)

    def test_malformed_is_bad_origin(self):
        for o in ("", "github.com", "https:github.com", "https:/github.com", "https://",
                  "//github.com", " https://github.com", "https://github.com ",
                  "https://github.com/", "https://github.com/login", "https://github.com?x",
                  "https://github.com#x", "https://user@github.com",
                  "https://github.com@evil.com", "https://evil.com\\@github.com",
                  "https://github.com.", "https://.github.com", "https://github..com",
                  "https://localhost", "https://com", "https://github.com:",
                  "https://github.com:0", "https://github.com:65536", "https://github.com:+1",
                  "https://github.com:443:443", "https://-github.com", "https://github-.com",
                  "https://git_hub.com", "https://git hub.com", "https://github.com\n",
                  "https://github.com\x00.evil.com", "https://[::1]", "https://[::1]:443",
                  "https://127.0.0.1", "https://10.0.0.1:8443", "https://1.2", "1https://x.y",
                  "https://" + "a" * 64 + ".com", "https://" + "a." * 130 + "com",
                  "https://" + "a" * 3000 + ".com"):
            self.assertEqual(self.code(o), "bad-origin", repr(o))

    def test_non_ascii_is_refused_before_lowercasing(self):
        # U+212A KELVIN SIGN lowercases to ASCII "k"; U+0130 to "i" plus a combining dot.
        for o in ("https://Keep.com", "https://gıthub.com", "https://bücher.de",
                  "https://github.com​", "https://gіthub.com",       # Cyrillic і
                  "https∕∕github.com", "https://github。com"):
            self.assertEqual(self.code(o), "bad-origin", repr(o))

    def test_not_a_string(self):
        for o in (None, 1, ["https://github.com"], {"origin": "https://github.com"}, b"x"):
            self.assertEqual(self.code(o), "bad-origin", repr(o))


class MatchRankTests(unittest.TestCase):
    def test_exact_and_www(self):
        self.assertEqual(autofill.match_rank("github.com", meta("github.com")), 0)
        self.assertEqual(autofill.match_rank("github.com", meta("www.github.com")), 0)
        self.assertEqual(autofill.match_rank("github.com", meta("GitHub.com.")), 0)
        self.assertEqual(autofill.match_rank("github.com", meta("https://github.com/login")), 0)
        self.assertEqual(autofill.match_rank("github.com", meta("github.com:443")), 0)

    def test_sites_count_like_the_domain(self):
        m = meta("example.org", sites=["github.com"])
        self.assertEqual(autofill.match_rank("github.com", m), 0)
        self.assertEqual(autofill.match_rank("gist.github.com", m), 1)

    def test_sub_and_parent_domains_are_related(self):
        self.assertEqual(autofill.match_rank("login.github.com", meta("github.com")), 1)
        self.assertEqual(autofill.match_rank("github.com", meta("login.github.com")), 1)
        self.assertEqual(autofill.match_rank("a.b.github.com", meta("github.com")), 1)

    def test_dot_boundary(self):
        for page in ("notgithub.com", "github.com.evil.com", "evilgithub.com",
                     "github.co", "hub.com", "com"):
            self.assertIsNone(autofill.match_rank(page, meta("github.com")), page)

    def test_siblings_never_match(self):
        self.assertIsNone(autofill.match_rank("mail.google.com", meta("accounts.google.com")))
        self.assertIsNone(autofill.match_rank("evil.com.au", meta("bank.com.au")))

    def test_public_suffixes_are_never_the_shared_part(self):
        cases = [("evil.github.io", "github.io"), ("github.io", "me.github.io"),
                 ("evil.co.uk", "co.uk"), ("co.uk", "bank.co.uk"),
                 ("evil.blogspot.com", "blogspot.com"), ("x.pages.dev", "pages.dev"),
                 ("evil.herokuapp.com", "herokuapp.com")]
        for page, domain in cases:
            self.assertIsNone(autofill.match_rank(page, meta(domain)), (page, domain))
        # Below a suffix, the owner's own subdomains still relate.
        self.assertEqual(autofill.match_rank("login.bank.co.uk", meta("bank.co.uk")), 1)
        self.assertEqual(autofill.match_rank("x.me.github.io", meta("me.github.io")), 1)
        self.assertEqual(autofill.match_rank("me.github.io", meta("me.github.io")), 0)

    def test_guard_list_shape(self):
        for s in autofill.PUBLIC_SUFFIX_GUARD:
            self.assertEqual(s, s.lower())
            self.assertGreaterEqual(s.count("."), 1, s)
            self.assertIsNotNone(autofill._entry_host(s), s)

    def test_aliases_and_names_never_match(self):
        m = meta("example.org", aliases=["github.com"], title="GitHub", nickname="github.com",
                 apple_title="github.com")
        self.assertIsNone(autofill.match_rank("github.com", m))
        self.assertIsNone(autofill.match_rank("github.com", meta("", title="GitHub")))
        self.assertIsNone(autofill.match_rank("github.com", meta("GitHub", title="GitHub")))

    def test_non_hosts_never_match(self):
        for d in ("AirPort", "192.168.1.1", "", "  ", "com.apple.something", "localhost",
                  None):
            self.assertIsNone(autofill.match_rank("github.com", meta(d)), d)

    def test_unicode_entry_domain_matches_its_punycode(self):
        self.assertEqual(autofill.match_rank("xn--bcher-kva.de", meta("bücher.de")), 0)

    def test_internal_apple_records_are_never_offered(self):
        for kw in ({"username": "PCSBoundaryKey-123"}, {"username": "com.apple.foo"},
                   {"username": "_Apple123"}, {"title": "_AppleThing"},
                   {"username": "CHIPPlugin.x"}, {"title": "PCS com.apple.notes"},
                   {"title": "Website Metadata"}):
            self.assertIsNone(autofill.match_rank("github.com", meta(**kw)), kw)

    def test_page_host_is_revalidated(self):
        self.assertIsNone(autofill.match_rank("github.com/evil", meta()))
        self.assertIsNone(autofill.match_rank("10.0.0.1", meta("10.0.0.1")))


class LabelTests(unittest.TestCase):
    def test_label_prefers_nickname_then_titles_then_domain(self):
        self.assertEqual(autofill.account_label(meta(nickname="Work")), "Work — me")
        self.assertEqual(autofill.account_label(meta(apple_title="Hub")), "Hub — me")
        self.assertEqual(autofill.account_label(meta()), "GitHub — me")
        self.assertEqual(autofill.account_label(meta(title="")), "github.com — me")
        self.assertEqual(autofill.account_label(meta(username="")), "GitHub")
        self.assertEqual(autofill.account_label(meta(title="", domain="", username="u")), "u")


if __name__ == "__main__":
    unittest.main()
