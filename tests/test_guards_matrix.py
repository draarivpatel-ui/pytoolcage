import unittest

from pytoolcage import classify_ip, guard_command, guard_path, guard_url, normalize_ip, parse_ipv4, parse_ipv6, split_command_words
from helpers import add_case


def codes(items):
    return [item["code"] for item in items]


class TestGuards(unittest.TestCase):
    pass


shell_payloads = [
    ("semicolon", "cat a; cat b", "SHELL_OPERATOR"), ("background", "sleep 1 &", "SHELL_OPERATOR"),
    ("and", "test a && test b", "SHELL_OPERATOR"), ("or", "test a || test b", "SHELL_OPERATOR"),
    ("pipe", "cat a | cat b", "SHELL_OPERATOR"), ("out", "cat a > out", "SHELL_OPERATOR"),
    ("append", "cat a >> out", "SHELL_OPERATOR"), ("input", "cat < in", "SHELL_OPERATOR"),
    ("adjacent", "cat a>out", "SHELL_OPERATOR"), ("stderr", "cat a 2>err", "SHELL_OPERATOR"),
    ("proc_in", "cat <(echo x)", "PROCESS_SUBSTITUTION"), ("proc_out", "cat >(echo x)", "PROCESS_SUBSTITUTION"),
    ("dollar_subst", "cat $(pwd)", "COMMAND_SUBSTITUTION"), ("backtick", "cat `pwd`", "COMMAND_SUBSTITUTION"),
    ("parameter", "cat ${HOME}", "COMMAND_SUBSTITUTION"), ("variable", "cat $HOME", "SHELL_EXPANSION"),
    ("glob_star", "cat *", "SHELL_OPERATOR"), ("glob_question", "cat ?.txt", "SHELL_OPERATOR"),
    ("glob_class", "cat [a-z].txt", "SHELL_OPERATOR"), ("newline", "cat a\ncat b", "CONTROL_CHARACTER"),
    ("carriage", "cat a\rcat b", "CONTROL_CHARACTER"), ("nul", "cat a\x00b", "CONTROL_CHARACTER"),
    ("single_quote", "cat 'abc", "UNBALANCED_QUOTE"), ("double_quote", 'cat "abc', "UNBALANCED_QUOTE"),
]
for name, command, code in shell_payloads:
    def check(self, command=command, code=code):
        self.assertIn(code, codes(guard_command(command, {"type": "command"})))
    add_case(TestGuards, "command_blocks_" + name, check)

for index, command in enumerate(["git status", "git diff --stat", "python3 script.py --input file.txt", "npm test", "echo hello world", "tool --flag=value", "tool \"two words\"", "tool 'two words'", "tool alpha beta gamma", "git log -5 --oneline"]):
    def check(self, command=command):
        self.assertEqual(guard_command(command, {"type": "command"}), [])
    add_case(TestGuards, "command_allows_%d" % index, check)

git_payloads = [
    "git -c core.sshCommand=evil status", "git -c core.sshcommand=evil status", "git -c user.name=x status",
    "git --config core.sshCommand=evil status", "git --config-env core.sshCommand=evil status",
    "git clone --upload-pack=evil repo", "git clone --upload-pack evil repo", "git --exec-path=/tmp/evil status",
    "git --git-dir=/tmp/repo/.git status", "git --work-tree=/tmp/repo status", "git --namespace=x status",
    "GIT_SSH_COMMAND=evil git clone repo", "GIT_SSH=evil git clone repo", "GIT_ASKPASS=evil git clone repo",
    "/usr/bin/git -c core.sshCommand=evil status", "git.exe -c core.sshCommand=evil status",
]
for index, command in enumerate(git_payloads):
    def check(self, command=command):
        self.assertTrue(any(code.startswith("GIT_") for code in codes(guard_command(command, {"type": "command"}))), command)
    add_case(TestGuards, "git_blocks_%d" % index, check)

for index, (command, expected) in enumerate([("tool a b", ["tool", "a", "b"]), ("tool \"a b\"", ["tool", "a b"]), ("tool 'a b'", ["tool", "a b"]), ("tool a\\ b", ["tool", "a b"]), ("tool \"\" empty", ["tool", "", "empty"])]):
    def check(self, command=command, expected=expected):
        self.assertEqual(split_command_words(command), expected)
    add_case(TestGuards, "tokenizes_%d" % index, check)

hostile_paths = [
    ("direct", "../secret", "PATH_TRAVERSAL"), ("middle", "safe/../secret", "PATH_TRAVERSAL"),
    ("encoded", "%2e%2e/secret", "PATH_TRAVERSAL"), ("encoded_slash", "..%2fsecret", "PATH_TRAVERSAL"),
    ("double_encoded", "%252e%252e/secret", "PATH_TRAVERSAL"), ("upper_encoded", "%2E%2E/secret", "PATH_TRAVERSAL"),
    ("backslash", "..\\secret", "PATH_TRAVERSAL"), ("absolute", "/etc/passwd", "ABSOLUTE_PATH"),
    ("unc", "//server/share", "ABSOLUTE_PATH"), ("drive", "C:\\Windows\\system32", "ABSOLUTE_PATH"),
    ("forward_drive", "C:/Windows/system32", "ABSOLUTE_PATH"), ("home", "~/secret", "HOME_EXPANSION"),
    ("nul", "safe\x00secret", "CONTROL_CHARACTER"), ("newline", "safe\nsecret", "CONTROL_CHARACTER"),
    ("encoded_newline", "safe%0asecret", "CONTROL_CHARACTER"), ("encoded_nul", "safe%00secret", "CONTROL_CHARACTER"),
    ("bidi", "safe%u202esecret", "PATH_OBFUSCATION"),
]
for name, value, code in hostile_paths:
    def check(self, value=value, code=code):
        self.assertIn(code, codes(guard_path(value, {"type": "path"})))
    add_case(TestGuards, "path_blocks_" + name, check)

for index, value in enumerate(["file.txt", "nested/file.txt", "./nested/file.txt", "nested/./file.txt", "a/b/c/d/e.txt", "name with spaces.txt", "unicode-\u00e9.txt", ".hidden", "nested/.hidden/file", "file..txt"]):
    def check(self, value=value):
        self.assertEqual(guard_path(value, {"type": "path"}), [])
    add_case(TestGuards, "path_allows_%d" % index, check)

hostile_urls = [
    ("file", "file:///etc/passwd", "UNSAFE_URL_SCHEME"), ("ftp", "ftp://example.com/a", "UNSAFE_URL_SCHEME"),
    ("gopher", "gopher://example.com/a", "UNSAFE_URL_SCHEME"), ("javascript", "javascript:alert(1)", "UNSAFE_URL_SCHEME"),
    ("data", "data:text/plain,x", "UNSAFE_URL_SCHEME"), ("relative", "//example.com/a", "SCHEME_RELATIVE_URL"),
    ("space", "https://example.com/a b", "URL_WHITESPACE"), ("newline", "https://example.com/a\nb", "CONTROL_CHARACTER"),
    ("backslash", "https:\\example.com\\a", "URL_BACKSLASH"), ("userinfo", "https://user:pass@example.com/", "URL_USERINFO"),
    ("localhost", "http://localhost/", "SSRF_LOCAL_HOSTNAME"), ("sub_localhost", "http://x.localhost/", "SSRF_LOCAL_HOSTNAME"),
    ("local", "http://printer.local/", "SSRF_LOCAL_HOSTNAME"), ("lan", "http://router.lan/", "SSRF_LOCAL_HOSTNAME"),
    ("internal", "http://service.internal/", "SSRF_LOCAL_HOSTNAME"), ("loopback", "http://127.0.0.1/", "SSRF_PRIVATE_NETWORK"),
    ("private10", "http://10.1.2.3/", "SSRF_PRIVATE_NETWORK"), ("private172", "http://172.16.0.1/", "SSRF_PRIVATE_NETWORK"),
    ("private192", "http://192.168.1.1/", "SSRF_PRIVATE_NETWORK"), ("linklocal", "http://169.254.1.1/", "SSRF_PRIVATE_NETWORK"),
    ("cgnat", "http://100.64.0.1/", "SSRF_PRIVATE_NETWORK"), ("decimal", "http://2130706433/", "SSRF_PRIVATE_NETWORK"),
    ("hex", "http://0x7f000001/", "SSRF_PRIVATE_NETWORK"), ("octal", "http://0177.0.0.1/", "SSRF_PRIVATE_NETWORK"),
    ("ipv6loop", "http://[::1]/", "SSRF_PRIVATE_NETWORK"), ("mapped", "http://[::ffff:127.0.0.1]/", "SSRF_PRIVATE_NETWORK"),
    ("ipv6link", "http://[fe80::1]/", "SSRF_PRIVATE_NETWORK"), ("ipv6ula", "http://[fd00::1]/", "SSRF_PRIVATE_NETWORK"),
    ("multicast", "http://224.0.0.1/", "SSRF_PRIVATE_NETWORK"), ("documentation", "http://192.0.2.1/", "SSRF_PRIVATE_NETWORK"),
    ("port0", "http://example.com:0/", "URL_PORT_BLOCKED"), ("port8080", "http://example.com:8080/", "URL_PORT_BLOCKED"),
]
for name, value, code in hostile_urls:
    def check(self, value=value, code=code):
        self.assertIn(code, codes(guard_url(value, {"type": "url"})))
    add_case(TestGuards, "url_blocks_" + name, check)

for index, value in enumerate(["https://example.com/", "http://example.com/a?x=1", "https://example.com:443/", "http://example.com:80/a", "https://sub.example.com/a%20b", "https://example.com/#fragment", "https://8.8.8.8/", "https://1.1.1.1/path", "https://example.co.uk/path", "https://xn--bcher-kva.example/"]):
    def check(self, value=value):
        self.assertEqual(guard_url(value, {"type": "url"}), [], value)
    add_case(TestGuards, "url_allows_%d" % index, check)

ipv4_cases = [("127.0.0.1", "127.0.0.1"), ("2130706433", "127.0.0.1"), ("0x7f000001", "127.0.0.1"), ("0177.0.0.1", "127.0.0.1"), ("127.1", "127.0.0.1"), ("192.168.1.1", "192.168.1.1"), ("8.8.8.8", "8.8.8.8")]
for value, expected in ipv4_cases:
    def check(self, value=value, expected=expected):
        self.assertEqual(parse_ipv4(value), expected)
    add_case(TestGuards, "ipv4_" + value.replace(".", "_").replace("x", "x"), check)

for index, value in enumerate(["999.1.1.1", "1.2.3.4.5", "x.1.1.1", "", "0xfffffffff"]):
    def check(self, value=value):
        self.assertIsNone(parse_ipv4(value))
    add_case(TestGuards, "ipv4_rejects_%d" % index, check)

for value, valid in [("::1", True), ("::ffff:127.0.0.1", True), ("2001:db8::1", True), ("fe80::1", True), ("1:2:3:4:5:6:7:8", True), ("1:2:3:4:5:6:7", False), ("1::2::3", False)]:
    def check(self, value=value, valid=valid):
        self.assertEqual(parse_ipv6(value) is not None, valid)
    add_case(TestGuards, "ipv6_" + value.replace(":", "_").replace(".", "_"), check)

for value, expected in [("127.0.0.1", "loopback"), ("10.0.0.1", "private"), ("172.16.0.1", "private"), ("192.168.0.1", "private"), ("169.254.0.1", "link-local"), ("100.64.0.1", "carrier-grade-nat"), ("224.0.0.1", "multicast"), ("8.8.8.8", "public"), ("::1", "loopback"), ("fe80::1", "link-local"), ("fd00::1", "private"), ("2001:db8::1", "documentation")]:
    def check(self, value=value, expected=expected):
        self.assertEqual(classify_ip(value), expected)
    add_case(TestGuards, "classify_" + value.replace(":", "_").replace(".", "_"), check)


class TestGuardSingles(unittest.TestCase):
    def test_shell_escape_hatch(self):
        self.assertNotIn("SHELL_OPERATOR", codes(guard_command("cat a | cat b", {"type": "command", "allowShellOperators": True})))

    def test_absolute_escape_hatch(self):
        self.assertEqual(guard_path("/tmp/file.txt", {"type": "path", "allowAbsolute": True}), [])

    def test_private_escape_hatch(self):
        self.assertEqual(guard_url("http://127.0.0.1/", {"type": "url", "allowPrivateNetworks": True}), [])

    def test_custom_port(self):
        self.assertEqual(guard_url("http://example.com:8080/", {"type": "url", "allowedPorts": [8080]}), [])

    def test_deny_beats_allow(self):
        result = guard_url("https://api.example.com/", {"type": "url", "hostPolicy": {"allow": ["example.com"], "deny": ["api.example.com"]}})
        self.assertIn("HOST_DENIED", codes(result))

    def test_normalize(self):
        self.assertEqual(normalize_ip("0177.0.0.1"), "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
