import contextlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"

_spec = importlib.util.spec_from_file_location("nmap_parser", ROOT / "recon-parser-util.py")
np = importlib.util.module_from_spec(_spec)
sys.modules["nmap_parser"] = np
_spec.loader.exec_module(np)


def parse(*names, base_url=""):
    report = np.Report()
    for name in names:
        np.parse_input((EXAMPLES / name).read_text(), name, report, base_url=base_url)
    np.attach_web(report)
    return report


def run(argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = np.main(argv)
    return code, out.getvalue(), err.getvalue()


class DetectTests(unittest.TestCase):
    def test_detects_each_example(self):
        expected = {
            "nmap.txt": ["nmap"],
            "nmap.xml": ["nmap-xml"],
            "nmap.gnmap": ["nmap-grep"],
            "gobuster-dir.txt": ["gobuster"],
            "gobuster-vhost.txt": ["gobuster"],
        }
        for name, formats in expected.items():
            self.assertEqual(np.detect_formats((EXAMPLES / name).read_text()), formats, name)

    def test_unknown_input(self):
        self.assertEqual(np.detect_formats("hello world\n"), [])


class NmapTests(unittest.TestCase):
    def test_normal_output(self):
        report = parse("nmap.txt")
        self.assertEqual(report.warnings, [])
        self.assertEqual(set(report.hosts), {"10.10.10.5", "10.10.10.7"})
        box = report.hosts["10.10.10.5"]
        self.assertEqual(box.hostname, "box.htb")
        self.assertEqual(box.latency, "0.042s")
        ports = {(p.number, p.state) for p in box.ports}
        self.assertIn((3306, "filtered"), ports)
        ssh = next(p for p in box.ports if p.number == 22)
        self.assertTrue(ssh.version.startswith("OpenSSH 8.2p1"))
        self.assertEqual(ssh.scripts[0], "ssh-hostkey:")
        self.assertTrue(report.hosts["10.10.10.7"].scripts)

    def test_xml_and_grepable_agree_with_normal(self):
        def ports(report):
            return {(p.number, p.service) for p in report.hosts["10.10.10.5"].ports if p.state == "open"}

        xml, gnmap = parse("nmap.xml"), parse("nmap.gnmap")
        self.assertEqual(xml.warnings, [])
        self.assertEqual(gnmap.warnings, [])
        self.assertIn((8443, "ssl/http"), ports(xml))
        self.assertEqual(ports(gnmap), {(22, "ssh"), (80, "http")})
        self.assertEqual(xml.hosts["10.10.10.5"].os, "Linux 4.15 - 5.8")

    def test_reason_column_is_stripped(self):
        report = np.Report()
        np.parse_nmap_text("Nmap scan report for 10.0.0.1\nPORT STATE SERVICE REASON VERSION\n"
                           "22/tcp open ssh syn-ack ttl 63 OpenSSH 9.6\n", "t", report)
        self.assertEqual(report.hosts["10.0.0.1"].ports[0].version, "OpenSSH 9.6")

    def test_invalid_lines_are_reported(self):
        report = np.Report()
        np.parse_nmap_text("Nmap scan report for 10.0.0.1\n99999/tcp open x\n22/tcp opne ssh\n"
                           "Nmap done: 1 IP address (2 hosts up) scanned in 1.00 seconds\n", "t", report)
        self.assertEqual(report.hosts["10.0.0.1"].ports, [])
        joined = "\n".join(report.warnings)
        self.assertIn("out of range", joined)
        self.assertIn("unknown port state", joined)
        self.assertIn("truncated", joined)

    def test_truncated_xml(self):
        report = np.Report()
        text = (EXAMPLES / "nmap.xml").read_text()
        np.parse_nmap_xml(text[: len(text) // 2], "t", report)
        self.assertIn("invalid XML", report.warnings[0])


class GobusterTests(unittest.TestCase):
    def test_dir_results_attach_to_host(self):
        report = parse("nmap.txt", "gobuster-dir.txt")
        self.assertEqual(report.duplicates, 1)
        admin = next(w for w in report.web if w.url.endswith("/admin"))
        self.assertEqual((admin.status, admin.size, admin.redirect), (301, 308, "http://box.htb/admin/"))
        self.assertTrue(all(w.host == "10.10.10.5" for w in report.web))

    def test_vhost_results(self):
        report = parse("nmap.txt", "gobuster-vhost.txt")
        self.assertEqual([(w.kind, w.url, w.status) for w in report.web],
                         [("vhost", "dev.box.htb", 200), ("vhost", "staging.box.htb", 403)])
        self.assertTrue(all(w.host == "10.10.10.5" for w in report.web))

    def test_dns_and_colours(self):
        report = np.Report()
        np.parse_gobuster("[+] Domain: example.com\n\x1b[2KFound: www.example.com [93.184.216.34]\n"
                          "Progress: 1/2\r\x1b[2KFound: mail.example.com\n", "t", report)
        self.assertEqual([(w.kind, w.url, w.addresses) for w in report.web],
                         [("dns", "www.example.com", ["93.184.216.34"]), ("dns", "mail.example.com", [])])

    def test_base_url_and_validation(self):
        report = np.Report()
        np.parse_gobuster("/a (Status: 200) [Size: 1]\n/b (Status: 999)\n[ERROR] timeout\n", "t", report,
                          base_url="http://10.0.0.1:8080/")
        self.assertEqual([w.url for w in report.web], ["http://10.0.0.1:8080/a"])
        self.assertEqual(len(report.warnings), 2)


class CliTests(unittest.TestCase):
    def test_json_output(self):
        code, out, _ = run([str(EXAMPLES / "nmap.txt"), str(EXAMPLES / "gobuster-dir.txt"), "-f", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["summary"]["open_ports"], 5)
        self.assertEqual(len(data["hosts"][0]["web"]), 5)

    def test_filters(self):
        _, out, _ = run([str(EXAMPLES / "nmap.txt"), str(EXAMPLES / "gobuster-dir.txt"),
                         "-f", "json", "--state", "filtered", "--status", "2xx"])
        host = json.loads(out)["hosts"][0]
        self.assertEqual([p["number"] for p in host["ports"]], [3306])
        self.assertEqual([w["status"] for w in host["web"]], [200])

    def test_urls_output(self):
        _, out, _ = run([str(EXAMPLES / "nmap.xml"), "-f", "urls"])
        self.assertEqual(out.split(), ["http://box.htb", "https://box.htb:8443"])

    def test_strict_and_empty(self):
        bad = EXAMPLES.parent / "tests" / "_bad.txt"
        bad.write_text("Nmap scan report for 10.0.0.1\n22/tcp opne ssh\n")
        try:
            self.assertEqual(run([str(bad), "--strict", "-q"])[0], 3)
        finally:
            bad.unlink()
        self.assertEqual(run([str(EXAMPLES / "nmap.txt"), "--strict"])[0], 0)

    def test_bad_filter_rejected(self):
        with self.assertRaises(SystemExit):
            run([str(EXAMPLES / "nmap.txt"), "--status", "abc"])


if __name__ == "__main__":
    unittest.main()
