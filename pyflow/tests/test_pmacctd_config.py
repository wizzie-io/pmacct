'''Configuration files pyflow writes for pmacctd. Run from pyflow/: python3 -m unittest discover tests'''

import os, sys, tempfile, time, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wizzie.common import Configuration, ConfigError
from wizzie.pmacctd import PmacctdConfig
from wizzie.geoip import GeoipFile

BASE = {"HTTP_ENDPOINT": "http://192.168.102.9:8880", "API_KEY": "secret", "PCAP_INTERFACE": "eth0", "LOG_LEVEL": "ERROR"}


class PmacctdConfigTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def render(self, **env):
        conf = Configuration(dict(BASE, CONFIG_DIR=self.dir.name, **env))
        files = PmacctdConfig(conf).render()
        return {os.path.basename(path): content for path, content in files.items()}

    def lines(self, **env):
        return self.render(**env)["pmacctd.conf"].splitlines()

    def test_defaults(self):
        lines = self.lines()
        self.assertIn("pcap_interface: eth0", lines)
        self.assertIn("pcap_filter: not ((host 192.168.102.9) and tcp port 8880)", lines)
        self.assertIn("http_topic[wdp]: pmacct", lines)
        self.assertIn("http_event_type[wdp]: pmacct_flow", lines)
        self.assertIn("http_class_split[wdp]: true", lines)
        self.assertNotIn("pre_tag_map", "\n".join(lines))

    def test_empty_disables(self):
        lines = "\n".join(self.lines(EVENT_TYPE="", OVERRIDE_PREFIX="", HISTORY_ROUNDOFF=""))
        for key in ("http_event_type", "http_override_prefix", "http_history_roundoff"):
            self.assertNotIn(key, lines)
        self.assertIn("http_event_source[wdp]: pmacct", lines)

    def test_empty_takes_default(self):
        self.assertIn("http_topic[wdp]: pmacct", self.lines(EVENTS_TOPIC=""))

    def test_local_networks(self):
        files = self.render(LOCAL_NETWORKS="192.168.102.0/24, 10.0.0.0/8")
        pretag = files["pretag.map"].splitlines()
        self.assertEqual(pretag[2], "set_label=direction%local  filter='(src net 192.168.102.0/24 or src net 10.0.0.0/8) and "
                         "(dst net 192.168.102.0/24 or dst net 10.0.0.0/8 or dst net 224.0.0.0/4 or dst host 255.255.255.255 "
                         "or dst net ff00::/8)'")
        self.assertEqual(pretag[-1], "set_label=direction%in     filter='dst net 192.168.102.0/24 or dst net 10.0.0.0/8'")
        conf = files["pmacctd.conf"]
        self.assertIn(", label\n", conf)
        self.assertIn("http_label_flatten[wdp]: true", conf)
        self.assertNotIn("networks.lst", files)

    def test_net_fields(self):
        files = self.render(LOCAL_NETWORKS="10.0.0.0/8", NET_FIELDS="True", LOCAL_MULTICAST="False")
        self.assertEqual(files["networks.lst"].splitlines()[1:], ["10.0.0.0/8"])
        self.assertIn(", label, src_net, dst_net\n", files["pmacctd.conf"])

    def test_primitive_not_added_twice(self):
        conf = self.render(LOCAL_NETWORKS="10.0.0.0/8", AGGREGATE="src_host, label")["pmacctd.conf"]
        self.assertIn("aggregate[wdp]: src_host, label\n", conf)

    def test_several_interfaces(self):
        files = self.render(PCAP_INTERFACE="eth0, eth1")
        self.assertEqual(files["pcap_interfaces.map"], "ifindex=1 ifname=eth0\nifindex=2 ifname=eth1\n")
        self.assertIn("pcap_ifindex: map", files["pmacctd.conf"])

    def test_filter_and_exclusion(self):
        self.assertIn("pcap_filter: (not port 22) and not ((host fd00::1) and tcp port 443)",
                      self.lines(PCAP_FILTER="not port 22", HTTP_ENDPOINT="https://[fd00::1]/ingest"))
        self.assertIn("pcap_filter: not port 22", self.lines(PCAP_FILTER="not port 22", PCAP_EXCLUDE_ENDPOINT="False"))

    def test_unresolvable_endpoint_keeps_filter(self):
        self.assertIn("pcap_filter: not port 22", self.lines(PCAP_FILTER="not port 22", HTTP_ENDPOINT="http://no-such-host.invalid"))

    def test_api_key_not_logged(self):
        conf = Configuration(dict(BASE, CONFIG_DIR=self.dir.name, LOG_LEVEL="INFO"))
        with self.assertLogs(conf.logger, "INFO") as logs:
            PmacctdConfig(conf).write()
        self.assertNotIn("secret", "\n".join(logs.output))
        self.assertIn("http_apikey[wdp]: <API_KEY>", "\n".join(logs.output))

    def test_geoip(self):
        conf = self.render(GEOIPV2_FILE="/geoip/db.mmdb")["pmacctd.conf"]
        self.assertIn("geoipv2_file: /geoip/db.mmdb\n", conf)
        self.assertIn(", src_host_country, dst_host_country\n", conf)
        conf = self.render(GEOIPV2_FILE="/geoip/db.mmdb", GEOIP_FIELDS="country, coords")["pmacctd.conf"]
        self.assertIn(", src_host_country, dst_host_country, src_host_coords, dst_host_coords\n", conf)
        self.assertNotIn("country", self.render(GEOIPV2_FILE="/geoip/db.mmdb", GEOIP_FIELDS="")["pmacctd.conf"].replace("geoipv2", ""))
        self.assertNotIn("country", self.render()["pmacctd.conf"])
        with self.assertRaises(ConfigError):
            Configuration(dict(BASE, GEOIP_FIELDS="country, city"))
        conf = self.render(GEOIP_ASN_FILE="/geoip/asn.mmdb")["pmacctd.conf"]
        self.assertIn("http_geoip_asn_file[wdp]: /geoip/asn.mmdb\n", conf)
        self.assertNotIn("country", conf)

    def test_geoip_file_changes(self):
        path = os.path.join(self.dir.name, "db.mmdb")
        conf = Configuration(dict(BASE, GEOIPV2_FILE=path, GEOIPV2_WAIT="0", GEOIPV2_CHECK_SECONDS="1"))
        geoip = GeoipFile(conf)
        with self.assertLogs(conf.logger, "WARNING"):
            geoip.wait()  # not there: pmacctd starts without it
        self.assertFalse(geoip.changed())
        with open(path + ".tmp", "w") as f:
            f.write("v1")
        os.rename(path + ".tmp", path)  # as geoipupdate does
        geoip.next_check = 0
        self.assertTrue(geoip.changed())
        geoip.next_check = 0
        self.assertFalse(geoip.changed(), "the same version is reported once")
        with open(path + ".tmp", "w") as f:
            f.write("v2, longer")
        os.rename(path + ".tmp", path)
        self.assertFalse(geoip.changed(), "not checked again before GEOIPV2_CHECK_SECONDS")
        geoip.next_check = 0
        self.assertTrue(geoip.changed())

    def test_required(self):
        for var in ("HTTP_ENDPOINT", "API_KEY", "PCAP_INTERFACE"):
            with self.assertRaises(ConfigError):
                Configuration(dict(BASE, **{var: ""}))
        with self.assertRaises(ConfigError):
            Configuration(dict(BASE, SNAPLEN="big"))


if __name__ == "__main__":
    unittest.main()
