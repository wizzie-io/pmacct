'''Session with Insight as its flow_manager: what pmacctd's output tells, the Hello, the status and our
own gRPC traffic out of the capture. Without grpc: run from pyflow/: python3 -m unittest discover tests'''

import os, sys, tempfile, threading, time, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wizzie.common import Configuration
from wizzie.insight import hello_values, status_values
from wizzie.pmacctd import PmacctdConfig
from wizzie.status import PmacctdLog

BASE = {"HTTP_ENDPOINT": "http://192.168.102.9:8880", "API_KEY": "secret", "PCAP_INTERFACE": "eth0", "LOG_LEVEL": "ERROR"}
INSIGHT = {"GRPC_HOST": "192.168.102.20", "GRPC_PORT": "50051", "GRPC_DEVICE_ID": "137dba7f-1629-4c08-a9b3-bd81a951f16f"}


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class PmacctdLogTest(unittest.TestCase):

    def setUp(self):
        self.clock = Clock()
        self.log = PmacctdLog(self.clock)

    def test_purges(self):
        self.log.feed("INFO ( wdp/http ): *** Purging cache - END (PID: 10, QN: 846/880, ET: 1) ***\n")
        self.clock.now = 1060
        self.log.feed("INFO ( wdp/http ): *** Purging cache - END (PID: 11, QN: 931/937, ET: 0) ***\n")

        snapshot = self.log.snapshot()
        self.assertEqual((snapshot["purges"], snapshot["messages_sent"]), (2, 1777))
        self.assertEqual(snapshot["last_purge"], {"time": 1060, "sent": 931, "total": 937})
        self.assertIsNone(snapshot["last_error"])

    def purge(self, sent, at):
        self.clock.now = at
        self.log.feed(f"INFO ( wdp/http ): *** Purging cache - END (PID: 1, QN: {sent}/{sent}, ET: 0) ***")

    def test_no_rate_until_the_second_purge(self):
        self.purge(600, 1000)

        self.assertIsNone(self.log.snapshot()["messages_per_second"])

        self.purge(1200, 1060)
        self.assertEqual(self.log.snapshot()["messages_per_second"], 20)

    def test_the_rate_weighs_the_last_purges_most(self):
        self.purge(1200, 1000)
        self.purge(1200, 1060)  # 20/s
        self.purge(2400, 1120)  # 40/s: one minute of a 5 minute half-life moves it ~13 % of the way

        self.assertAlmostEqual(self.log.snapshot()["messages_per_second"], 20 + 20 * (1 - 2 ** (-60 / 300)), places=6)

    def test_the_rate_is_weighted_by_time(self):
        self.purge(1200, 1000)
        self.purge(1200, 1060)  # 20/s
        self.purge(12000, 1360)  # 40/s after five minutes: half the way

        self.assertAlmostEqual(self.log.snapshot()["messages_per_second"], 30)

    def test_dropped_batches_and_errors(self):
        self.log.feed("WARN ( wdp/http ): HTTP POST http://192.168.102.9:8880/v1/data/flows_index returned 401 (attempt 1/3)")
        self.log.feed("ERROR ( wdp/http ): HTTP POST http://192.168.102.9:8880/v1/data/flows_index failed, "
                      "dropping 163 msgs (130719 bytes)")

        snapshot = self.log.snapshot()
        self.assertEqual(snapshot["messages_dropped"], 163)
        self.assertEqual(snapshot["last_error"], {
            "time": 1000, "message": "HTTP POST http://192.168.102.9:8880/v1/data/flows_index failed, "
                                     "dropping 163 msgs (130719 bytes)"})

    def test_interface_counters_of_sigusr1(self):
        threading.Timer(0.1, self.log.feed, args=(
            "NOTICE ( default/core ): stats [enx00e04c5a5480,0] time=1795091160 received_packets=1000 dropped_packets=3",)).start()

        stats = self.log.wait_interfaces(["enx00e04c5a5480"], since=1000, timeout=2)

        self.assertEqual(stats["enx00e04c5a5480"]["received_packets"], 1000)
        self.assertEqual(stats["enx00e04c5a5480"]["dropped_packets"], 3)

    def test_counters_written_before_the_request_do_not_count(self):
        self.log.feed("NOTICE ( default/core ): stats [eth0,0] time=1 received_packets=5 dropped_packets=0")
        self.clock.now = 2000

        self.assertEqual(self.log.wait_interfaces(["eth0"], since=1500, timeout=0), {})


class FakePmacctd:
    def __init__(self, running=True):
        self._running = running
        self.log = PmacctdLog(Clock(1795091160))
        self.asked = None

    def running(self):
        return self._running

    def uptime(self):
        return 3590 if self._running else 0

    def interface_stats(self, names, timeout):
        self.asked = names
        return {"eth0": {"received_packets": 1000, "dropped_packets": 3, "time": 0}}


class InsightTest(unittest.TestCase):

    def conf(self, **env):
        return Configuration(dict(BASE, **env))

    def test_the_session_needs_host_device_and_key(self):
        self.assertFalse(self.conf().insight_enabled())
        self.assertTrue(self.conf(**INSIGHT).insight_enabled())
        self.assertFalse(self.conf(**dict(INSIGHT, GRPC_DEVICE_ID="")).insight_enabled())

    def test_hello(self):
        conf = self.conf(**INSIGHT, GRPC_INSTANCE_ID="lab", PCAP_INTERFACE="eth0, eth1", LOCAL_NETWORKS="192.168.102.0/24")
        conf.local_geo_sources = ["country ES (ipinfo.io)"]

        values = hello_values(conf, {"country": "ES", "asn": "3352", "coords": "37.3865,-6.0773"})

        self.assertEqual(values, {
            "flow_manager_device_id": INSIGHT["GRPC_DEVICE_ID"], "instance_id": "lab", "version": "unknown",
            "interfaces": ["eth0", "eth1"], "local_networks": ["192.168.102.0/24"],
            "site": {"country": "ES", "asn": "3352", "coordinates": {"latitude": 37.3865, "longitude": -6.0773},
                     "sources": ["country ES (ipinfo.io)"]},
        })

    def test_hello_without_site(self):
        self.assertNotIn("site", hello_values(self.conf(**INSIGHT), {}))

    def test_status(self):
        conf = self.conf(**INSIGHT)
        pmacctd = FakePmacctd()
        pmacctd.log.feed("INFO ( wdp/http ): *** Purging cache - END (PID: 11, QN: 931/937, ET: 0) ***")

        values = status_values(conf, pmacctd, started_at=time.time() - 3600)

        self.assertEqual(pmacctd.asked, ["eth0"])
        self.assertAlmostEqual(values.pop("uptime_seconds"), 3600, delta=1)
        self.assertEqual(values, {
            "version": "unknown", "pmacctd_running": True, "pmacctd_uptime_seconds": 3590,
            "interfaces": [{"name": "eth0", "received_packets": 1000, "dropped_packets": 3}],
            "purges": 1, "messages_sent": 931, "messages_dropped": 0, "messages_per_second": 0.0,
            "last_purge": {"time": 1795091160, "sent": 931, "total": 937},
            "geoip": {"city": False, "asn": False, "updated": 0},
        })

    def test_status_with_the_geoip_database(self):
        with tempfile.NamedTemporaryFile() as city:
            os.utime(city.name, (1795000000, 1795000000))
            values = status_values(self.conf(**INSIGHT, GEOIPV2_FILE=city.name), FakePmacctd(running=False), time.time())

        self.assertEqual(values["geoip"], {"city": True, "asn": False, "updated": 1795000000})
        self.assertEqual((values["pmacctd_running"], values["interfaces"]), (False, []))


class ExcludeInsightTrafficTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def pcap_filter(self, **env):
        conf = Configuration(dict(BASE, CONFIG_DIR=self.dir.name, LOCAL_NETWORKS="", **env))
        lines = PmacctdConfig(conf, local_geo={}).render()[os.path.join(self.dir.name, "pmacctd.conf")].splitlines()
        return next(line for line in lines if line.startswith("pcap_filter:"))

    def test_the_grpc_traffic_is_left_out_too(self):
        self.assertEqual(self.pcap_filter(**INSIGHT), "pcap_filter: not ((host 192.168.102.9) and tcp port 8880) "
                                                      "and not ((host 192.168.102.20) and tcp port 50051)")

    def test_without_session_only_the_http_endpoint(self):
        self.assertEqual(self.pcap_filter(), "pcap_filter: not ((host 192.168.102.9) and tcp port 8880)")
