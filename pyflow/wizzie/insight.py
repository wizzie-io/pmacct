'''Session with Insight as its flow_manager (wdp-insight#2104 phase 4): one bidirectional stream of
FlowManagerService.OpenSession (proto/flow_manager.proto, vendored from Insight), kept open and
reconnected while pyflow runs. The flows do not go through it: they are published over HTTP.

The first message is a Hello with the flow_manager Device id (GRPC_DEVICE_ID), an instance id stable
across reconnections, the capture interfaces, the local networks and where the site is (localgeo).
Insight lets only one instance hold a flow_manager's connection: another one is rejected with
ALREADY_EXISTS and retries; the same instance gets it back at once when it reconnects.

Insight sends control requests on the stream (today StatusRequest), which this answers with what
pyflow knows of pmacctd (wizzie/status.py).

Only started with GRPC_HOST, GRPC_DEVICE_ID and API_KEY (Configuration.insight_enabled). grpc is
imported when the session starts: the rest of pyflow, and its tests, do without it.
'''
import os, queue, socket, threading, time

# Seconds between reconnection attempts, as pyprobes, pyosmocv and pykatok
RECONNECT_SECONDS = 10
# Keepalive as the other connectors: Insight's server accepts pings every 45 s at most, and the BDP
# pings gRPC adds on its own made it answer GOAWAY "too_many_pings" (wdp-insight#2068)
KEEPALIVE_OPTIONS = [
    ("grpc.keepalive_time_ms", 60_000),
    ("grpc.keepalive_timeout_ms", 20_000),
    ("grpc.keepalive_permit_without_calls", 1),
    ("grpc.http2.max_pings_without_data", 0),
    ("grpc.http2.bdp_probe", 0),
]
# Initial metadata with which Insight accepts the connection
SESSION_OPEN_METADATA = ("flow-session", "open")
# Seconds the status waits for the libpcap counters pmacctd writes on SIGUSR1
STATS_TIMEOUT = 2.0


def instance_id(conf) -> str:
    '''GRPC_INSTANCE_ID, or the hostname: stable across reconnections of this process, so Insight
    gives the connection back at once instead of waiting for it to expire'''
    return conf.config["grpc_instance_id"] or socket.gethostname()


def hello_values(conf, local_geo: dict) -> dict:
    '''Fields of the Hello: who this is, what it captures and where the site is'''
    values = {
        "flow_manager_device_id": conf.config["grpc_device_id"],
        "instance_id": instance_id(conf),
        "version": conf.version,
        "interfaces": conf.items("pcap_interface"),
        "local_networks": conf.items("local_networks"),
    }
    if local_geo:
        site = {key: str(local_geo[key]) for key in ("country", "asn", "as_org", "city", "region", "ip")
                if local_geo.get(key)}
        if local_geo.get("coords"):
            latitude, longitude = local_geo["coords"].split(",")
            site["coordinates"] = {"latitude": float(latitude), "longitude": float(longitude)}
        site["sources"] = list(getattr(conf, "local_geo_sources", []))
        values["site"] = site
    return values


def geoip_values(conf) -> dict:
    '''Whether the GeoIP databases are there, and the version in use of GEOIPV2_FILE'''
    city, asn = conf.config["geoipv2_file"], conf.config["geoip_asn_file"]
    values = {"city": bool(city and os.path.exists(city)), "asn": bool(asn and os.path.exists(asn)), "updated": 0}
    if values["city"]:
        values["updated"] = int(os.stat(city).st_mtime)
    return values


def status_values(conf, pmacctd, started_at: float, stats_timeout: float = STATS_TIMEOUT) -> dict:
    '''Fields of the StatusResponse, out of pmacctd and what its output said'''
    running = pmacctd.running()
    interfaces = pmacctd.interface_stats(conf.items("pcap_interface"), stats_timeout) if running else {}
    log = pmacctd.log.snapshot()
    values = {
        "uptime_seconds": int(time.time() - started_at),
        "version": conf.version,
        "pmacctd_running": running,
        "pmacctd_uptime_seconds": pmacctd.uptime(),
        "interfaces": [
            {"name": name, "received_packets": stats["received_packets"], "dropped_packets": stats["dropped_packets"]}
            for name, stats in sorted(interfaces.items())
        ],
        "purges": log["purges"],
        "messages_sent": log["messages_sent"],
        "messages_dropped": log["messages_dropped"],
        "geoip": geoip_values(conf),
    }
    if log["last_purge"]:
        values["last_purge"] = log["last_purge"]
    if log["last_error"]:
        values["last_error"] = log["last_error"]["message"]
        values["last_error_time"] = log["last_error"]["time"]
    return values


class InsightSession:
    '''One OpenSession stream: what goes out is queued in `outbound` and sent by the generator gRPC consumes'''

    def __init__(self, conf, pmacctd, local_geo, started_at, pb2):
        self.conf = conf
        self.logger = conf.logger
        self.pmacctd = pmacctd
        self.local_geo = local_geo
        self.started_at = started_at
        self.pb2 = pb2
        self.outbound = queue.Queue()
        self.closed = threading.Event()

    def messages(self):
        '''Generator consumed by stub.OpenSession(): the Hello first, then whatever is queued'''
        values = hello_values(self.conf, self.local_geo)
        site = values.pop("site", None)
        hello = self.pb2.Hello(**values)
        if site:
            coordinates = site.pop("coordinates", None)
            hello.site.CopyFrom(self.pb2.Site(**site))
            if coordinates:
                hello.site.coordinates.CopyFrom(self.pb2.Coordinates(**coordinates))
        yield self.pb2.FlowManagerInput(hello=hello)
        while not self.closed.is_set() and not self.conf.exit_event.is_set():
            try:
                yield self.outbound.get(timeout=1)
            except queue.Empty:
                continue

    def handle(self, output):
        kind = output.WhichOneof("message")
        if kind == "status":
            # answered in its own thread: the counters of SIGUSR1 take a moment
            request_id = output.status.request_id
            threading.Thread(target=self.answer_status, args=(request_id,), daemon=True).start()
        else:
            self.logger.debug(f"Insight: {kind} message not handled")

    def answer_status(self, request_id: str):
        try:
            values = status_values(self.conf, self.pmacctd, self.started_at)
        except Exception as error:
            self.logger.error(f"Insight: status not answered: {error}")
            return
        pb2 = self.pb2
        interfaces = [pb2.InterfaceStats(**interface) for interface in values.pop("interfaces")]
        geoip = pb2.GeoipStatus(**values.pop("geoip"))
        last_purge = values.pop("last_purge", None)
        response = pb2.StatusResponse(request_id=request_id, interfaces=interfaces, geoip=geoip, **values)
        if last_purge:
            response.last_purge.CopyFrom(pb2.Purge(**last_purge))
        self.outbound.put(pb2.FlowManagerInput(status=response))


def run_session(conf, pmacctd, local_geo, started_at):
    import grpc
    from wizzie.grpc_generated import flow_manager_pb2, flow_manager_pb2_grpc

    config = conf.config
    target = f"{config['grpc_host']}:{config['grpc_port']}"
    if conf.is_true("grpc_secure"):
        channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(), options=KEEPALIVE_OPTIONS)
    else:
        channel = grpc.insecure_channel(target, options=KEEPALIVE_OPTIONS)
    session = InsightSession(conf, pmacctd, local_geo, started_at, flow_manager_pb2)
    try:
        stub = flow_manager_pb2_grpc.FlowManagerServiceStub(channel)
        stream = stub.OpenSession(session.messages(), metadata=[("x-api-key", config["api_key"])])
        # Insight accepts the connection sending SESSION_OPEN_METADATA; a rejected one gets none
        if SESSION_OPEN_METADATA in (stream.initial_metadata() or ()):
            conf.logger.info(f"Insight: connected to {target} as instance {instance_id(conf)}")
        for output in stream:
            session.handle(output)
            if conf.exit_event.is_set():
                stream.cancel()
                break
    finally:
        session.closed.set()
        channel.close()


def insight_watch(conf, pmacctd, local_geo, started_at):
    '''Thread target: keeps the stream with Insight open, reconnecting every RECONNECT_SECONDS until
    the exit. An error here never touches the capture'''
    import grpc

    logger = conf.logger
    while not conf.exit_event.is_set():
        try:
            run_session(conf, pmacctd, local_geo, started_at)
            if not conf.exit_event.is_set():
                logger.info("Insight: the stream ended, reconnecting")
        except grpc.RpcError as error:
            code = error.code() if callable(getattr(error, "code", None)) else None
            details = error.details() if callable(getattr(error, "details", None)) else str(error)
            if code == grpc.StatusCode.ALREADY_EXISTS:
                logger.info(f"Insight: another instance holds the connection of this flow_manager ({details})")
            elif code in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.CANCELLED):
                logger.warning(f"Insight: disconnected ({details}), reconnecting in {RECONNECT_SECONDS} s")
            else:
                logger.error(f"Insight: stream error {code}: {details}")
        except Exception as error:
            logger.error(f"Insight: stream error: {error}")
        conf.exit_event.wait(RECONNECT_SECONDS)
