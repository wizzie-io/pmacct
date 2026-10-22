#!/usr/bin/env python3
#
# Functional test of the http plugin, normally run through run.sh. For each
# case it starts a mock HTTP endpoint and nfacctd with an http plugin pointed
# at it, sends one NetFlow v5 packet and checks what the endpoint received and
# what nfacctd logged.
#
#   harness.py <path to nfacctd> [case ...]

import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NF_PORT = 2100
APIKEY = "testkey"
TOPIC = "flows"
REFRESH = 5  # http_refresh_time, seconds


class Endpoint:
    '''Mock of Kong + http2k: records every request, answers with a fixed status'''

    def __init__(self, status=200):
        self.status = status
        self.requests = []  # (path, headers with lowercase names, body)
        endpoint = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                headers = {k.lower(): v for k, v in self.headers.items()}
                endpoint.requests.append((self.path, headers, body))
                self.send_response(endpoint.status)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def messages(self):
        '''Every JSON object received, in order: bodies are objects back to back'''
        decoder = json.JSONDecoder()
        out = []
        for _, _, body in self.requests:
            text = body.decode()
            pos = 0
            while pos < len(text):
                obj, pos = decoder.raw_decode(text, pos)
                out.append(obj)
        return out


def send_netflow_v5(n_records):
    '''One NetFlow v5 packet with n_records TCP flows 10.0.0.x:4000x -> 10.0.1.1:443'''
    uptime = 100000
    header = struct.pack("!HHIIIIBBH", 5, n_records, uptime, int(time.time()), 0, 1, 0, 0, 0)
    records = b""
    for i in range(n_records):
        records += struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH",
                               socket.inet_aton("10.0.0.%d" % (i + 1)), socket.inet_aton("10.0.1.1"),
                               socket.inet_aton("0.0.0.0"), 0, 0, 10, 1000, uptime - 5000, uptime - 1000,
                               40000 + i, 443, 0, 0x18, 6, 0, 0, 0, 0, 0, 0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(header + records, ("127.0.0.1", NF_PORT))
    sock.close()


class Nfacctd:
    def __init__(self, binary, workdir, config):
        self.conf = os.path.join(workdir, "nfacctd.conf")
        self.log = os.path.join(workdir, "nfacctd.log")
        with open(self.conf, "w") as f:
            f.write(config)
        with open(self.log, "w") as logf:
            # own process group, so that stopping it also stops the plugin and writer processes
            self.proc = subprocess.Popen([binary, "-f", self.conf], stdout=logf, stderr=subprocess.STDOUT,
                                         start_new_session=True)

    def text(self):
        with open(self.log) as f:
            return f.read()

    def wait_for(self, predicate, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate(self.text()):
                return True
            time.sleep(0.5)
        return False

    def stop(self):
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        # writer processes may outlive the core for a moment
        time.sleep(1)


def config(endpoint, *extra):
    lines = [
        "daemonize: false",
        "nfacctd_ip: 127.0.0.1",
        "nfacctd_port: %d" % NF_PORT,
        "nfacctd_time_new: true",
        "plugins: http[t]",
        "aggregate[t]: src_host, dst_host, src_port, dst_port, proto",
        "http_endpoint[t]: %s" % endpoint.url,
        "http_topic[t]: %s" % TOPIC,
        "http_refresh_time[t]: %d" % REFRESH,
    ]
    return "\n".join(lines + list(extra)) + "\n"


def purged(text):
    '''True once a purge with something in the cache has ended'''
    return any(int(total) > 0 for _, total in re.findall(r"Purging cache - END \(.*QN: (\d+)/(\d+)", text))


class Failure(Exception):
    pass


def check(cond, what):
    if not cond:
        raise Failure(what)


def run_flows(binary, workdir, endpoint, n_records, *extra, wait=purged):
    '''Starts nfacctd, sends n_records flows, waits for the purge; returns the log'''
    nf = Nfacctd(binary, workdir, config(endpoint, *extra))
    try:
        time.sleep(2)
        send_netflow_v5(n_records)
        nf.wait_for(wait, REFRESH * 4)
        return nf.text()
    finally:
        nf.stop()


# Cases: each takes (nfacctd, workdir) and raises Failure

def case_delivery(binary, workdir):
    '''200: all records delivered, in batches bounded by http_multi_values, with the contract headers'''
    ep = Endpoint(200)
    try:
        log = run_flows(binary, workdir, ep, 20, "http_apikey[t]: %s" % APIKEY, "http_multi_values[t]: 600")
        msgs = ep.messages()
        check("QN: 20/20" in log, "log reports QN: 20/20")
        check(len(msgs) == 20, "20 messages received, got %d" % len(msgs))
        check(len(ep.requests) > 1, "more than one POST with http_multi_values 600")
        for path, headers, body in ep.requests:
            check(path == "/v1/data/%s" % TOPIC, "path /v1/data/%s, got %s" % (TOPIC, path))
            check(headers.get("apikey") == APIKEY, "apikey header")
            check(headers.get("content-type") == "application/json", "Content-Type application/json")
            check(len(body) <= 600, "batch within http_multi_values, got %d bytes" % len(body))
        check(all(m.get("event_type") == "purge" for m in msgs), "event_type purge")
        check(sorted(m["ip_src"] for m in msgs) == sorted("10.0.0.%d" % (i + 1) for i in range(20)),
              "one message per flow sent")
        check(all("timestamp" not in m and "event_source" not in m for m in msgs),
              "no timestamp/event_source unless configured")
        check(not re.search(r"WARN|ERROR", log), "no WARN/ERROR in the log")
    finally:
        ep.stop()


def case_apikey_header(binary, workdir):
    '''http_apikey_header renames the header carrying the key'''
    ep = Endpoint(200)
    try:
        run_flows(binary, workdir, ep, 2, "http_apikey[t]: %s" % APIKEY, "http_apikey_header[t]: X-Api-Key")
        check(ep.requests, "something was received")
        for _, headers, _ in ep.requests:
            check(headers.get("x-api-key") == APIKEY, "X-Api-Key header")
            check("apikey" not in headers, "no default apikey header")
    finally:
        ep.stop()


def case_timestamp_history(binary, workdir):
    '''http_timestamp_field is the start of the http_history bin, same as stamp_inserted; plus event_source'''
    ep = Endpoint(200)
    try:
        run_flows(binary, workdir, ep, 3, "http_apikey[t]: %s" % APIKEY,
                  "http_history[t]: 1m", "http_history_roundoff[t]: m", "timestamps_since_epoch: true",
                  "http_timestamp_field[t]: timestamp", "http_event_source[t]: pmacct")
        msgs = ep.messages()
        check(len(msgs) == 3, "3 messages received, got %d" % len(msgs))
        for m in msgs:
            check(isinstance(m.get("timestamp"), int), "timestamp is an integer")
            check(m["timestamp"] == int(m["stamp_inserted"]), "timestamp equals stamp_inserted")
            check(m["timestamp"] % 60 == 0, "timestamp aligned to the minute")
            check(m.get("event_source") == "pmacct", "event_source pmacct")
    finally:
        ep.stop()


def case_timestamp_no_history(binary, workdir):
    '''without http_history the timestamp field is the time of the purge'''
    ep = Endpoint(200)
    try:
        start = int(time.time())
        run_flows(binary, workdir, ep, 2, "http_apikey[t]: %s" % APIKEY, "http_timestamp_field[t]: ts")
        msgs = ep.messages()
        check(msgs, "something was received")
        for m in msgs:
            check("stamp_inserted" not in m, "no stamp_inserted without http_history")
            check(isinstance(m.get("ts"), int) and start <= m["ts"] <= time.time(), "ts is the purge time")
    finally:
        ep.stop()


def case_retry_5xx(binary, workdir):
    '''5xx is retried http_retries times, then the batch is dropped with an ERROR'''
    ep = Endpoint(500)
    try:
        log = run_flows(binary, workdir, ep, 2, "http_apikey[t]: %s" % APIKEY, "http_retries[t]: 2",
                        wait=lambda t: "dropping" in t)
        check(len(ep.requests) == 2, "2 attempts, got %d" % len(ep.requests))
        check(re.search(r"ERROR .*failed, dropping 2 msgs", log), "ERROR about the dropped batch")
        check(APIKEY not in log, "the API key is never logged")
    finally:
        ep.stop()


def case_no_retry_4xx(binary, workdir):
    '''a 401 (rejected key) is not retried'''
    ep = Endpoint(401)
    try:
        run_flows(binary, workdir, ep, 2, "http_apikey[t]: %s" % APIKEY, "http_retries[t]: 3",
                  wait=lambda t: "dropping" in t)
        check(len(ep.requests) == 1, "1 attempt, got %d" % len(ep.requests))
    finally:
        ep.stop()


def case_missing_apikey(binary, workdir):
    '''http_apikey is mandatory: the plugin refuses to start'''
    ep = Endpoint(200)
    try:
        nf = Nfacctd(binary, workdir, config(ep))
        try:
            found = nf.wait_for(lambda t: "'http_apikey' is required" in t, 10)
        finally:
            nf.stop()
        check(found, "ERROR about the missing http_apikey")
    finally:
        ep.stop()


CASES = [(name[len("case_"):], func) for name, func in globals().items() if name.startswith("case_")]


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: harness.py <nfacctd> [case ...]")
    binary, wanted = sys.argv[1], sys.argv[2:]
    unknown = set(wanted) - {name for name, _ in CASES}
    if unknown:
        sys.exit("unknown cases: %s (known: %s)" % (", ".join(sorted(unknown)), ", ".join(n for n, _ in CASES)))

    failed = 0
    for name, func in CASES:
        if wanted and name not in wanted:
            continue
        with tempfile.TemporaryDirectory() as workdir:
            try:
                func(binary, workdir)
                print("PASS  %s" % name)
            except Failure as e:
                failed += 1
                print("FAIL  %s: %s" % (name, e))
                log = os.path.join(workdir, "nfacctd.log")
                if os.path.exists(log):
                    with open(log) as f:
                        print("      " + "\n      ".join(f.read().splitlines()[-15:]))
        sys.stdout.flush()

    print("%d failed" % failed if failed else "all passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
