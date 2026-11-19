'''What pyflow knows of pmacctd for the status Insight asks for (flow_manager, wdp-insight#2104 phase 4).

pmacctd writes everything to its log, so pyflow reads its output line by line (Pmacctd forwards
every line to its own stdout, the container log stays the same) and keeps:

* the deliveries of the http plugin: "*** Purging cache - END (PID: n, QN: sent/total, ET: s) ***"
  at the end of each purge, "HTTP POST <url> failed, dropping n msgs (b bytes)" when a batch is
  given up after the retries;
* the last ERROR line;
* the messages delivered per second: an exponential moving average of each purge, weighted by time
  (RATE_HALF_LIFE), so that the last purges weigh most;
* the libpcap counters of each interface, which pmacctd writes on SIGUSR1:
  "stats [<interface>,<id>] time=<t> received_packets=<n> dropped_packets=<n>".
'''

import re, threading, time

PURGE_END = re.compile(r"Purging cache - END \(PID: \d+, QN: (\d+)/(\d+)")
DROPPED = re.compile(r"HTTP POST \S+ failed, dropping (\d+) msgs")
INTERFACE_STATS = re.compile(r"stats \[([^,\]]+),\d+\] time=\d+ received_packets=(\d+) dropped_packets=(\d+)")
ERROR = re.compile(r"^ERROR \( [^)]* \): (.*)$")
# Half-life of the moving average of the messages per second: what was delivered this many seconds
# ago weighs half as much as the last purge
RATE_HALF_LIFE = 300


class PmacctdLog:
    '''Counters out of the lines pmacctd writes, safe to read from another thread'''

    def __init__(self, clock=time.time):
        self.clock = clock
        self.lock = threading.Lock()
        self.stats_seen = threading.Condition(self.lock)
        self.purges = 0
        self.messages_sent = 0
        self.messages_dropped = 0
        self.last_purge = None  # {"time", "sent", "total"}
        self.last_error = None  # {"time", "message"}
        self.interfaces = {}  # name -> {"received_packets", "dropped_packets", "time"}
        self.messages_per_second = None  # moving average; None until the second purge
        self.previous_purge = None  # time of the last purge, to measure the interval

    def feed(self, line: str):
        line = line.rstrip("\n")
        with self.lock:
            match = PURGE_END.search(line)
            if match:
                sent, total = int(match.group(1)), int(match.group(2))
                now = self.clock()
                self.purges += 1
                self.messages_sent += sent
                self.last_purge = {"time": int(now), "sent": sent, "total": total}
                self.__update_rate(sent, now)
                return
            match = INTERFACE_STATS.search(line)
            if match:
                self.interfaces[match.group(1)] = {
                    "received_packets": int(match.group(2)), "dropped_packets": int(match.group(3)),
                    "time": self.clock(),
                }
                self.stats_seen.notify_all()
                return
            match = DROPPED.search(line)
            if match:
                self.messages_dropped += int(match.group(1))
            match = ERROR.match(line)
            if match:
                self.last_error = {"time": int(self.clock()), "message": match.group(1).strip()}

    def __update_rate(self, sent: int, now: float):
        '''Rate of this purge (its messages over the time since the previous one) into the moving
        average, weighted by the time elapsed: alpha = 1 - 2^(-dt / RATE_HALF_LIFE). The first purge
        has no interval, so it only starts the clock'''
        previous, self.previous_purge = self.previous_purge, now
        if previous is None or now <= previous:
            return
        elapsed = now - previous
        rate = sent / elapsed
        if self.messages_per_second is None:
            self.messages_per_second = rate
        else:
            alpha = 1 - 2 ** (-elapsed / RATE_HALF_LIFE)
            self.messages_per_second += alpha * (rate - self.messages_per_second)

    def wait_interfaces(self, names, since: float, timeout: float) -> dict:
        '''The counters of `names` written after `since` (a SIGUSR1 sent then), waiting up to
        `timeout` seconds for all of them; the ones that did not show up are left out'''
        deadline = self.clock() + timeout
        with self.lock:
            while True:
                fresh = {name: dict(stats) for name, stats in self.interfaces.items()
                         if stats["time"] >= since and (not names or name in names)}
                remaining = deadline - self.clock()
                if (names and len(fresh) == len(names)) or remaining <= 0:
                    return fresh
                self.stats_seen.wait(remaining)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "purges": self.purges,
                "messages_sent": self.messages_sent,
                "messages_dropped": self.messages_dropped,
                "last_purge": dict(self.last_purge) if self.last_purge else None,
                "last_error": dict(self.last_error) if self.last_error else None,
                "messages_per_second": self.messages_per_second,
            }
