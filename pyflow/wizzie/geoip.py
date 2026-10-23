'''The GeoIP databases of pmacctd, usually kept up to date by another container
(ghcr.io/maxmind/geoipupdate) on a shared volume: GEOIPV2_FILE (country, postal code,
coordinates) and GEOIP_ASN_FILE (AS, read by the http plugin). pyflow waits for them at start
and tells pmacctd to load GEOIPV2_FILE again (SIGUSR2) whenever it changes; the http plugin
opens GEOIP_ASN_FILE at every purge, so it needs nothing'''

import os, time

# pmacct primitives of each GEOIP_FIELDS value, both ends of the flow. pmacct has none for "city":
# city and region are added by the http plugin itself (http_geoip_city_file)
GEOIP_PRIMITIVES = {
    "country": ("src_host_country", "dst_host_country"),
    "pocode": ("src_host_pocode", "dst_host_pocode"),
    "coords": ("src_host_coords", "dst_host_coords"),
    "city": (),
}


class GeoipFile:

    def __init__(self, conf):
        self.logger = conf.logger
        self.exit_event = conf.exit_event
        self.path = conf.config["geoipv2_file"]  # the one followed, may be None
        self.paths = [path for path in (self.path, conf.config["geoip_asn_file"]) if path]  # the ones waited for
        self.check_seconds = int(conf.config["geoipv2_check_seconds"])
        self.wait_seconds = int(conf.config["geoipv2_wait"])
        self.stamp = None  # what identifies the version of the file pmacctd has, see __stamp
        self.next_check = 0

    def wait(self):
        '''Waits up to GEOIPV2_WAIT seconds for the files to be there. Without them pmacctd still
        runs, with no GeoIP fields, and uses each file as soon as it shows up'''
        deadline = time.monotonic() + self.wait_seconds
        missing = [path for path in self.paths if self.__stamp(path) is None]
        if missing:
            self.logger.info(f"waiting up to {self.wait_seconds} s for {', '.join(missing)}")
        while missing and time.monotonic() < deadline:
            if self.exit_event.wait(1):
                return
            missing = [path for path in missing if self.__stamp(path) is None]
        for path in missing:
            self.logger.warning(f"{path} is not there: its GeoIP fields stay out until it shows up")
        self.stamp = self.__stamp(self.path)

    def changed(self) -> bool:
        '''True, once, when the file shows up or is replaced; checked every GEOIPV2_CHECK_SECONDS'''
        now = time.monotonic()
        if not self.path or now < self.next_check:
            return False
        self.next_check = now + self.check_seconds
        stamp = self.__stamp(self.path)
        if stamp is None or stamp == self.stamp:
            return False
        self.stamp = stamp
        return True

    # Private

    @staticmethod
    def __stamp(path):
        '''inode, size and modification time: geoipupdate writes a new file and renames it over the old one'''
        if not path:
            return None
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (st.st_ino, st.st_size, st.st_mtime_ns) if st.st_size else None
