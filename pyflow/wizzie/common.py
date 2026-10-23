import logging, os, threading


def str2bool(v):
    return v.lower() in ("yes", "true", "t", "1")


class ConfigError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)

    def __str__(self):
        return self.message


class Configuration:
    '''Settings of pyflow out of environment variables (see README.md). An unset or empty variable
    takes the default, but for _EMPTY_DISABLES: set to empty, the feature it drives is disabled'''

    # Keys that may legitimately be left unset: each one is validated together with the feature that needs it
    _OPTIONAL_KEYS = {"http_endpoint", "api_key", "pcap_interface", "pcap_savefile", "pmacctd_config_file", "pcap_filter",
                      "local_networks", "cache_entries", "geoipv2_file", "extra_config"}
    # Keys an empty value disables instead of taking the default
    _EMPTY_DISABLES = {"history_roundoff", "timestamp_field", "event_source", "event_type", "override_prefix"}
    # Keys whose value is never written to the log
    _SECRET_KEYS = {"api_key"}

    def __init__(self, environ=None):
        environ = os.environ if environ is None else environ
        self.logger = logging.getLogger("PyFlow")
        self.exit_event = threading.Event()  # set when the process is asked to stop
        # set by the image build (--build-arg VERSION), it is not a setting: "unknown" when run from the sources
        self.version = environ.get("PYFLOW_VERSION") or "unknown"

        # default values for config
        self.config = {
            "log_level": "INFO",
            "pmacctd_config_file": None,  # complete pmacctd configuration: used as it is, the rest is ignored
            "config_dir": "/tmp/pmacct",  # where the pmacctd configuration files are written
            "http_endpoint": None,
            "api_key": None,
            "events_topic": "pmacct",
            "pcap_interface": None,  # one or several, comma separated
            "pcap_savefile": None,  # tests: packets out of a pcap file instead of an interface
            "pcap_filter": None,
            "pcap_exclude_endpoint": "True",  # leave out of the capture our own traffic to HTTP_ENDPOINT
            "promisc": "True",
            "snaplen": "700",
            "aggregate": "class, etype, src_mac, dst_mac, vlan, src_host, dst_host, src_port, dst_port, proto, tos, tcpflags",
            "refresh_time": "60",
            "history": "1m",
            "history_roundoff": "m",
            "timestamp_field": "timestamp",
            "event_source": "pmacct",
            "event_type": "pmacct_flow",
            "override_prefix": "pmacct_",
            "local_networks": None,  # comma separated: enables 'direction'
            "local_multicast": "True",
            "net_fields": "False",
            "classifier_num_roots": "512",
            "classifier_max_flows": "200000",
            "classifier_proto_guess": "True",
            "class_split": "True",
            "class_details": "True",
            "http_timeout": "10",
            "http_retries": "3",
            "http_multi_values": "131072",
            "cache_entries": None,
            "geoipv2_file": None,
            "debug": "False",  # pmacctd debug log
            "extra_config": None,  # pmacctd configuration lines appended at the end
        }
        # config keys mapping from System ENV vars: the same names, upper case
        self.env_map = {key: key.upper() for key in self.config}

        self.__set(environ)
        self.__configure_logger()
        self.__check_configuration()

    def is_true(self, key) -> bool:
        return str2bool(self.config[key] or "")

    def items(self, key) -> list:
        '''A comma separated setting as a list, blanks removed'''
        return [item.strip() for item in (self.config[key] or "").split(",") if item.strip()]

    # Private

    def __set(self, environ):
        # set all config keys from its environment map values. An empty value is the same as unset, but for _EMPTY_DISABLES
        for key, var in self.env_map.items():
            value = environ.get(var)
            if value is None:
                continue
            if value != "" or key in self._EMPTY_DISABLES:
                self.config[key] = value

    def __configure_logger(self):
        if not self.logger.handlers:
            log_handler = logging.StreamHandler()
            log_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', "%Y-%m-%d %H:%M:%S %Z"))
            self.logger.addHandler(log_handler)  # set to stdout logs
        level = self.config["log_level"].upper()
        if level == "WARN":
            level = "WARNING"
        if level not in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"):
            print(f"Unrecognized LOG_LEVEL value: {self.config['log_level']}. Setting LOG_LEVEL to default value INFO")
            level = "INFO"
        self.logger.setLevel(level)

    def __check_configuration(self):
        if self.config["pmacctd_config_file"]:
            if not os.access(self.config["pmacctd_config_file"], os.R_OK):
                raise ConfigError(f"PMACCTD_CONFIG_FILE \"{self.config['pmacctd_config_file']}\" can't be read")
            return
        if not self.config["http_endpoint"]:
            raise ConfigError("ENV var HTTP_ENDPOINT must be set")
        if not self.config["api_key"]:
            raise ConfigError("ENV var API_KEY must be set")
        if not (self.config["pcap_interface"] or self.config["pcap_savefile"]):
            raise ConfigError("ENV var PCAP_INTERFACE must be set")
        for key in ("snaplen", "refresh_time", "classifier_num_roots", "classifier_max_flows", "http_timeout", "http_retries",
                    "http_multi_values", "cache_entries"):
            if self.config[key] is not None and not self.config[key].isdigit():
                raise ConfigError(f"{self.env_map[key]} \"{self.config[key]}\" is not valid, expected an integer")
        for key in self.config:
            value = "***" if key in self._SECRET_KEYS else self.config[key]
            self.logger.debug(f"Configuration for {self.env_map[key]} is {value}")
