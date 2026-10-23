import signal, sys
from wizzie.common import Configuration, ConfigError
from wizzie.pmacctd import PmacctdConfig, Pmacctd

if __name__ == "__main__":
    try:
        conf = Configuration()
    except ConfigError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        sys.exit(1)
    logger = conf.logger
    logger.info(f"PyFlow version: {conf.version}")

    # SIGTERM (docker stop) and SIGINT ask for an ordered exit: pmacctd is stopped first
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda signum, frame: conf.exit_event.set())

    if conf.config["pmacctd_config_file"]:
        conf_file = conf.config["pmacctd_config_file"]
        logger.info(f"using {conf_file} as it is")
    else:
        conf_file = PmacctdConfig(conf).write()

    pmacctd = Pmacctd(conf, conf_file)
    pmacctd.start()

    # pyflow lives as long as pmacctd: if pmacctd ends on its own (an error, or the end of
    # PCAP_SAVEFILE), pyflow ends with its exit code and the container restart policy applies
    while not conf.exit_event.wait(1):
        code = pmacctd.poll()
        if code is not None:
            (logger.info if code == 0 else logger.error)(f"pmacctd exited with code {code}")
            sys.exit(code)

    logger.info("Stopping pmacctd")
    code = pmacctd.stop()
    logger.info(f"pmacctd exited with code {code}. Exiting from program, goodbye!")
