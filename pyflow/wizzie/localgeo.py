'''Where the probe is, for the addresses of LOCAL_NETWORKS, which no GeoIP database knows: the
country, AS and coordinates the http plugin gives them (http_local_*). Out of LOCAL_COUNTRY,
LOCAL_ASN, LOCAL_AS_ORG and LOCAL_COORDS and, for what they leave unset and LOCAL_GEO_LOOKUP
allows, out of ipinfo.io, which locates the public IP address the probe goes out to Internet with'''

import json, re, urllib.request

IPINFO_URL = "https://ipinfo.io/json"
IPINFO_TIMEOUT = 5  # seconds


def fetch_ipinfo(token=None) -> dict:
    request = urllib.request.Request(IPINFO_URL, headers={"Accept": "application/json"})
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=IPINFO_TIMEOUT) as response:
        return json.load(response)


def resolve(conf, fetch=fetch_ipinfo) -> dict:
    '''{"country", "asn", "as_org", "coords"} with the values found, only for the GeoIP fields in
    use; empty without LOCAL_NETWORKS or GeoIP databases'''
    c, logger = conf.config, conf.logger
    if not conf.items("local_networks"):
        return {}
    fields = conf.items("geoip_fields") if c["geoipv2_file"] else []
    wanted = []
    if "country" in fields:
        wanted.append("country")
    if c["geoip_asn_file"]:
        wanted += ["asn", "as_org"]
    if "coords" in fields:
        wanted.append("coords")

    values = {key: c[f"local_{key}"] for key in wanted if c[f"local_{key}"]}
    sources = {key: f"LOCAL_{key.upper()}" for key in values}
    missing = [key for key in wanted if key not in values and key != "as_org"]

    if missing and conf.is_true("local_geo_lookup"):
        logger.info(f"asking {IPINFO_URL} where this probe is ({', '.join(missing)}); LOCAL_GEO_LOOKUP=False to avoid it")
        try:
            found = from_ipinfo(fetch(c["ipinfo_token"]))
        except Exception as error:  # no Internet, rate limited, not JSON...
            logger.warning(f"{IPINFO_URL} could not be asked ({error}): set LOCAL_COUNTRY, LOCAL_ASN, LOCAL_AS_ORG and LOCAL_COORDS instead")
            found = {}
        for key in wanted:  # "asn" goes before "as_org"
            if key in values or key not in found:
                continue
            # the organization goes with its AS number: from ipinfo.io only when the number is too
            if key == "as_org" and sources.get("asn") != "ipinfo.io":
                continue
            values[key] = found[key]
            sources[key] = "ipinfo.io"

    for key in wanted:
        if key in values:
            logger.info(f"local networks: {key} {values[key]} ({sources[key]})")
        elif key != "as_org":
            logger.warning(f"local networks: no {key} known, their {key} fields stay as GeoIP leaves them")
    return values


def from_ipinfo(info) -> dict:
    '''The values of an ipinfo.io answer: "country": "ES", "org": "AS3352 TELEFONICA DE ESPANA
    S.A.U.", "loc": "37.3446,-6.0639"'''
    values = {}
    if isinstance(info.get("country"), str) and re.fullmatch(r"[A-Z]{2}", info["country"]):
        values["country"] = info["country"]
    org = re.fullmatch(r"AS(\d+)\s*(.*)", info.get("org") or "")
    if org:
        values["asn"] = org.group(1)
        if org.group(2):
            values["as_org"] = org.group(2)
    if isinstance(info.get("loc"), str) and re.fullmatch(r"-?\d+(\.\d+)?,-?\d+(\.\d+)?", info["loc"]):
        values["coords"] = info["loc"]
    return values
