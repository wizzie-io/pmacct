/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2025 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "plugin_common.h"
#include "plugin_cmn_json.h"
#include "http_plugin.h"
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#endif
#ifndef WITH_JANSSON
#error "--enable-http requires --enable-jansson"
#endif

/* Global variables */
char default_http_topic[] = "pmacct.acct";
char default_http_apikey_header[] = "apikey";

static void p_http_local_init(void);

/* significant digits of the decimal numbers (coordinates): 10 keep 7 decimals
   in any of them, about 1 cm, and spare "-6.0639000000000003" */
#define HTTP_REAL_PRECISION 10

/* Functions */
void http_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)
{
  struct pkt_data *data;
  struct ports_table pt;
  struct protos_table prt, tost;
  unsigned char *pipebuf;
  struct pollfd pfd;
  struct insert_data idata;
  int timeout, refresh_timeout;
  int ret, num, recv_budget, poll_bypass;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  int datasize = ((struct channels_list_entry *)ptr)->datasize;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  pid_t core_pid = ((struct channels_list_entry *)ptr)->core_pid;
  struct networks_file_data nfd;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  struct extra_primitives extras;
  struct primitives_ptrs prim_ptrs;
  unsigned char *dataptr;

#ifdef WITH_ZMQ
  struct p_zmq_host *zmq_host = &((struct channels_list_entry *)ptr)->zmq_host;
#else
  void *zmq_host = NULL;
#endif

#ifdef WITH_REDIS
  struct p_redis_host redis_host;
#endif

  memcpy(&config, cfgptr, sizeof(struct configuration));
  memcpy(&extras, &((struct channels_list_entry *)ptr)->extras, sizeof(struct extra_primitives));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "HTTP Plugin", config.name);

  P_set_signals();
  P_init_default_values();
  P_config_checks();
  pipebuf = (unsigned char *) pm_malloc(config.buffer_size);
  memset(pipebuf, 0, config.buffer_size);

  timeout = config.sql_refresh_time*1000;

  if (!config.http_endpoint) {
    Log(LOG_ERR, "ERROR ( %s/%s ): 'http_endpoint' is required. Exiting.\n", config.name, config.type);
    exit_gracefully(1);
  }

  if (!config.http_apikey) {
    Log(LOG_ERR, "ERROR ( %s/%s ): 'http_apikey' is required. Exiting.\n", config.name, config.type);
    exit_gracefully(1);
  }

  if (config.sql_table && strchr(config.sql_table, '$')) {
    Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'http_topic' is not supported. Exiting.\n", config.name, config.type);
    exit_gracefully(1);
  }

  if (config.http_label_flatten && !config.pretag_label_encode_as_map) {
    Log(LOG_WARNING, "WARN ( %s/%s ): 'http_label_flatten' requires 'pre_tag_label_encode_as_map: true'; labels are left as they are.\n", config.name, config.type);
  }

#if defined (WITH_GEOIPV2)
  if (config.http_geoip_asn_file) {
    MMDB_s asn_db;
    int status = MMDB_open(config.http_geoip_asn_file, MMDB_MODE_MMAP, &asn_db);

    if (status == MMDB_SUCCESS) {
      Log(LOG_INFO, "INFO ( %s/%s ): 'http_geoip_asn_file' %s loaded\n", config.name, config.type, config.http_geoip_asn_file);
      MMDB_close(&asn_db);
    }
    else Log(LOG_WARNING, "WARN ( %s/%s ): 'http_geoip_asn_file' can't be loaded yet (%s): AS fields are added once it can.\n", config.name, config.type, MMDB_strerror(status));

    if (!(config.what_to_count & (COUNT_SRC_HOST|COUNT_DST_HOST))) {
      Log(LOG_WARNING, "WARN ( %s/%s ): 'http_geoip_asn_file' needs src_host and/or dst_host in the aggregation method.\n", config.name, config.type);
    }
  }
#else
  if (config.http_geoip_asn_file) {
    Log(LOG_WARNING, "WARN ( %s/%s ): 'http_geoip_asn_file' requires GeoIP support (--enable-geoipv2); ignored.\n", config.name, config.type);
  }
#endif

  p_http_local_init();

#if !defined (WITH_NDPI)
  if (config.http_class_details) {
    Log(LOG_WARNING, "WARN ( %s/%s ): 'http_class_details' requires nDPI support (--enable-ndpi); ignored.\n", config.name, config.type);
  }
#endif

  /* setting some defaults */
  if (!config.sql_table) config.sql_table = default_http_topic;
  if (!config.http_apikey_header) config.http_apikey_header = default_http_apikey_header;
  if (!config.http_timeout) config.http_timeout = DEFAULT_HTTP_TIMEOUT;
  if (!config.http_retries) config.http_retries = DEFAULT_HTTP_RETRIES;
  if (!config.sql_multi_values) config.sql_multi_values = DEFAULT_HTTP_MULTI_VALUES;

  compose_json(config.what_to_count, config.what_to_count_2, config.what_to_count_3);

  if (curl_global_init(CURL_GLOBAL_DEFAULT)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): curl_global_init() failed. Exiting.\n", config.name, config.type);
    exit_gracefully(1);
  }

  /* setting function pointers */
  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET))
    insert_func = P_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) insert_func = P_sum_port_insert;
  else if (config.what_to_count & COUNT_SUM_AS) insert_func = P_sum_as_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) insert_func = P_sum_mac_insert;
#endif
  else insert_func = P_cache_insert;
  purge_func = http_cache_purge;

  memset(&nt, 0, sizeof(nt));
  memset(&nc, 0, sizeof(nc));
  memset(&pt, 0, sizeof(pt));
  memset(&prt, 0, sizeof(prt));
  memset(&tost, 0, sizeof(tost));

  load_networks(config.networks_file, &nt, &nc);
  set_net_funcs(&nt);

  if (config.ports_file) load_ports(config.ports_file, &pt);
  if (config.protos_file) load_protos(config.protos_file, &prt);
  if (config.tos_file) load_tos(config.tos_file, &tost);
  
  memset(&idata, 0, sizeof(idata));
  memset(&prim_ptrs, 0, sizeof(prim_ptrs));
  set_primptrs_funcs(&extras);

  if (config.pipe_zmq) P_zmq_pipe_init(zmq_host, &pipe_fd, &seq);
  else setnonblocking(pipe_fd);

  idata.now = time(NULL);

  /* print_refresh time init: deadline */
  refresh_deadline = idata.now; 
  P_init_refresh_deadline(&refresh_deadline, config.sql_refresh_time, config.sql_startup_delay, config.sql_history_roundoff);

  if (config.sql_history) {
    basetime_init = P_init_historical_acct;
    basetime_eval = P_eval_historical_acct;
    basetime_cmp = P_cmp_historical_acct;

    (*basetime_init)(idata.now);
  }

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

#ifdef WITH_REDIS
  if (config.redis_host) {
    char log_id[SHORTBUFLEN];

    snprintf(log_id, sizeof(log_id), "%s/%s", config.name, config.type);
    p_redis_init(&redis_host, log_id, p_redis_thread_produce_common_plugin_handler);
  }
#endif

  if (config.dry_run == DRY_RUN_SETUP) {
    sleep(DEFAULT_SLOTH_SLEEP_TIME); /* Make sure all comes up */
    printf("INFO ( %s/%s ): Dry run 'setup'. Exiting ..\n", config.name, config.type);
    exit(0);
  }

  /* plugin main loop */
  for(;;) {
    poll_again:
    status->wakeup = TRUE;
    poll_bypass = FALSE;

    calc_refresh_timeout(refresh_deadline, idata.now, &refresh_timeout);

    pfd.fd = pipe_fd;
    pfd.events = POLLIN;
    timeout = refresh_timeout; /* in case we have more timeouts to factor in */
    ret = poll(&pfd, (pfd.fd == ERR ? 0 : 1), timeout);

    if (ret <= 0) {
      if (getppid() != core_pid) {
        Log(LOG_ERR, "ERROR ( %s/%s ): Core process *seems* gone. Exiting.\n", config.name, config.type);
        exit_gracefully(1);
      }

      if (ret < 0) goto poll_again;
    }

    poll_ops:
    P_update_time_reference(&idata);

    if (idata.now > refresh_deadline) P_cache_handle_flush_event(&pt, &prt, &tost);

    recv_budget = 0;
    if (poll_bypass) {
      poll_bypass = FALSE;
      goto read_data;
    }

    switch (ret) {
    case 0: /* timeout */
      break;
    default: /* we received data */
      read_data:
      if (recv_budget == DEFAULT_PLUGIN_COMMON_RECV_BUDGET) {
        poll_bypass = TRUE;
        goto poll_ops;
      }

      if (config.pipe_homegrown) {
        if (!pollagain) {
          seq++;
          seq %= MAX_SEQNUM;
          if (seq == 0) rg_err_count = FALSE;
        }
        else {
          if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0) 
	    exit_gracefully(1); /* we exit silently; something happened at the write end */
        }

        if ((rg->ptr + bufsz) > rg->end) rg->ptr = rg->base;

        if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
          if (!pollagain) {
            pollagain = TRUE;
            goto poll_again;
          }
          else {
            rg_err_count++;
            if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
              Log(LOG_WARNING, "WARN ( %s/%s ): Missing data detected (plugin_buffer_size=%" PRIu64 " plugin_pipe_size=%" PRIu64 ").\n",
                        config.name, config.type, config.buffer_size, config.pipe_size);
              Log(LOG_WARNING, "WARN ( %s/%s ): Increase values or look for plugin_buffer_size, plugin_pipe_size in CONFIG-KEYS document.\n\n",
                        config.name, config.type);
            }

	    rg->ptr = (rg->base + status->last_buf_off);
            seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
          }
        }

        pollagain = FALSE;
        memcpy(pipebuf, rg->ptr, bufsz);
        rg->ptr += bufsz;
      }
#ifdef WITH_ZMQ
      else if (config.pipe_zmq) {
	ret = p_zmq_topic_recv(zmq_host, pipebuf, config.buffer_size);
	if (ret > 0) {
	  if (seq && (((struct ch_buf_hdr *)pipebuf)->seq != ((seq + 1) % MAX_SEQNUM))) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): Missing data detected. Sequence received=%u expected=%u\n",
		config.name, config.type, ((struct ch_buf_hdr *)pipebuf)->seq, ((seq + 1) % MAX_SEQNUM));
	  }

	  seq = ((struct ch_buf_hdr *)pipebuf)->seq;
	}
	else goto poll_again;
      }
#endif

      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));

      if (config.debug_internal_msg) 
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): buffer received len=%" PRIu64 " seq=%u num_entries=%u\n",
                config.name, config.type, ((struct ch_buf_hdr *)pipebuf)->len, seq,
                ((struct ch_buf_hdr *)pipebuf)->num);

      while (((struct ch_buf_hdr *)pipebuf)->num > 0) {
        for (num = 0; primptrs_funcs[num]; num++)
          (*primptrs_funcs[num])((u_char *)data, &extras, &prim_ptrs);

	for (num = 0; net_funcs[num]; num++)
	  (*net_funcs[num])(&nt, &nc, &data->primitives, prim_ptrs.pbgp, &nfd);

	if (config.ports_file) {
          if (!pt.table[data->primitives.src_port]) data->primitives.src_port = PM_L4_PORT_OTHERS;
          if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = PM_L4_PORT_OTHERS;
        }

	if (config.protos_file) {
	  if (!prt.table[data->primitives.proto]) data->primitives.proto = PM_IP_PROTO_OTHERS;
	}

	if (config.tos_file) {
	  if (!tost.table[data->primitives.tos]) data->primitives.tos = PM_IP_TOS_OTHERS;
	}

        prim_ptrs.data = data;
        (*insert_func)(&prim_ptrs, &idata);

	((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) {
          dataptr = (unsigned char *) data;
          if (!prim_ptrs.vlen_next_off) dataptr += datasize;
          else dataptr += prim_ptrs.vlen_next_off;
          data = (struct pkt_data *) dataptr;
	}
      }

      recv_budget++;
      goto read_data;
    }
  }
}

void p_http_get_version()
{
  printf("%s\n", curl_version());
}

/* libcurl write callback: the response body is of no use, discard it */
static size_t p_http_discard_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  return (size * nmemb);
}

/* Appends a JSON message to the batch: messages are concatenated back-to-back,
   which is the format expected by the ingest endpoint (ie. n2kafka, http2k
   decoder). Returns ERR if there is no room left in the batch buffer. */
static int p_http_batch_add(struct p_http_batch *batch, char *msg, size_t msg_len)
{
  if (msg_len > (batch->size - batch->len)) return ERR;

  memcpy((batch->buf + batch->len), msg, msg_len);
  batch->len += msg_len;
  batch->msgs++;

  return SUCCESS;
}

/* POSTs the supplied body, retrying on transport errors and on HTTP statuses
   that may be transient. Returns SUCCESS if the endpoint did accept the data,
   ERR otherwise. */
static int p_http_post(CURL *curl, char *url, char *body, size_t body_len, int msgs)
{
  char errbuf[CURL_ERROR_SIZE];
  long http_code;
  int attempt, retriable;
  CURLcode res;

  if (!body_len) return SUCCESS;

  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) body_len);

  for (attempt = 1; attempt <= config.http_retries; attempt++) {
    errbuf[0] = '\0';
    http_code = 0;
    retriable = TRUE;

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

      if (http_code < 400) {
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): HTTP POST %s: %ld, %lu bytes, %d msgs\n", config.name, config.type,
	    url, http_code, (unsigned long) body_len, msgs);

	return SUCCESS;
      }

      /* client errors, ie. a rejected API key, will not go away by retrying */
      if (http_code < 500 && http_code != 408 && http_code != 429) retriable = FALSE;

      Log(LOG_WARNING, "WARN ( %s/%s ): HTTP POST %s returned %ld (attempt %d/%d)\n", config.name, config.type,
	  url, http_code, attempt, config.http_retries);
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/%s ): HTTP POST %s error: %s (attempt %d/%d)\n", config.name, config.type,
	  url, (strlen(errbuf) ? errbuf : curl_easy_strerror(res)), attempt, config.http_retries);
    }

    if (!retriable) break;
    if (attempt < config.http_retries) usleep(HTTP_RETRY_BACKOFF_MS * 1000 * attempt);
  }

  Log(LOG_ERR, "ERROR ( %s/%s ): HTTP POST %s failed, dropping %d msgs (%lu bytes)\n", config.name, config.type,
      url, msgs, (unsigned long) body_len);

  return ERR;
}

/* POSTs what is in the batch, if anything, and empties it. 'qn' is increased
   by the amount of delivered messages flagged as accountable, ie. everything
   except purge markers. */
static int p_http_flush(CURL *curl, char *url, struct p_http_batch *batch, int *qn)
{
  int ret;

  ret = p_http_post(curl, url, batch->buf, batch->len, batch->msgs);
  if (!ret && qn) (*qn) += batch->acct_msgs;

  batch->len = 0;
  batch->msgs = 0;
  batch->acct_msgs = 0;

  return ret;
}

/* Queues a JSON message for delivery, flushing the batch first should there
   be no room left for it. A message larger than the whole batch buffer is
   sent on its own. */
static int p_http_produce(CURL *curl, char *url, struct p_http_batch *batch, char *msg, int *qn, int accountable)
{
  size_t msg_len = strlen(msg);
  int ret;

  if (!msg_len) return SUCCESS;

  if (p_http_batch_add(batch, msg, msg_len) == ERR) {
    ret = p_http_flush(curl, url, batch, qn);
    if (ret) return ret;

    if (p_http_batch_add(batch, msg, msg_len) == ERR) {
      ret = p_http_post(curl, url, msg, msg_len, 1);
      if (!ret && qn && accountable) (*qn)++;

      return ret;
    }
  }

  if (accountable) batch->acct_msgs++;

  return SUCCESS;
}

/* Sets 'key' to 'value' (reference stolen). If the key was already there and
   http_override_prefix is set, its original value is kept as <prefix><key>. */
static void p_http_override(json_t *obj, const char *key, json_t *value)
{
  json_t *orig = json_object_get(obj, key);

  if (orig && config.http_override_prefix) {
    char kept[SRVBUFLEN];

    snprintf(kept, sizeof(kept), "%s%s", config.http_override_prefix, key);
    json_object_set(obj, kept, orig);
  }

  json_object_set_new(obj, key, value);
}

#if defined (WITH_GEOIPV2)
/* AS of one end of the flow out of a GeoLite2-ASN (or GeoIP2-ISP) database:
   "asn_ip_<end>" and "as_org_ip_<end>"; nothing if the address is not there */
static void p_http_geoip_asn(json_t *obj, MMDB_s *db, struct host_addr *addr, const char *end)
{
  struct sockaddr_storage ss;
  MMDB_lookup_result_s result;
  MMDB_entry_data_s data;
  char key[SRVBUFLEN];
  int mmdb_error;

  if (!addr->family) return;

  memset(&ss, 0, sizeof(ss));
  addr_to_sa((struct sockaddr *) &ss, addr, 0);

  result = MMDB_lookup_sockaddr(db, (struct sockaddr *) &ss, &mmdb_error);
  if (mmdb_error != MMDB_SUCCESS || !result.found_entry) return;

  if (MMDB_get_value(&result.entry, &data, "autonomous_system_number", NULL) == MMDB_SUCCESS &&
      data.has_data && data.type == MMDB_DATA_TYPE_UINT32) {
    snprintf(key, sizeof(key), "asn_ip_%s", end);
    p_http_override(obj, key, json_integer(data.uint32));
  }

  if (MMDB_get_value(&result.entry, &data, "autonomous_system_organization", NULL) == MMDB_SUCCESS &&
      data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING) {
    snprintf(key, sizeof(key), "as_org_ip_%s", end);
    p_http_override(obj, key, json_stringn(data.utf8_string, data.data_size));
  }
}
#endif

/* Where the probe is, for the addresses of the local networks, which no GeoIP
   database knows: http_local_networks, http_local_country, http_local_asn,
   http_local_as_org, http_local_coords */
#define HTTP_LOCAL_NETWORKS_MAX 64

struct p_http_local_net {
  u_int8_t family;
  u_int8_t masklen;
  u_char addr[16];
};

static struct p_http_local_net local_nets[HTTP_LOCAL_NETWORKS_MAX];
static int local_nets_num;
static json_int_t local_asn;
static double local_lat, local_lon;
static int local_coords;

/* parsed once in the plugin process; the purge writers inherit it */
static void p_http_local_init(void)
{
  char *list, *tok, *saveptr = NULL;

  if (!config.http_local_networks) return;

  if (!(list = strdup(config.http_local_networks))) return;

  for (tok = strtok_r(list, ", ", &saveptr); tok; tok = strtok_r(NULL, ", ", &saveptr)) {
    struct p_http_local_net *net = &local_nets[local_nets_num];
    char *slash = strchr(tok, '/');
    int maxlen;

    if (local_nets_num == HTTP_LOCAL_NETWORKS_MAX) {
      Log(LOG_WARNING, "WARN ( %s/%s ): 'http_local_networks': more than %d networks, the rest are ignored.\n", config.name, config.type, HTTP_LOCAL_NETWORKS_MAX);
      break;
    }

    if (slash) *slash = '\0';

    if (inet_pton(AF_INET, tok, net->addr) == 1) net->family = AF_INET, maxlen = 32;
    else if (inet_pton(AF_INET6, tok, net->addr) == 1) net->family = AF_INET6, maxlen = 128;
    else {
      Log(LOG_WARNING, "WARN ( %s/%s ): 'http_local_networks': '%s' is not a network, ignored.\n", config.name, config.type, tok);
      continue;
    }

    net->masklen = slash ? atoi(slash + 1) : maxlen;
    if (net->masklen > maxlen) net->masklen = maxlen;
    local_nets_num++;
  }

  free(list);

  if (config.http_local_asn) local_asn = strtoll(config.http_local_asn, NULL, 10);

  if (config.http_local_coords) {
    if (sscanf(config.http_local_coords, "%lf,%lf", &local_lat, &local_lon) == 2) local_coords = TRUE;
    else Log(LOG_WARNING, "WARN ( %s/%s ): 'http_local_coords' is not '<latitude>,<longitude>', ignored.\n", config.name, config.type);
  }
}

static int p_http_is_local(struct host_addr *addr)
{
  const u_char *bytes;
  int idx, full, rest;

  if (addr->family == AF_INET) bytes = (const u_char *) &addr->address.ipv4;
  else if (addr->family == AF_INET6) bytes = (const u_char *) &addr->address.ipv6;
  else return FALSE;

  for (idx = 0; idx < local_nets_num; idx++) {
    struct p_http_local_net *net = &local_nets[idx];

    if (net->family != addr->family) continue;

    full = net->masklen / 8;
    rest = net->masklen % 8;

    if (memcmp(bytes, net->addr, full)) continue;
    if (rest && ((bytes[full] ^ net->addr[full]) & (0xff << (8 - rest)))) continue;

    return TRUE;
  }

  return FALSE;
}

/* fills in, for a local address, the GeoIP fields left empty: country only if
   the country primitive is there, AS and coordinates if configured */
static void p_http_local_geo(json_t *obj, struct host_addr *addr, const char *end)
{
  char key[SRVBUFLEN], key2[SRVBUFLEN];
  json_t *value, *value2;

  if (!p_http_is_local(addr)) return;

  snprintf(key, sizeof(key), "country_ip_%s", end);
  value = json_object_get(obj, key);
  if (config.http_local_country && json_is_string(value) && !strlen(json_string_value(value))) {
    json_object_set_new(obj, key, json_string(config.http_local_country));
  }

  snprintf(key, sizeof(key), "asn_ip_%s", end);
  if (local_asn && !json_object_get(obj, key)) {
    json_object_set_new(obj, key, json_integer(local_asn));

    snprintf(key, sizeof(key), "as_org_ip_%s", end);
    if (config.http_local_as_org && !json_object_get(obj, key)) {
      json_object_set_new(obj, key, json_string(config.http_local_as_org));
    }
  }

  snprintf(key, sizeof(key), "lat_ip_%s", end);
  snprintf(key2, sizeof(key2), "lon_ip_%s", end);
  value = json_object_get(obj, key);
  value2 = json_object_get(obj, key2);
  if (local_coords && json_is_real(value) && json_is_real(value2) && !json_real_value(value) && !json_real_value(value2)) {
    json_object_set_new(obj, key, json_real(local_lat));
    json_object_set_new(obj, key2, json_real(local_lon));
  }
}

/* compose_json_str() with fewer digits for decimal numbers */
static char *p_http_json_str(json_t *obj)
{
  char *str = json_dumps(obj, JSON_PRESERVE_ORDER | JSON_REAL_PRECISION(HTTP_REAL_PRECISION));

  json_decref(obj);

  return str;
}

void http_cache_purge(struct chained_cache *queue[], int index, int safe_action)
{
  char url[LARGEBUFLEN], hdrbuf[LARGEBUFLEN], *topic_esc = NULL;
  int j, stop, qn = 0, ret = SUCCESS, saved_index = index, endpoint_len;
  time_t start, duration;
  pid_t writer_pid = getpid();
  struct dynname_tokens writer_id_tokens;
  struct p_http_batch batch;
  struct curl_slist *headers = NULL;
  CURL *curl = NULL;
#if defined (WITH_GEOIPV2)
  MMDB_s asn_db;
  int asn_db_open = FALSE;
#endif

  memset(&batch, 0, sizeof(batch));

  if (!config.writer_id_string) {
    config.writer_id_string = DYNNAME_DEFAULT_WRITER_ID;
  }

  dynname_tokens_prepare(config.writer_id_string, &writer_id_tokens, DYN_STR_WRITER_ID);

  for (j = 0, stop = 0; (!stop) && P_preprocess_funcs[j]; j++)
    stop = P_preprocess_funcs[j](queue, &index, j);

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - START (PID: %u) ***\n", config.name, config.type, writer_pid);
  start = time(NULL);

  curl = curl_easy_init();
  if (!curl) {
    Log(LOG_ERR, "ERROR ( %s/%s ): curl_easy_init() failed. Exiting ..\n", config.name, config.type);
    exit_gracefully(1);
  }

  /* <http_endpoint>/v1/data/<http_topic> */
  topic_esc = curl_easy_escape(curl, config.sql_table, 0);
  endpoint_len = strlen(config.http_endpoint);
  while (endpoint_len && config.http_endpoint[endpoint_len - 1] == '/') endpoint_len--;

  if (!topic_esc ||
      snprintf(url, sizeof(url), "%.*s%s%s", endpoint_len, config.http_endpoint, HTTP_DATA_PATH, topic_esc) >= sizeof(url)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): unable to compose URL out of 'http_endpoint' and 'http_topic'. Exiting ..\n", config.name, config.type);
    exit_gracefully(1);
  }
  curl_free(topic_esc);

  if (snprintf(hdrbuf, sizeof(hdrbuf), "%s: %s", config.http_apikey_header, config.http_apikey) >= sizeof(hdrbuf)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): 'http_apikey' too long. Exiting ..\n", config.name, config.type);
    exit_gracefully(1);
  }

  headers = curl_slist_append(headers, hdrbuf);
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "Expect:");

  batch.size = config.sql_multi_values;
  batch.buf = malloc(batch.size);

  if (!headers || !batch.buf) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (http_cache_purge). Exiting ..\n", config.name, config.type);
    exit_gracefully(1);
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "pmacct/" PMACCT_VERSION);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) config.http_timeout);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, p_http_discard_cb);

#if defined (WITH_GEOIPV2)
  /* opened at every purge (mmap, cheap): a new version of the file, ie. by
     geoipupdate, is picked up with no reload */
  if (config.http_geoip_asn_file) {
    int status = MMDB_open(config.http_geoip_asn_file, MMDB_MODE_MMAP, &asn_db);

    if (status == MMDB_SUCCESS) asn_db_open = TRUE;
    else Log(LOG_INFO, "INFO ( %s/%s ): 'http_geoip_asn_file' can't be loaded (%s): no AS fields in this purge.\n", config.name, config.type, MMDB_strerror(status));
  }
#endif

  if (config.print_markers) {
    void *json_obj = NULL;
    char *json_str = NULL;

    json_obj = compose_purge_init_json(config.name, writer_pid);

    if (json_obj) json_str = p_http_json_str(json_obj);
    if (json_str) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_str);
      ret = p_http_produce(curl, url, &batch, json_str, NULL, FALSE);

      free(json_str);
      json_str = NULL;
    }
  }

  for (j = 0; j < index && !ret; j++) {
    json_t *json_obj = NULL;
    char *json_str = NULL;
    int idx;

    if (queue[j]->valid != PRINT_CACHE_COMMITTED) continue;

    json_obj = json_object();

    for (idx = 0; idx < N_PRIMITIVES && cjhandler[idx]; idx++) cjhandler[idx](json_obj, queue[j]);
    add_writer_name_and_pid_json(json_obj, &writer_id_tokens);

    /* time of the aggregate, in seconds since the epoch: the start of its time
       bin (http_history) or, without time bins, the start of the purge */
    if (config.http_timestamp_field) {
      time_t stamp = queue[j]->basetime.tv_sec ? queue[j]->basetime.tv_sec : start;

      json_object_set_new_nocheck(json_obj, config.http_timestamp_field, json_integer((json_int_t) stamp));
    }

    if (config.http_event_source) {
      json_object_set_new_nocheck(json_obj, "event_source", json_string(config.http_event_source));
    }

    /* replaces "purge"; purge_init / purge_close markers keep theirs */
    if (config.http_event_type) {
      p_http_override(json_obj, "event_type", json_string(config.http_event_type));
    }

    /* "label": {"k1": "v1", ..} becomes "k1": "v1", ..; keys never override
       fields already there */
    if (config.http_label_flatten) {
      json_t *label = json_object_get(json_obj, "label");

      if (json_is_object(label)) {
        json_object_update_missing(json_obj, label);
        json_object_del(json_obj, "label");
      }
    }

    /* nDPI "class": "<master>/<app>", ie. "QUIC/YouTube", split in two fields;
       with no master ("Unknown/DNS") the protocol is the app one */
    if (config.http_class_split) {
      json_t *class = json_object_get(json_obj, "class");

      if (json_is_string(class)) {
        const char *str = json_string_value(class), *app = strchr(str, '/');
        char master[SRVBUFLEN];

        if (app) {
          snprintf(master, sizeof(master), "%.*s", (int) (app - str), str);
          app++;
        }
        else {
          master[0] = '\0';
          app = str;
        }

        p_http_override(json_obj, "l7_protocol", json_string((master[0] && strcasecmp(master, "Unknown")) ? master : app));
        p_http_override(json_obj, "application", json_string(app));
      }
    }

#if defined (WITH_NDPI)
    /* what else nDPI knows about the class: its category and, out of the
       addresses alone, who the traffic belongs to */
    if (config.http_class_details && (config.what_to_count_2 & COUNT_NDPI_CLASS)) {
      pm_class2_t *ndpi_class = &queue[j]->primitives.ndpi_class;

      p_http_override(json_obj, "application_category", json_string(ndpi_category_get_name(pm_ndpi_wfl->ndpi_struct, ndpi_class->category)));
      p_http_override(json_obj, "ip_owner", json_string(ndpi_get_proto_name(pm_ndpi_wfl->ndpi_struct, ndpi_class->protocol_by_ip)));
    }
#endif

#if defined (WITH_GEOIPV2)
    if (asn_db_open) {
      if (config.what_to_count & COUNT_SRC_HOST) p_http_geoip_asn(json_obj, &asn_db, &queue[j]->primitives.src_ip, "src");
      if (config.what_to_count & COUNT_DST_HOST) p_http_geoip_asn(json_obj, &asn_db, &queue[j]->primitives.dst_ip, "dst");
    }
#endif

    if (local_nets_num) {
      if (config.what_to_count & COUNT_SRC_HOST) p_http_local_geo(json_obj, &queue[j]->primitives.src_ip, "src");
      if (config.what_to_count & COUNT_DST_HOST) p_http_local_geo(json_obj, &queue[j]->primitives.dst_ip, "dst");
    }

    json_str = p_http_json_str(json_obj);

    if (json_str) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_str);
      ret = p_http_produce(curl, url, &batch, json_str, &qn, TRUE);

      free(json_str);
      json_str = NULL;
    }
  }

  /* upon a failed delivery what is left of the queue is dropped: the endpoint
     is likely down and retrying every single batch would stall the writer */
  if (!ret) ret = p_http_flush(curl, url, &batch, &qn);

  duration = time(NULL)-start;

  if (config.print_markers && !ret) {
    void *json_obj = NULL;
    char *json_str = NULL;

    json_obj = compose_purge_close_json(config.name, writer_pid, qn, saved_index, duration);

    if (json_obj) json_str = p_http_json_str(json_obj);
    if (json_str) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_str);
      p_http_post(curl, url, json_str, strlen(json_str), 1);

      free(json_str);
      json_str = NULL;
    }
  }

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

#if defined (WITH_GEOIPV2)
  if (asn_db_open) MMDB_close(&asn_db);
#endif

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - END (PID: %u, QN: %u/%u, ET: %lu) ***\n",
		config.name, config.type, writer_pid, qn, saved_index, duration);

  if (config.sql_trigger_exec && !safe_action) P_trigger_exec(config.sql_trigger_exec);

  if (batch.buf) free(batch.buf);
}
