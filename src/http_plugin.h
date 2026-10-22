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

#ifndef HTTP_PLUGIN_H
#define HTTP_PLUGIN_H

/* includes */
#include <curl/curl.h>
#include <sys/poll.h>
#include "plugin_common.h"

/* defines */
#define HTTP_DATA_PATH			"/v1/data/"
#define DEFAULT_HTTP_TIMEOUT		10	/* seconds, whole request */
#define DEFAULT_HTTP_RETRIES		3	/* attempts per batch */
#define DEFAULT_HTTP_MULTI_VALUES	131072	/* bytes, batch buffer */
#define HTTP_RETRY_BACKOFF_MS		500

/* structures */
struct p_http_batch {
  char *buf;
  size_t size;
  size_t len;
  int msgs;		/* messages in the batch */
  int acct_msgs;	/* of which, not purge markers */
};

/* prototypes */
extern void p_http_get_version(void);
extern void http_plugin(int, struct configuration *, void *);
extern void http_cache_purge(struct chained_cache *[], int, int);

/* global variables */
extern char default_http_topic[];
extern char default_http_apikey_header[];

#endif //HTTP_PLUGIN_H
