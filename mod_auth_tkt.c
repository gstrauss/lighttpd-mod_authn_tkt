/* 
   mod_auth_tkt - a cookie-based authentification for Lighttpd

   author: Mars Agliullin griph <at> mail <dot> ru
   based on: mod_auth_tkt by Gavin Carr with contributors 
	     (see http://www.openfusion.com.au/labs/mod_auth_tkt),
   license: BSD 
 */ 
#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "base.h"
#include "buffer.h"
#include "plugin.h"
#include "http_auth.h"
#include "log.h"
#include "response.h"
#include "http_auth_digest.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef USE_OPENSSL
# include <openssl/md5.h>
#else
# include "md5.h"
#endif

/* Default settings */
#define AUTH_COOKIE_NAME "auth_tkt"
#define BACK_ARG_NAME "back"
#define MD5_DIGEST_SZ 32
#define MD5andTSTAMP (MD5_DIGEST_SZ + 8)
#define SEPARATOR '!'
#define SEPARATOR_HEX "%21"
#define REMOTE_USER_ENV "REMOTE_USER"
#define REMOTE_USER_DATA_ENV "REMOTE_USER_DATA"
#define REMOTE_USER_TOKENS_ENV "REMOTE_USER_TOKENS"
#define DEFAULT_TIMEOUT_SEC 7200
#define DEFAULT_GUEST_USER "guest"

#define FORCE_REFRESH 1
#define CHECK_REFRESH 0

typedef struct {
	array  *auth_require;

	buffer *auth_secret;
	buffer *auth_login_url;
	buffer *auth_timeout_url;
	buffer *auth_post_timeout_url;
	buffer *auth_unauth_url;

	buffer *auth_guest_user;
	buffer *auth_timeout_conf;
	buffer *auth_timeout_refresh_conf;
	buffer *auth_cookie_name;
	buffer *auth_domain;
	buffer *auth_cookie_expires_conf;
	buffer *auth_back_arg_name;
	buffer *auth_back_cookie_name;

	short auth_guest_login;
	short auth_guest_cookie;
	short auth_ignore_ip;
	short auth_require_ssl;
	short auth_cookie_secure;

	short auth_debug;

	/* induced elements */
	int auth_timeout;
	double auth_timeout_refresh;
	int auth_cookie_expires;
} mod_auth_tkt_plugin_config;


typedef struct {
	PLUGIN_DATA;    

	mod_auth_tkt_plugin_config **config_storage;
	
	mod_auth_tkt_plugin_config conf; /* this is only used as long as no handler_ctx is setup */
} mod_auth_tkt_plugin_data;


typedef struct auth_tkt_struct {
	buffer *uid;
	buffer *tokens;
	buffer *user_data;
	time_t timestamp;
} auth_tkt;


INIT_FUNC(mod_auth_tkt_init) /*{{{*/
{
	mod_auth_tkt_plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	return p;
}/*}}}*/

FREE_FUNC(mod_auth_tkt_free) /*{{{*/
{
	mod_auth_tkt_plugin_data *p = p_d;
	
	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;
	
	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			mod_auth_tkt_plugin_config *s = p->config_storage[i];
			
			if (!s) continue;
			
			array_free(s->auth_require);
			buffer_free(s->auth_secret);
			buffer_free(s->auth_login_url);
			buffer_free(s->auth_timeout_url);
			buffer_free(s->auth_post_timeout_url);
			buffer_free(s->auth_unauth_url);

			buffer_free(s->auth_guest_user);
			buffer_free(s->auth_timeout_conf);
			buffer_free(s->auth_timeout_refresh_conf);
			buffer_free(s->auth_cookie_name);
			buffer_free(s->auth_domain);
			buffer_free(s->auth_cookie_expires_conf);
			buffer_free(s->auth_back_arg_name);
			buffer_free(s->auth_back_cookie_name);
			
			free(s);
		}
		free(p->config_storage);
	}
	
	free(p);
	
	return HANDLER_GO_ON;
}/*}}}*/

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_auth_tkt_patch_connection(server *srv, connection *con, mod_auth_tkt_plugin_data *p) /*{{{*/
{
	size_t i, j;
	mod_auth_tkt_plugin_config *s = p->config_storage[0];

	PATCH(auth_require);
	PATCH(auth_secret);
	PATCH(auth_login_url);
	PATCH(auth_timeout_url);
	PATCH(auth_post_timeout_url);
	PATCH(auth_unauth_url);
	PATCH(auth_guest_user);
	PATCH(auth_cookie_name);
	PATCH(auth_domain);
	PATCH(auth_back_arg_name);
	PATCH(auth_back_cookie_name);
	PATCH(auth_guest_login);
	PATCH(auth_guest_cookie);
	PATCH(auth_ignore_ip);
	PATCH(auth_require_ssl);
	PATCH(auth_cookie_secure);
	PATCH(auth_debug);
	PATCH(auth_timeout);
	PATCH(auth_timeout_refresh);
	PATCH(auth_cookie_expires);
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.require"))) {
				PATCH(auth_require);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.secret"))) {
				PATCH(auth_secret);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.login_url"))) {
				PATCH(auth_login_url);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.timeout_url"))) {
				PATCH(auth_timeout_url);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.post_timeout_url"))) {
				PATCH(auth_post_timeout_url);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.unauth_url"))) {
				PATCH(auth_unauth_url);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.guest_user"))) {
				PATCH(auth_guest_user);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.cookie_name"))) {
				PATCH(auth_cookie_name);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.domain"))) {
				PATCH(auth_domain);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.back_arg_name"))) {
				PATCH(auth_back_arg_name);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.back_cookie_name"))) {
				PATCH(auth_back_cookie_name);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.guest_login"))) {
				PATCH(auth_guest_login);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.guest_cookie"))) {
				PATCH(auth_guest_cookie);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.ignore_ip"))) {
				PATCH(auth_ignore_ip);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.require_ssl"))) {
				PATCH(auth_require_ssl);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.cookie_secure"))) {
				PATCH(auth_cookie_secure);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.debug"))) {
				PATCH(auth_debug);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.timeout"))) {
				PATCH(auth_timeout);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.timeout_refresh"))) {
				PATCH(auth_timeout_refresh);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth_tkt.cookie_expires"))) {
				PATCH(auth_cookie_expires);
			}
		}
	}
	
	return 0;
}/*}}}*/
#undef PATCH

static const char base64_pad = '=';

static const char base64_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const short base64_reverse_table[256] = {
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
                -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
                15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
                -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

static int buffer_base64_encode(buffer *buf_in, buffer *buf_out)/*{{{*/
{
    char *in = buf_in->ptr, *out;
    int len = buf_in->used;
    buffer_prepare_copy(buf_out, len*4/3 + 6);
    out = buf_out->ptr;

    for (; len >= 3; len -= 3)
    {
        *out++ = base64_table[in[0] >> 2];
        *out++ = base64_table[((in[0] << 4) & 0x30) | (in[1] >> 4)];
        *out++ = base64_table[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
        *out++ = base64_table[in[2] & 0x3f];
        in += 3;
    }
    if (len > 0)
    {
        unsigned char fragment;
    
        *out++ = base64_table[in[0] >> 2];
        fragment = (in[0] << 4) & 0x30;
        if (len > 1)
            fragment |= in[1] >> 4;
        *out++ = base64_table[fragment];
        *out++ = (len < 2) ? '=' : base64_table[(in[1] << 2) & 0x3c];
        *out++ = '=';
    }
    *out++ = '\0';
    buf_out->used = out - buf_out->ptr;

    return 0;
}/*}}}*/

static int buffer_base64_decode(buffer *b) {/*{{{*/
        const char *src;
        char *dst;
    
        int ch;
        size_t i;
        
	if (!b || !b->ptr) return -1;

        src = (const char*) b->ptr;
        dst = (char*) b->ptr;

        ch = *src;
        /* run through the whole string, converting as we proceed */
	for (i = 0; (*src) != '\0'; i++, src++) {
	    ch = *src;

	    if (ch == base64_pad) break;

	    ch = base64_reverse_table[ch];
	    if (ch < 0) continue;

	    switch(i & 0x3) {
	    case 0:
		    *dst = ch << 2;
		    break;
	    case 1:
		    *dst++ |= ch >> 4;
		    *dst = (ch & 0x0f) << 4;
		    break;
	    case 2:
		    *dst++ |= ch >> 2;
		    *dst = (ch & 0x03) << 6;
		    break;
	    case 3:
		    *dst++ |= ch;
		    break;
	    }
	}
        /* mop things up if we ended on a boundary */
        if (ch == base64_pad) {
                switch(i & 0x3) {
                case 0:
                case 1:
                        return -1;
                case 2:
                        dst++;
                case 3:
			*dst++ = '\0';
                }
        }
        *dst = '\0';
        b->used = (dst - b->ptr) + 1;
	return 0;
}/*}}}*/

/* Send an auth cookie with the given value */
static void send_auth_cookie(server *srv, connection *con, mod_auth_tkt_plugin_config *cfg, const char *cookie_name, buffer *value)/*{{{*/
{
    data_string *ds;
    buffer *cookie;
    buffer *domain = buffer_is_empty(cfg->auth_domain) ? con->server_name : cfg->auth_domain;
    char exp_date[256];
    time_t now = time(NULL);

    if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
	    ds = data_response_init();
    }
    buffer_copy_string(ds->key, "Set-Cookie");
    cookie = ds->value;

    buffer_copy_string(cookie, cookie_name);
    buffer_append_string(cookie, "=");
    buffer_append_string_buffer(cookie, value);
    buffer_append_string(cookie, "; path=/");
    if (domain->used) {
	buffer_append_string(cookie, "; domain=");
	buffer_append_string_encoded(cookie, CONST_BUF_LEN(domain), ENCODING_REL_URI);
    }
    if (cfg->auth_cookie_expires > 0) {
	now += cfg->auth_cookie_expires;
	strftime(exp_date, 255, "%a, %d %b %Y %H:%M:%S +0000", gmtime(&now));
	buffer_append_string(cookie, "; expires=");
	buffer_append_string(cookie, exp_date);
    }
    if (cfg->auth_cookie_secure > 0) {
	buffer_append_string(cookie, "; secure");
    }
    if (cfg->auth_debug) {
	log_error_write(srv, __FILE__, __LINE__, "b", cookie);
    }
    array_insert_unique(con->response.headers, (data_unset *)ds);
}/*}}}*/

/* Parse cookie. Returns 1 if valid, and details in *parsed; 0 if not */
static int parse_ticket(server *srv, mod_auth_tkt_plugin_config *cfg, buffer *ticket, auth_tkt *parsed)/*{{{*/
{
	char *tkt = ticket->ptr, *sep, *sep2;
	int len = ticket->used;
  
	/* Basic length check for min size */
	if (len <= MD5andTSTAMP) return 0; 

	/* See if there is a uid/data separator */
	sep = strchr(tkt, SEPARATOR);
	if (NULL == sep) {	
	    /* Ticket either uri-escaped, base64-escaped, or bogus */
	    if (strstr(tkt, SEPARATOR_HEX)) {
		if (cfg->auth_debug) {
		    log_error_write(srv, __FILE__, __LINE__, "s", 
				"mod_auth_tkt: url encoded ticket");
		}
		buffer_urldecode_path(ticket);
		sep = strchr(tkt, SEPARATOR);
	    } else {
		if (cfg->auth_debug) {
		    log_error_write(srv, __FILE__, __LINE__, "s", 
				"mod_auth_tkt: base64 encoded ticket");
		}
		/* base64 encoded string always longer than original, 
		   so len+1 is sufficient */
		buffer_base64_decode(ticket);
		sep = strchr(tkt, SEPARATOR);
		/* If still no separator, must be bogus */
		if (NULL == sep) return 0;
	    }
	    /* Reset len */
	    len = ticket->used;
	}

	/* Recheck length */
	if (len <= MD5andTSTAMP || sep-tkt < MD5andTSTAMP) return 0; 

	if (cfg->auth_debug) {
	    log_error_write(srv, __FILE__, __LINE__, "ss", 
		    "mod_auth_tkt: parse_ticket decoded ticket", tkt);
	}

	/* Get user id */
	len = sep - tkt - MD5andTSTAMP;
	buffer_copy_string_len(parsed->uid, tkt + MD5andTSTAMP, len);
	if (cfg->auth_debug) {
	    log_error_write(srv, __FILE__, __LINE__, "b", parsed->uid);
	}

	/* Check for tokens */
	sep2 = strchr(sep+1, SEPARATOR);
	if (NULL == sep2) {
		if (cfg->auth_debug) {
			log_error_write(srv, __FILE__, __LINE__, "s", 
					"mod_auth_tkt: ticket has no tokens");
		}
	} else {
		/* Copy tokens to parsed->tokens */
		buffer_copy_string_len(parsed->tokens, sep+1, sep2-sep-1);
		if (cfg->auth_debug) {
			log_error_write(srv, __FILE__, __LINE__, "sb", 
			    "mod_auth_tkt: parse_ticket tokens - ", parsed->tokens);
		}
		sep = sep2;
	}

	/* Copy user data to parsed->user_data */
	buffer_copy_string(parsed->user_data, sep+1);

	/* Copy timestamp to parsed->timestamp */
	sscanf(tkt+MD5_DIGEST_SZ, "%8x", &(parsed->timestamp));

	return 1;
}/*}}}*/


/* Search cookie headers for our ticket */
static int cookie_match(server *srv, const mod_auth_tkt_plugin_config *cfg, 
	const buffer *cookie, const char *cookie_name, const int cookie_name_len, buffer *result)/*{{{*/
{
    char *start, *end;

    if (cfg->auth_debug) {
	    log_error_write(srv, __FILE__, __LINE__, "sssb",
		    "mod_auth_tkt: cookie_match, key", cookie_name, 
		    "against", cookie);
    }

    start = cookie->ptr;
    while ((start = strstr(start, cookie_name))) {
	    start += cookie_name_len;
	    if (*start != '=') continue;
	    start++;
	    /* Cookie includes our cookie_name - copy (first) value into result */
	    end = strchr(start, ';');

	    /* For some reason (some clients?), tickets sometimes come in quoted */
	    if (*start == '"') start++;

	    if (end) {
		    /* end points at ';' we will not copy it! */
		    if (end[-1] == '"') end--;
		    buffer_copy_string_len(result, start, end-start);
	    } else {
		    if (cookie->ptr[cookie->used-1] == '"') {
			    end = &(cookie->ptr[cookie->used-1]);
			    /* don't copy quote */
			    buffer_copy_string_len(result, start, end-start);
		    } else {
			    buffer_copy_string(result, start);
		    }
	    }
	    /* Skip empty cookies (such as with misconfigured logoffs) */
	    if (!buffer_is_empty(result)) {
		    if (cfg->auth_debug) {
			    log_error_write(srv, __FILE__, __LINE__, "sb", 
					    "mod_auth_tkt: cookie_match found ", result);
		    }
		    return 1;
	    }
    }

    if (cfg->auth_debug) {
      log_error_write(srv, __FILE__, __LINE__, "s",
		      "mod_auth_tkt: match NOT found");
    }
    return 0;
}/*}}}*/

/* Strip specified query args from a url */
static buffer *query_strip(buffer *query, buffer *strip)/*{{{*/
{
	buffer *new_args = buffer_init_buffer(query);
	char *b, *e;

	assert(new_args);
	if (buffer_is_empty(new_args)) return new_args;

#if 0
	b = new_args->ptr;
	/* Convert all '&' to ';' */
	while ((b = strchr(b, '&'))) 
		*b = ';';
#endif

	b = new_args->ptr;
	while (1) {
		/* inv: b points to the key */
		e = strchr(b, '=');
		if (NULL == e) break;

		if (e - b == strip->used && 0 == strncmp(b, strip->ptr, strip->used-1)) {
			/* strip this key-value pair */
			e = strchr(e+1, '&');
			if (e) {
				e++;
				/* shift query tail towards the beginnig thus overwriting the pair */
				memmove(b, e, new_args->used - (e - new_args->ptr));
				new_args->used -= e - b;
			} else {
				if (b == new_args->ptr) {
					buffer_reset(new_args);
				} else {
					*(b-1) = '\0';
					new_args->used = b - new_args->ptr - 1;
				}
				break;
			}
		} else {
			/* go to the next pair */
			b = strchr(e+1, '&');
			if (b) b++;
			else break;
		}
	}
	return new_args;
}/*}}}*/

/* External redirect to the given url, setting back cookie or arg */
static void redirect(server *srv, connection *con, mod_auth_tkt_plugin_config *cfg, buffer *location)/*{{{*/
{
	buffer *domain = buffer_is_empty(cfg->auth_domain) ? con->server_name : cfg->auth_domain;
	buffer *back_cookie_name = cfg->auth_back_cookie_name;
	buffer *back_arg_name = cfg->auth_back_arg_name;
	buffer *url, *cookie, *back;
	data_string *ds = NULL;
	buffer *hostinfo; 
	unsigned short port;
	int free_hostinfo = 0, free_url = 0;
	char buf[8];

	/* Get the scheme we use (http or https) */
	buffer *scheme = con->uri.scheme;

	/* Strip any auth_cookie_name arguments from the current args */
	buffer *query = query_strip(con->uri.query, cfg->auth_cookie_name);

	/* Build back URL */
	/* Use Host header for host:port info if available */
	ds = (data_string *)array_get_element(con->request.headers, "Host");
	if (ds && !buffer_is_empty(ds->value)) {
		hostinfo = ds->value;
	} else {
		/* Fallback to using configured hostname and the server port. This usually
		works, but behind a reverse proxy the port may well be wrong. 
		On the other hand, it's really the proxy's problem, not ours.  */
		if (cfg->auth_debug) {
		    log_error_write(srv, __FILE__, __LINE__, "s",
				    "mod_auth_tkt: could not find Host header, falling back to hostname/server port");
		}
		port = srv->srvconf.port;
		if (port == (con->conf.is_ssl ? 443 : 80)) {
			hostinfo = con->server_name;
		} else {
			hostinfo = buffer_init_buffer(con->server_name);
			sprintf(buf, ":%u", port);
			buffer_append_string(hostinfo, buf);
			free_hostinfo = 1;
		}
	}
	back = buffer_init_buffer(scheme);
	buffer_append_string(back, "://");
	buffer_append_string_encoded(back, hostinfo->ptr, hostinfo->used-1, ENCODING_REL_URI_PART);
	buffer_append_string_encoded(back, con->uri.path->ptr, con->uri.path->used-1, ENCODING_REL_URI_PART);
	if (query->used) {
	    buffer_append_string(back, "?");
	    buffer_append_string_encoded(back, query->ptr, query->used-1, ENCODING_REL_URI_PART);
	}

	if (cfg->auth_debug >= 1) {
		log_error_write(srv, __FILE__, __LINE__, "sb", 
				"mod_auth_tkt: back url ", back);
	}
  
	if (buffer_is_empty(back_cookie_name)) {
		/* If back_cookie_name not set, add a back url argument to url */
		char *sep = strchr(location->ptr, '?') ? ";" : "?";
		url = buffer_init_buffer(location);
		buffer_append_string(url, sep);
		buffer_append_string_buffer(url, back_arg_name);
		buffer_append_string(url, "=");
		buffer_append_string_buffer(url, back);
		free_url = 1;
	} else {
		if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
			ds = data_response_init();
		}
		buffer_copy_string(ds->key, "Set-Cookie");
		cookie = ds->value;
		buffer_copy_string_buffer(cookie, back_cookie_name);
		buffer_append_string(cookie, "=");
		buffer_append_string_buffer(cookie, back);

		if (buffer_is_empty(domain)) {
		    buffer_append_string(cookie, "; path=/");
		} else {
		    buffer_append_string(cookie, "; path=/; domain=");
		    buffer_append_string_buffer(cookie, domain);
		}
		array_insert_unique(con->response.headers, (data_unset *)ds);
		url = location;
	}

	if (cfg->auth_debug >= 2) {
		log_error_write(srv, __FILE__, __LINE__, "sb",
				"mod_auth_tkt: redirect ", url);
	}

	response_header_insert(srv, con, CONST_STR_LEN("Location"), CONST_BUF_LEN(url));

	con->http_status = 302;
	con->file_finished = 1;

	if (free_hostinfo) buffer_free(hostinfo);
	if (free_url) buffer_free(url);
	buffer_free(query);
}/*}}}*/

#if 0
/* Look for an url ticket */
static char *get_url_ticket(server *srv, buffer *query)/*{{{*/
{
	char *ticket = NULL;

	/* TODO */

  return ticket;
}
#endif

static void init_auth_rec(auth_tkt *r)/*{{{*/
{
	r->uid = buffer_init();
	r->tokens = buffer_init();
	r->user_data = buffer_init();
	r->timestamp = 0;
}/*}}}*/

static void free_auth_rec(auth_tkt *r) /*{{{*/
{
	buffer_free(r->uid);
	buffer_free(r->tokens);
	buffer_free(r->user_data);
}/*}}}*/

/* Generate a ticket digest string from the given details */
/* return 0 on error, 1 if OK */
static int ticket_digest(server *srv, connection *con,
	mod_auth_tkt_plugin_config *cfg, auth_tkt *parsed, 
	unsigned int timestamp, char *digest)/*{{{*/
{
    buffer *secret = cfg->auth_secret;
    buffer *uid = parsed->uid;
    buffer *tokens = parsed->tokens;
    buffer *user_data = parsed->user_data;

    buffer *remote_ip;
    unsigned long ip;
    HASH Hash;
    MD5_CTX Md5Ctx;    

    /* TODO: IPv6 support */
    ip = con->dst_addr.ipv4.sin_addr.s_addr;
    if (ip == INADDR_NONE) return 0;

    if (timestamp == 0) timestamp = parsed->timestamp;

    remote_ip = cfg->auth_ignore_ip > 0 
			    ? buffer_init_string("0.0.0.0")
			    : buffer_init_buffer(con->dst_addr_buf);

#if 0
    if (cfg->auth_debug) {
	log_error_write(srv, __FILE__, __LINE__, "sbsbsd",
	    "TKT ticket_digest: using md5 key", secret, "ip", remote_ip, "ts", timestamp);
    }
#endif

    /* Generate the initial digest */
    MD5_Init(&Md5Ctx);
    MD5_Update(&Md5Ctx, (unsigned char *)&ip, sizeof(ip));
    timestamp = htonl(timestamp);
    MD5_Update(&Md5Ctx, (unsigned char *)&timestamp, sizeof(timestamp));
    MD5_Update(&Md5Ctx, (unsigned char *)secret->ptr, secret->used - 1);
    MD5_Update(&Md5Ctx, (unsigned char *)uid->ptr, uid->used); /* terminating NUL included */
    if (0 == tokens->used)
	MD5_Update(&Md5Ctx, (unsigned char *)"", 1);
    else
	MD5_Update(&Md5Ctx, (unsigned char *)tokens->ptr, tokens->used); /* terminating NUL included */
    if (user_data->used) {
	MD5_Update(&Md5Ctx, (unsigned char *)user_data->ptr, user_data->used - 1);
    }
    MD5_Final(Hash, &Md5Ctx);
    CvtHex(Hash, digest);

    if (cfg->auth_debug) {
	log_error_write(srv, __FILE__, __LINE__, "ss", 
		"TKT ticket_digest: digest0:", digest);
    }

    /* Generate the second digest */
    MD5_Init(&Md5Ctx);
    MD5_Update(&Md5Ctx, (unsigned char *)digest, MD5_DIGEST_SZ);
    MD5_Update(&Md5Ctx, (unsigned char *)secret->ptr, secret->used - 1);
    MD5_Final(Hash, &Md5Ctx);
    CvtHex(Hash, digest);

    if (cfg->auth_debug) {
	log_error_write(srv, __FILE__, __LINE__, "ss", 
		"TKT ticket_digest: digest:", digest);
    }

    buffer_free(remote_ip);

    return 1;
}/*}}}*/

/* Check for required user
 * Returns 1 on success, 0 on failure */
static int match_users(server *srv, mod_auth_tkt_plugin_config *cfg, array *requsers, buffer *user)/*{{{*/
{
    int i;
    buffer *cur;

    if (requsers->used == 0) {
	/* valid-user */
	return 1;
    }
    for (i = 0; i < requsers->used; i++) {
	cur = ((data_string *)requsers->data[i])->value;
	if (buffer_is_equal(cur, user)) return 1;
    }
    return 0;
}/*}}}*/

/* Check for required auth tokens 
 * Returns 1 on success, 0 on failure */
static int match_tokens(server *srv, mod_auth_tkt_plugin_config *cfg, array *reqtokens, buffer *tokens)/*{{{*/
{
    char *tok = tokens->ptr, *delim = NULL;
    int match = 0; 
    int i, len;

    /* Failure if required and no user tokens found */
    if (tokens->used == 0) return 0;

    do {
	delim = strchr(tok, ',');
	if (delim) {
	    len = delim-tok;
	} else {
	    len = strlen(tok);
	}
	for (i = 0; i < reqtokens->used; i++) {
	    buffer *reqtok = ((data_string *)reqtokens->data[i])->value;
	    if (buffer_is_equal_string(reqtok, tok, len)) {
		match = 1;
		break;
	    }
	}
	if (match) break;
	if (delim) tok = delim+1;
    } while (delim);

    if (cfg->auth_debug && match == 0) {
      log_error_write(srv, __FILE__, __LINE__, "sb", 
	      "mod_auth_tkt: no matching tokens! User tokens:", tokens);
    }

    return match;
}/*}}}*/

/* Refresh the auth cookie if timeout refresh is set */
static void refresh_cookie(server *srv, connection *con,
	mod_auth_tkt_plugin_config *cfg, auth_tkt *parsed, 
	const char *cookie_name, unsigned int timeout, int force_flag)/*{{{*/
{
    /* The timeout refresh is a double between 0 and 1, signifying what
    * proportion of the timeout should be left before we refresh i.e. 
    * 0 means never refresh (hard timeouts); 1 means always refresh;
    * .33 means only refresh if less than a third of the timeout 
    * period remains. */ 
    unsigned int now = time(NULL);
    int remainder = parsed->timestamp + timeout - now;
    double refresh_sec = cfg->auth_timeout_refresh * timeout;

    if (cfg->auth_debug >= 1) {
	char buf[1024];
	sprintf(buf, "mod_auth_tkt: timeout %u, refresh %f, remainder %d, refresh_sec, %f", 
		timeout, cfg->auth_timeout_refresh, remainder, refresh_sec);
	log_error_write(srv, __FILE__, __LINE__, "s", buf);
    }

    /* If less than our refresh_sec treshold, refresh the cookie */
    if (force_flag || remainder < refresh_sec) {
	char digest[MD5_DIGEST_SZ+1];
	char sep = SEPARATOR;
	buffer *ticket, *ticket_base64 = buffer_init();

	ticket_digest(srv, con, cfg, parsed, now, digest);
	ticket = buffer_init_string(digest);
	sprintf(digest, "%08x", now);
	buffer_append_string(ticket, digest);
	buffer_append_string_buffer(ticket, parsed->uid);
	buffer_append_string_len(ticket, &sep, 1);
	if (parsed->tokens->used > 0) {
	    buffer_append_string_buffer(ticket, parsed->tokens);
	    buffer_append_string_len(ticket, &sep, 1);
	}
	buffer_append_string_buffer(ticket, parsed->user_data);

	buffer_base64_encode(ticket, ticket_base64);
	if (cfg->auth_debug) {
	    log_error_write(srv, __FILE__, __LINE__, "sbsb",
		    "mod_auth_tkt: refreshing cookie with", ticket, "encoded:", ticket_base64);
	}

	send_auth_cookie(srv, con, cfg, cookie_name, ticket_base64); 
    }
}/*}}}*/
  
/* Check whether the given timestamp has timed out 
 * Returns 1 if OK, 0 if timed out */
static int check_timeout(server *srv, connection *con, 
	mod_auth_tkt_plugin_config *cfg, auth_tkt *parsed,
	char *cookie_name)/*{{{*/
{
    buffer *timeout_cookie;
    time_t now = time(NULL);
    buffer *domain = buffer_is_empty(cfg->auth_domain) ? con->server_name : cfg->auth_domain;
    int timeout;
    data_string *ds;
    
    /* Success if no timeout configured */
    if (cfg->auth_timeout == 0) return 1;

    timeout = cfg->auth_timeout == -1 ? DEFAULT_TIMEOUT_SEC : cfg->auth_timeout;

    /* Check whether timestamp is still fresh */
    if (parsed->timestamp + timeout >= now) {
	if (cfg->auth_debug >= 1) {
	    log_error_write(srv, __FILE__, __LINE__, "sdsdsd",
		    "TKT: cookie timeout still good: now", now, 
		    "timeout:", timeout, "tstamp:", parsed->timestamp);
	}

	/* Check whether to refresh the cookie */
	if (cfg->auth_timeout_refresh > 0) 
	  refresh_cookie(srv, con, cfg, parsed, cookie_name, timeout, CHECK_REFRESH);

	return 1;
    }

    if (cfg->auth_debug >= 1) {
	log_error_write(srv, __FILE__, __LINE__, "sdsdsd",
		"TKT: ticket timed out: now", now, 
		"timeout:", timeout, "timestamp:", parsed->timestamp);

    }

    /* Ticket is invalid. Erase it! */
    if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
	    ds = data_response_init();
    }
    buffer_copy_string(ds->key, "Set-Cookie");
    timeout_cookie = ds->value;
    /* Delete cookie (set expired) if invalid, in case we want to set from url */
    buffer_copy_string(timeout_cookie, cookie_name);
    buffer_append_string(timeout_cookie, "=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT");
    if (domain->used) {
	buffer_append_string(timeout_cookie, "; domain=");
	buffer_append_string_encoded(timeout_cookie, CONST_BUF_LEN(domain), ENCODING_REL_URI);
    }
    if (cfg->auth_cookie_secure > 0) {
	buffer_append_string(timeout_cookie, "; secure");
    }
    array_insert_unique(con->response.headers, (data_unset *)ds);
	
    return 0;
}/*}}}*/

/* Set environment variable for backend (SCGI, FastCGI, ...) */
static void add_to_env(array *env, char *key, buffer *value)/*{{{*/
{
    data_string *ds_dst;

    if (NULL == (ds_dst = (data_string *)array_get_unused_element(env, TYPE_STRING))) {
	ds_dst = data_string_init();
    }

    buffer_copy_string(ds_dst->key, key);
    buffer_copy_string_buffer(ds_dst->value, value);
    array_insert_unique(env, (data_unset *)ds_dst);
}/*}}}*/

/* Main ticket authentication entry point */
URIHANDLER_FUNC(mod_auth_tkt_uri_handler) /*{{{*/
{
	size_t k;
	int auth_required = 0, auth_satisfied = 0;
	buffer *cookie = buffer_init();
	data_string *ds;
	mod_auth_tkt_plugin_data *p = p_d;
	char *cookie_name; 	
	int cookie_name_len;
	array *req;
	int (*fcmp) (char *, char *, int);
	auth_tkt auth_rec;
	int r;
	buffer *redirect_url;
	
	if (buffer_is_empty(con->uri.path)) return HANDLER_GO_ON;

	/* select the right config */
	mod_auth_tkt_patch_connection(srv, con, p);

	if (p->conf.auth_require == NULL) return HANDLER_GO_ON;
	
	/*
	 * AUTH
	 *  
	 */
	
	/* do we have to ask for auth ? */
	
	auth_required = 0;
	auth_satisfied = 0;
	

	/* if we have a case-insensitive FS we have to lower-case the URI here too */
	if (con->conf.force_lowercase_filenames) {
	    fcmp = strncasecmp;
	} else {
	    fcmp = strncmp;
	}
	/* search auth-directives for path */
	for (k = 0; k < p->conf.auth_require->used; k++) {
		buffer *req = p->conf.auth_require->data[k]->key;

		if (req->used == 0) continue;
		if (con->uri.path->used < req->used) continue;

		if (0 == fcmp(con->uri.path->ptr, req->ptr, req->used - 1)) {
			auth_required = 1;
			break;
		}
	}
	
	/* we have nothing to do */
	if (auth_required == 0) return HANDLER_GO_ON;

	/* set default redirect URL */
	redirect_url = p->conf.auth_login_url;

	/* check config */
	/* Module is misconfigured unless secret is set */
	if (buffer_is_empty(p->conf.auth_secret)) {
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"mod_auth_tkt: need secret");
		con->http_status = 500;

		return HANDLER_FINISHED;
	}

	/* Module is not configured unless login_url or guest_login is set */
	if (buffer_is_empty(p->conf.auth_login_url) && (p->conf.auth_guest_login == 0)) {
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"mod_auth_tkt: need either auth_tkt.login_url of auth_tkt.guest_login to be enabled");
		con->http_status = 403;

		return HANDLER_FINISHED;
	}

	/* redirect/login if scheme not "https" and require_ssl is set */
	if (p->conf.auth_require_ssl && con->conf.is_ssl == 0) {
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"mod_auth_tkt: redirect/login - unsecured request, auth_tkt.require_ssl is enabled");

		redirect(srv, con, &(p->conf), redirect_url);
		
		return HANDLER_FINISHED;
	}

	/* Backwards compatibility mode for auth_tkt.require_ssl */
	if (p->conf.auth_require_ssl && (p->conf.auth_cookie_secure == -1)) {
		/* Set secure_cookie flag if require_ssl is set and secure_cookie is 
		   undefined (as opposed to 'off') */
		log_error_write(srv, __FILE__, __LINE__, "ss", 
				"mod_auth_tkt: auth_tkt.require_ssl on, but no auth_tkt.cookie_secure found - ",
				"please set auth_tkt.cookie_secure explicitly, assuming 'enabled'");
		p->conf.auth_cookie_secure = 1;
	}

	/* set default cookie_name if needed */
	if (buffer_is_empty(p->conf.auth_cookie_name)) {
		cookie_name = AUTH_COOKIE_NAME;
		cookie_name_len = sizeof(AUTH_COOKIE_NAME);
	} else {
		cookie_name = p->conf.auth_cookie_name->ptr;
		cookie_name_len = p->conf.auth_cookie_name->used-1;
	}

	/* parameters extracted from the ticket */
	init_auth_rec(&auth_rec);

	/* authentification parameters for this url ("require" & "tickets") */
	req = ((data_array *)(p->conf.auth_require->data[k]))->value;
	
#if 0
	/* TODO */
	/* Check for url ticket - either found (accept) or empty (reset/login) */
	ticket = get_url_ticket(srv, con->uri.query);
#endif

	/* try to get Cookie-header */
	ds = (data_string *)array_get_element(con->request.headers, "Cookie");
	
	if (ds && ds->value && ds->value->used) {
	    if (p->conf.auth_debug) {
		log_error_write(srv, __FILE__, __LINE__, "ssb", "auth", cookie_name, ds->value);
	    }

	    /* cookie is assigned in cookie_match */
	    if (cookie_match(srv, &(p->conf), ds->value, cookie_name, cookie_name_len, cookie) 
		    && (cookie->used >= MD5andTSTAMP)) {
		char digest[MD5_DIGEST_SZ+1];
		data_array *require, *tokens;

		if (!parse_ticket(srv, &(p->conf), cookie, &auth_rec)) {
		    if (p->conf.auth_debug) {
			  log_error_write(srv, __FILE__, __LINE__, "sb",
			    "auth_tkt: unparseable ticket found", cookie);
		    }
		} else {
		    /* ticket syntax OK */
		    if (p->conf.auth_debug) {
			    log_error_write(srv, __FILE__, __LINE__, "sbsbsbsd",
			      "auth_tkt: ticket uid", auth_rec.uid,  
			      "tokens", auth_rec.tokens, 
			      "user_data", auth_rec.user_data, 
			      "timestamp", auth_rec.timestamp);
		    }
		    /* Check ticket hash */
		    ticket_digest(srv, con, &(p->conf), &auth_rec, 0, digest);
		    if (memcmp(cookie->ptr, digest, MD5_DIGEST_SZ) != 0) {
			log_error_write(srv, __FILE__, __LINE__, "sssb",
			       "mod_auth_tkt: ticket found, but hash is invalid - digest",  
			       digest, "ticket", cookie);
		    } else {
			/* ticket valid */
			log_error_write(srv, __FILE__, __LINE__, "ss",
			       "mod_auth_tkt: ticket matched",  digest);

			/* check user */
			require = (data_array *)array_get_element(req, "require");
			/* 'require' is a compulsory configuration parameter,
			 * don't check for its existence */
			if (!match_users(srv, &(p->conf), require->value, auth_rec.uid)) {
			    log_error_write(srv, __FILE__, __LINE__, "sb",
				   "mod_auth_tkt: user NOT matched", auth_rec.uid);
			    redirect_url = buffer_is_empty(p->conf.auth_unauth_url) 
					       ? p->conf.auth_login_url 
					       : p->conf.auth_unauth_url;
			    goto process;
			}
			if (p->conf.auth_debug) {
			    log_error_write(srv, __FILE__, __LINE__, "sb",
				   "mod_auth_tkt: user matched", auth_rec.uid);
			}

			/* check for tokens */
			tokens = (data_array *)array_get_element(req, "tokens");
			if (tokens != NULL && tokens->value->used > 0) {
			    if (!match_tokens(srv, &(p->conf), tokens->value, auth_rec.tokens)) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
				       "mod_auth_tkt: tokens NOT matched", auth_rec.tokens);
				redirect_url = buffer_is_empty(p->conf.auth_unauth_url) 
						   ? p->conf.auth_login_url 
						   : p->conf.auth_unauth_url;
				goto process;
			    } else {
				if (p->conf.auth_debug) {
				    log_error_write(srv, __FILE__, __LINE__, "sb",
					   "mod_auth_tkt: tokens matched", auth_rec.tokens);
				}
			    }
			}
			/* check timeout */
			if (!check_timeout(srv, con, &(p->conf), &auth_rec, cookie_name)) {
			    if (con->request.http_method == HTTP_METHOD_POST 
				    && p->conf.auth_post_timeout_url->used > 0) {
				redirect_url = p->conf.auth_post_timeout_url;
			    } else {
				redirect_url = buffer_is_empty(p->conf.auth_timeout_url) 
						   ? p->conf.auth_login_url 
						   : p->conf.auth_timeout_url;
			    }
			} else {
			    auth_satisfied = 1;
			}
		    }
		}
	    }
	}
process:	
	if (!auth_satisfied) {
	    if (redirect_url && (redirect_url->used > 0)) {
		redirect(srv, con, &(p->conf), redirect_url);
	    } else {
		if (p->conf.auth_debug >= 2) {
		    log_error_write(srv, __FILE__, __LINE__, "s", 
				    "mod_auth_tkt: empty redirect URL");
		}
		con->http_status = 403;
	    }

	    r = HANDLER_FINISHED;
	} else {
	    buffer *auth_type = buffer_init_string("Basic");

	    /* set CGI/FCGI/SCGI environment */
	    if (p->conf.auth_debug) {
		log_error_write(srv, __FILE__, __LINE__, "sb", 
			"user:", auth_rec.uid);
	    }
	    buffer_copy_string_buffer(con->authed_user, auth_rec.uid);

	    add_to_env(con->environment, "REMOTE_USER_DATA", auth_rec.user_data);
	    add_to_env(con->environment, "REMOTE_USER_TOKENS", auth_rec.tokens);
	    add_to_env(con->environment, "AUTH_TYPE", auth_type);
	    buffer_free(auth_type);

	    r = HANDLER_GO_ON;
	}
	free_auth_rec(&auth_rec);
	return r;
}/*}}}*/

/* configuration processing & checking */
static char *convert_to_seconds(buffer *cfg, int *timeout)/*{{{*/
{
	int num, multiplier;
	char unit;

	if (light_isdigit(cfg->ptr[0])) {
		num = atoi(cfg->ptr);
	} else {
		return "bad time string - numeric expected";
	}

	if (*timeout < 0) *timeout = 0;
	multiplier = 1;

	unit = cfg->ptr[cfg->used - 2];
	if (light_isalpha(unit)) {
		if (unit == 's')
			multiplier = 1;
		else if (unit == 'm')
			multiplier = 60;
		else if (unit == 'h')
			multiplier = 60 * 60;
		else if (unit == 'd')
			multiplier = 24 * 60 * 60;
		else if (unit == 'w')
			multiplier = 7 * 24 * 60 * 60;
		else if (unit == 'M')
			multiplier = 30 * 24 * 60 * 60;
		else if (unit == 'y')
			multiplier = 365 * 24 * 60 * 60;
		else {
			return "bad time string - unrecognized unit";
		}
	}

	*timeout += num * multiplier;

	return NULL;
}/*}}}*/

static char *set_auth_tkt_timeout(buffer *cfg, int *timeout)/*{{{*/
{
	char *msg;

	if (light_isdigit(cfg->ptr[0]) && light_isdigit(cfg->ptr[cfg->used - 2])) {
		/* Easy case - looks like all digits */
		*timeout = atoi(cfg->ptr);
	} else {
		/* Harder case - convert units to seconds */
		msg = convert_to_seconds(cfg, timeout);
		if (msg) return msg;
	}

	if (*timeout < 0) {
		return "timeout must be positive";
	}
	if (*timeout == INT_MAX) {
		return "integer overflow or invalid number";
	}
	return NULL;
}/*}}}*/

static char *set_auth_tkt_timeout_refresh(buffer *cfg, double *refresh)/*{{{*/
{
	*refresh = atof(cfg->ptr);

	if (*refresh < 0.0 || *refresh > 1.0) {
		return "refresh flag must be between 0 and 1";
	}
	return NULL;
}/*}}}*/

static int check_tokens(array *tokens)/*{{{*/
{
	size_t i;
	for (i = 0; i < tokens->used; i++) {
		if (tokens->data[i]->type != TYPE_STRING) {
			return i;
		}
	}
	return -1;
}/*}}}*/

SETDEFAULTS_FUNC(mod_auth_tkt_set_defaults) /*{{{*/
{
	mod_auth_tkt_plugin_data *p = p_d;
	size_t i;
	
	config_values_t cv[] = { 
		{ "auth_tkt.secret",                    NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ "auth_tkt.login_url",                 NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.timeout_url",               NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.post_timeout_url",          NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.unauth_url",                NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.guest_login",               NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.guest_cookie",              NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.guest_user",                NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.timeout",                   NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.timeout_refresh",           NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.cookie_name",               NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 10 */
		{ "auth_tkt.domain",                    NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.cookie_expires",            NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.back_arg_name",             NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.back_cookie_name",          NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.ignore_ip",                 NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.require_ssl",               NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.cookie_secure",             NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.require",                   NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },
		{ "auth_tkt.debug",                     NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },  /* 19 */
		{ NULL,                                 NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	assert(p->config_storage);

	for (i = 0; i < srv->config_context->used; i++) {
		mod_auth_tkt_plugin_config *s;
		size_t n;
		data_array *da;
		array *ca;
		char *msg;
		
		s = calloc(1, sizeof(mod_auth_tkt_plugin_config));
		assert(s);

		s->auth_require = array_init();

		s->auth_secret = buffer_init();
		s->auth_login_url = buffer_init();
		s->auth_timeout_url = buffer_init();
		s->auth_post_timeout_url = buffer_init();
		s->auth_unauth_url = buffer_init();
		
		s->auth_guest_user = buffer_init();
		s->auth_timeout_conf = buffer_init();
		s->auth_timeout_refresh_conf = buffer_init();
		s->auth_cookie_name = buffer_init();
		s->auth_domain = buffer_init(); 
		s->auth_cookie_expires_conf = buffer_init();
		s->auth_back_arg_name = buffer_init();
		s->auth_back_cookie_name = buffer_init();

		s->auth_guest_login = 0;
		s->auth_guest_cookie = 0;
		s->auth_ignore_ip = 0;
		s->auth_require_ssl = 0;
		s->auth_cookie_secure = -1;
		s->auth_debug = 0;
		
		cv[0].destination = s->auth_secret;
		cv[1].destination = s->auth_login_url;
		cv[2].destination = s->auth_timeout_url;
		cv[3].destination = s->auth_post_timeout_url;
		cv[4].destination = s->auth_unauth_url;
		cv[5].destination = &(s->auth_guest_login);
		cv[6].destination = &(s->auth_guest_cookie);
		cv[7].destination = s->auth_guest_user;
		cv[8].destination = s->auth_timeout_conf;
 		cv[9].destination = s->auth_timeout_refresh_conf;
 		cv[10].destination = s->auth_cookie_name;
		cv[11].destination = s->auth_domain;
		cv[12].destination = s->auth_cookie_expires_conf;
		cv[13].destination = s->auth_back_arg_name;
		cv[14].destination = s->auth_back_cookie_name;
		cv[15].destination = &(s->auth_ignore_ip);
		cv[16].destination = &(s->auth_require_ssl);
		cv[17].destination = &(s->auth_cookie_secure);
		cv[18].destination = s->auth_require;
		cv[19].destination = &(s->auth_debug);
		
		p->config_storage[i] = s;
		ca = ((data_config *)srv->config_context->data[i])->value;
		
		if (0 != config_insert_values_global(srv, ca, cv)) {
			return HANDLER_ERROR;
		}
		
		/* check scalar config elements */
		if (!buffer_is_empty(s->auth_timeout_conf)) {
			s->auth_timeout = 0;
			msg = set_auth_tkt_timeout(s->auth_timeout_conf, &(s->auth_timeout));
			if (msg) {
				log_error_write(srv, __FILE__, __LINE__, "ss", 
						"mod_auth_tkt: ", msg);
				return HANDLER_ERROR;
			}
		}
		if (!buffer_is_empty(s->auth_timeout_refresh_conf)) {
			msg = set_auth_tkt_timeout_refresh(s->auth_timeout_refresh_conf, &(s->auth_timeout_refresh)); 
			if (msg) {
				log_error_write(srv, __FILE__, __LINE__, "ss", 
						"mod_auth_tkt: ", msg);
				return HANDLER_ERROR;
			}
		}
		s->auth_cookie_expires = 0;
		if (!buffer_is_empty(s->auth_cookie_expires_conf)) {
			msg = set_auth_tkt_timeout(s->auth_cookie_expires_conf, &(s->auth_cookie_expires));
			if (msg) {
				log_error_write(srv, __FILE__, __LINE__, "ss", 
						"mod_auth_tkt: cookie_expires ", msg);
				return HANDLER_ERROR;
			}
		}

		/* no auth_tkt.require for this section */
		if (NULL == (da = (data_array *)array_get_element(ca, "auth_tkt.require"))) continue;
		
		if (da->type != TYPE_ARRAY) {
			log_error_write(srv, __FILE__, __LINE__, "sss", 
					"unexpected type for key: ", "auth_tkt.require", "array of strings");
			
			return HANDLER_ERROR;
		}
		
		/* 
		 * auth_tkt.require = ( "<path>" => ( ... ), 
		 *                      "<path>" => ( ... ) )
		 */
		for (n = 0; n < da->value->used; n++) {
			size_t m;
			data_array *da_path = (data_array *)da->value->data[n];
			char *require_str;
			data_array *require_arr;
			data_array *tokens = NULL;
			data_array *require = NULL;
			
			if (da->value->data[n]->type != TYPE_ARRAY) {
				log_error_write(srv, __FILE__, __LINE__, "ss", 
						"auth_tkt.require should contain an array as in:", 
						"auth_tkt.require = ( \"...\" => ( ..., ...) )");

				return HANDLER_ERROR;
			}
					
			for (m = 0; m < da_path->value->used; m++) {
				if (0 == strcmp(da_path->value->data[m]->key->ptr, "require")) {
				    switch(da_path->value->data[m]->type) {
					case TYPE_STRING:
						require_str = ((data_string *)(da_path->value->data[m]))->value->ptr;
						if (strcmp(require_str, "valid-user") == 0) {
						    /* empty array for any valid user */
						    require = data_array_init();
						    buffer_copy_string(require->key, "require");
						} else {
						    log_error_write(srv, __FILE__, __LINE__, "ss", 
							    "only 'valid-user' string is accepted for require. Use array for list of users:", 
							    "auth_tkt.require = ( \"...\" => ( \"require\" => (\"...\", ...) )");

						    return HANDLER_ERROR;
						}
						break;
					case TYPE_ARRAY:
						require_arr = (data_array *)(da_path->value->data[m]);
						require = (data_array *)require_arr->copy((data_unset *)require_arr);
						break;
					default:
						log_error_write(srv, __FILE__, __LINE__, "ss", 
							"a string was expected for:", 
							"auth_tkt.require = ( \"...\" => ( \"require\" => \"...\", ... )");

						return HANDLER_ERROR;
				    }
				} else if (0 == strcmp(da_path->value->data[m]->key->ptr, "tokens")) {
					if (da_path->value->data[m]->type == TYPE_ARRAY) {
						int pos;
						tokens = (data_array *)(da_path->value->data[m]);
						pos = check_tokens(tokens->value);
						if (pos != -1) {
							log_error_write(srv, __FILE__, __LINE__, "sssd", 
								"a string was expected for:", 
								"auth_tkt.require = ( \"...\" => ( ..., \"tokens\" => (\"...\", \"...\"), ...",
								"at index ", pos);
							return HANDLER_ERROR;
						}
					} else {
						log_error_write(srv, __FILE__, __LINE__, "ss", 
							"an array was expected for:", 
							"auth_tkt.require = ( \"...\" => ( \"tokens\" => \"...\", ... )");

						return HANDLER_ERROR;
					}
				} else {
					log_error_write(srv, __FILE__, __LINE__, "ssbs", 
						"the field is unknown in:", 
						"auth_tkt.require = ( \"...\" => ( ..., -> \"",
						da_path->value->data[m]->key,
						"\" <- => \"...\" ) )");

					return HANDLER_ERROR;
				}
			}
					
			if (require == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "ss", 
						"the require field is missing in:", 
						"auth_tkt.require = ( \"...\" => ( ..., \"require\" => \"...\" ) )");
				return HANDLER_ERROR;
			}
			
			/* setup config */
			{
			    data_array *a;
			    
			    a = data_array_init();
			    buffer_copy_string_buffer(a->key, da_path->key);
			    
			    array_insert_unique(a->value, (data_unset *)require);
			    
			    if (tokens) {
				    array_insert_unique(a->value, (data_unset *)(tokens->copy((data_unset *)tokens)));
			    }
			    array_insert_unique(s->auth_require, (data_unset *)a);
			}
		}
        }

        return HANDLER_GO_ON;
}/*}}}*/

int mod_auth_tkt_plugin_init(plugin *p) /*{{{*/
{
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("auth_tkt");
	p->init        = mod_auth_tkt_init;
	p->set_defaults = mod_auth_tkt_set_defaults;
	p->handle_uri_clean = mod_auth_tkt_uri_handler;
	p->cleanup     = mod_auth_tkt_free;
	
	p->data        = NULL;
	
	return 0;
}/*}}}*/
