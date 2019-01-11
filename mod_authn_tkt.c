/*
 * mod_authn_tkt - a cookie-based authentification for Lighttpd
 *
 * lighttpd module
 *   Copyright Glenn Strauss gstrauss@gluelogic.com
 *   License: BSD 3-clause + see below
 *
 * based on: mod_auth_tkt by Gavin Carr with contributors
 *           (see http://www.openfusion.com.au/labs/mod_auth_tkt),
 *           https://github.com/gavincarr/mod_auth_tkt
 *           License: Apache License 1.0
 */
#include "first.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base.h"
#include "base64.h"
#include "buffer.h"
#include "md5.h"
#include "http_auth.h"
#include "http_header.h"
#include "log.h"
#include "plugin.h"
#include "rand.h"
#include "response.h"

/* Default settings */
#define AUTH_COOKIE_NAME "auth_tkt"
#define SEPARATOR '!'
#define DEFAULT_TIMEOUT_SEC 7200
#define DEFAULT_GUEST_USER "guest"

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

#ifdef USE_OPENSSL_CRYPTO
#include <openssl/sha.h>
#define MAX_DIGEST_LENGTH SHA512_DIGEST_LENGTH
#else
#define MAX_DIGEST_LENGTH MD5_DIGEST_LENGTH
#endif

#define TIMESTAMP_HEXLEN 8  /*(assumes 32-bit time_t)*/

#define TIME_T_MAX (~((time_t)1 << (sizeof(time_t)*CHAR_BIT-1)))


typedef struct authn_tkt_struct {
	buffer *uid;
	buffer *tokens;
	buffer *user_data;
	buffer *tmp_buf;
	buffer *addr_buf; /* not allocated */
	int refresh_cookie;
	time_t timestamp;
	unsigned int digest_len;
        void (*digest_fn)(struct authn_tkt_struct *, time_t, const buffer *);
	unsigned char digest[MAX_DIGEST_LENGTH];
} authn_tkt;


typedef struct {
	buffer *auth_secret;
	buffer *auth_secret_old;
	buffer *auth_login_url;
	buffer *auth_timeout_url;
	buffer *auth_post_timeout_url;
	buffer *auth_unauth_url;

	buffer *auth_timeout_conf;
	buffer *auth_timeout_refresh_conf;
	buffer *auth_cookie_name;
	buffer *auth_cookie_domain;
	buffer *auth_cookie_expires_conf;
	buffer *auth_back_cookie_name;
	buffer *auth_back_arg_name;
	buffer *auth_digest_type_conf;
	buffer *auth_guest_user;
	array *auth_tokens;

        void (*auth_digest_fn)(struct authn_tkt_struct *,time_t,const buffer *);
	unsigned short auth_digest_len;
	short auth_ignore_ip;
	short auth_cookie_secure;
	short auth_require_ssl;
	short auth_guest_login;
	short auth_guest_cookie;
	short auth_guest_fallback;

	/* generated from user config strings */
	int auth_timeout;
	int auth_timeout_refresh;
	int auth_cookie_expires;
} mod_authn_tkt_plugin_opts;


typedef struct {
	mod_authn_tkt_plugin_opts *auth_opts;
} mod_authn_tkt_plugin_config;


typedef struct {
	PLUGIN_DATA;
	mod_authn_tkt_plugin_config **config_storage;
	mod_authn_tkt_plugin_config conf;
	authn_tkt auth_rec;
} mod_authn_tkt_plugin_data;


static handler_t mod_authn_tkt_check(server *srv, connection *con, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);

INIT_FUNC(mod_authn_tkt_init) /*{{{*/
{
    static http_auth_scheme_t http_auth_scheme_authn_tkt = { "authn_tkt", mod_authn_tkt_check, NULL };

    mod_authn_tkt_plugin_data *p = calloc(1, sizeof(*p));

    /* register http_auth_scheme_* */
    http_auth_scheme_authn_tkt.p_d = p;
    http_auth_scheme_set(&http_auth_scheme_authn_tkt);

    p->auth_rec.uid = buffer_init();
    p->auth_rec.tokens = buffer_init();
    p->auth_rec.user_data = buffer_init();
    p->auth_rec.tmp_buf = buffer_init();
    return p;
}/*}}}*/

FREE_FUNC(mod_authn_tkt_free) /*{{{*/
{
	mod_authn_tkt_plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			mod_authn_tkt_plugin_config *s = p->config_storage[i];

			if (!s) continue;

			if (s->auth_opts) {
				mod_authn_tkt_plugin_opts *o = s->auth_opts;
				buffer_free(o->auth_secret);
				buffer_free(o->auth_secret_old);
				buffer_free(o->auth_login_url);
				buffer_free(o->auth_timeout_url);
				buffer_free(o->auth_post_timeout_url);
				buffer_free(o->auth_unauth_url);
				buffer_free(o->auth_timeout_conf);
				buffer_free(o->auth_timeout_refresh_conf);
				buffer_free(o->auth_digest_type_conf);
				buffer_free(o->auth_cookie_name);
				buffer_free(o->auth_cookie_domain);
				buffer_free(o->auth_cookie_expires_conf);
				buffer_free(o->auth_back_cookie_name);
				buffer_free(o->auth_back_arg_name);
				buffer_free(o->auth_guest_user);
				array_free(o->auth_tokens);
				free(o);
			}

			free(s);
		}
		free(p->config_storage);
	}

	buffer_free(p->auth_rec.uid);
	buffer_free(p->auth_rec.tokens);
	buffer_free(p->auth_rec.user_data);
	buffer_free(p->auth_rec.tmp_buf);

	free(p);

	return HANDLER_GO_ON;
}/*}}}*/

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_authn_tkt_patch_connection(server *srv, connection *con, mod_authn_tkt_plugin_data *p) /*{{{*/
{
	mod_authn_tkt_plugin_config *s = p->config_storage[0];
	PATCH(auth_opts);

	/* skip the first, the global context */
	for (size_t i = 1; i < srv->config_context->used; ++i) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (size_t j = 0; j < dc->value->used; ++j) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.method.tkt.opts"))) {
				PATCH(auth_opts);
			}
		}
	}

	return 0;
}/*}}}*/
#undef PATCH

/* Send an auth cookie with given value; NULL value is flag to expire cookie */
static void send_auth_cookie(connection *con, mod_authn_tkt_plugin_opts *opts, const buffer *cookie_name, const buffer *value, time_t now)/*{{{*/
{
    buffer *cookie;
    buffer *domain;

    http_header_response_insert(con, HTTP_HEADER_SET_COOKIE,
                                CONST_STR_LEN("Set-Cookie"),
                                CONST_BUF_LEN(cookie_name));
    cookie = http_header_response_get(con, HTTP_HEADER_SET_COOKIE,
                                      CONST_STR_LEN("Set-Cookie"));
  #ifdef __COVERITY__
    force_assert(cookie);
  #endif

    if (NULL != value) {
        buffer_append_string_len(cookie, "=", 1);
        buffer_append_string_buffer(cookie, value);
        buffer_append_string_len(cookie, CONST_STR_LEN("; path=/"));
        if (opts->auth_cookie_expires > 0) {
            now = (TIME_T_MAX - now > opts->auth_cookie_expires)
                ? now + opts->auth_cookie_expires
                : TIME_T_MAX;
            buffer_append_string_len(cookie, CONST_STR_LEN("; expires="));
            buffer_append_strftime(cookie, "%a, %d %b %Y %H:%M:%S GMT",
                                   gmtime(&now));
        }
    }
    else {
        buffer_append_string_len(cookie,
          CONST_STR_LEN("=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT"));
    }
    /* (Apache mod_authn_tkt prefers X-Forwarded-Host to Host; not done here) */
    /* XXX: if using con->server_name, do we need to omit :port, if present? */
    domain = buffer_string_is_empty(opts->auth_cookie_domain)
      ? con->server_name
      : opts->auth_cookie_domain;
    if (!buffer_string_is_empty(domain)) {
        buffer_append_string_len(cookie, CONST_STR_LEN("; domain="));
        buffer_append_string_encoded(cookie, CONST_BUF_LEN(domain),
                                     ENCODING_REL_URI);
    }
    if (opts->auth_cookie_secure > 0) {
        buffer_append_string_len(cookie, CONST_STR_LEN("; secure"));
    }
}/*}}}*/

static int digest_hex_to_bin(unsigned char *out, size_t outlen, const char *in, size_t inlen)/*{{{*/
{
    if ((outlen << 1) != inlen) return 0;

    for (size_t i = inlen; i < inlen; i+=2) {
        unsigned char hi = (unsigned char)hex2int(((unsigned char *)in)[i]);
        unsigned char lo = (unsigned char)hex2int(((unsigned char *)in)[i+1]);
        if (hi == 0xFF) return 0; /*(invalid hex encoding)*/
        if (lo == 0xFF) return 0; /*(invalid hex encoding)*/
        out[(i >> 1)] = (hi << 4) | lo;
    }
    return 1;
}/*}}}*/

/* Parse cookie. Returns 1 if valid, and details in *parsed; 0 if not */
static int parse_ticket(authn_tkt *parsed)/*{{{*/
{
    const char *tkt = parsed->tmp_buf->ptr, *sep, *sep2;
    const unsigned int digest_hexlen = (parsed->digest_len << 1);

    /* See if there is a uid/data separator */
    sep = strchr(tkt, SEPARATOR);
    if (NULL == sep) return 0;

    /* Basic length check for min size */
    if (sep - tkt < digest_hexlen + TIMESTAMP_HEXLEN) return 0;

    if (!digest_hex_to_bin(parsed->digest, sizeof(parsed->digest),
                           tkt, digest_hexlen)) {
        return 0; /*(invalid hex encoding)*/
    }

    parsed->timestamp = 0;
    if (!digest_hex_to_bin((unsigned char *)&parsed->timestamp,
                           sizeof(parsed->timestamp),
                           tkt+digest_hexlen,
                           TIMESTAMP_HEXLEN)) {
        return 0; /*(invalid hex encoding in timestamp)*/
    }

    buffer_copy_string_len(parsed->uid,
                           tkt + digest_hexlen + TIMESTAMP_HEXLEN,
                           sep - tkt - (digest_hexlen + TIMESTAMP_HEXLEN));

    sep2 = strchr(sep+1, SEPARATOR);
    if (NULL != sep2) {
        buffer_copy_string_len(parsed->tokens, sep+1, sep2-sep-1);
        sep = sep2;
    }

    /* Copy user data to parsed->user_data */
    ++sep;
    buffer_copy_string_len(parsed->user_data, sep,
                           tkt + buffer_string_length(parsed->tmp_buf) - sep);

    return 1;
}/*}}}*/


/* Search query string for our ticket */
static int authn_tkt_from_querystring(connection *con, mod_authn_tkt_plugin_data *p)/*{{{*/
{
    const buffer * const name = p->conf.auth_opts->auth_cookie_name;
    const size_t nlen = buffer_string_length(name);
    const char *qstr = con->uri.query->ptr;
    if (buffer_string_is_empty(con->uri.query)) return 0;
    for (const char *start=qstr, *amp, *end; *start; start = amp+1) {
        amp = strchr(start+1, '&');
        if (0 != strncmp(start, name->ptr, nlen) || start[nlen] != '=') {
            if (NULL == amp) break;
            continue;
        }

        /* query param includes our name - copy (first) value into result */
        start += nlen + 1;
        end = (NULL != amp)
          ? amp - 1  /* end points at '&' we will not copy it! */
          : qstr + buffer_string_length(con->uri.query);

        /* For some reason (some clients?), tickets sometimes come in quoted */
        if (*start == '"') {
            ++start;
            if (end[-1] == '"') --end;
        }

        /* Skip empty values (such as with misconfigured logoffs) */
        if (end == start) {
            if (NULL == amp) break;
            continue;
        }
        else {
            buffer *result = p->auth_rec.tmp_buf;
            buffer_copy_string_len(result, start, end-start);
            buffer_urldecode_path(result);
            return parse_ticket(&p->auth_rec);
        }
    }
    return 0;
}/*}}}*/

/* Search cookie headers for our ticket */
static int authn_tkt_from_cookie(connection *con, mod_authn_tkt_plugin_data *p)/*{{{*/
{
    const buffer * const name = p->conf.auth_opts->auth_cookie_name;
    const size_t nlen = buffer_string_length(name);
    const buffer * const hdr =
      http_header_request_get(con, HTTP_HEADER_COOKIE, CONST_STR_LEN("Cookie"));
    if (NULL == hdr) return 0;
    for (const char *start=hdr->ptr, *semi, *end; *start; start = semi+1) {
        semi = strchr(start+1, ';');
        if (0 != strncmp(start, name->ptr, nlen) || start[nlen] != '=') {
            if (NULL == semi) break;
            continue;
        }

        /* Cookie includes our cookie name - copy (first) value into result */
        start += nlen + 1;
        end = (NULL != semi)
          ? semi - 1  /* end points at ';' we will not copy it! */
          : hdr->ptr + buffer_string_length(hdr);

        /* For some reason (some clients?), tickets sometimes come in quoted */
        if (*start == '"') {
            ++start;
            if (end[-1] == '"') --end;
        }

        /* Skip empty cookies (such as with misconfigured logoffs) */
        if (end == start) {
            if (NULL == semi) break;
            continue;
        }
        else {
            buffer *result = p->auth_rec.tmp_buf;
            buffer_clear(result);
            buffer_append_base64_decode(result,start,end-start,BASE64_STANDARD);
            return parse_ticket(&p->auth_rec);
        }
    }
    return 0;
}/*}}}*/

#if 1
/* Strip specified query args from a url and append the rest urlencoded */
static void query_append_urlencoded(buffer *b, buffer *q, buffer *omit)/*{{{*/
{
    char sep[] = "?";
    char *qend = q->ptr + buffer_string_length(q);
    for (char *qb = q->ptr, *qe; qb < qend; qb = qe+1) {
        qe = strchr(qb, '=');
        if (NULL == qe || !buffer_is_equal_string(omit, qb, (size_t)(qe-qb))) {
            if (NULL != qe) qe = strchr(qe+1, '&');
            if (NULL == qe) qe = qend;
            buffer_append_string_encoded(b, sep, 1, ENCODING_REL_URI_PART);
            if (*sep == '?') *sep = '&';
            buffer_append_string_encoded(b, qb, (size_t)(qe - qb),
                                         ENCODING_REL_URI_PART);
        }
    }
}/*}}}*/
#endif

static int authn_tkt_construct_back_urlencoded(server *srv, connection *con, buffer *back, buffer *strip_arg)/*{{{*/
{
    buffer_copy_buffer(back, con->uri.scheme);
    buffer_append_string_len(back, CONST_STR_LEN("://"));
    buffer_clear(srv->tmp_buf);
    if (0 != http_response_buffer_append_authority(srv, con, srv->tmp_buf))
        return 0;
    buffer_append_string_encoded(back, CONST_BUF_LEN(srv->tmp_buf),
                                 ENCODING_REL_URI_PART);
    buffer_append_string_encoded(back, CONST_BUF_LEN(con->uri.path),
                                 ENCODING_REL_URI_PART);
    if (!buffer_string_is_empty(con->uri.query)) {
      #if 1
        /* XXX: why strip auth_cookie_name instead of back_arg_name? */
        /* Strip any auth_cookie_name arguments from the current args */
        query_append_urlencoded(back, con->uri.query, strip_arg);
      #else
        buffer_append_string_len(back, "?", 1);
        buffer_append_string_encoded(back, CONST_BUF_LEN(con->uri.query),
                                     ENCODING_REL_URI_PART);
      #endif
    }
    return 1;
}/*}}}*/

/* External redirect to the given url, setting back cookie or arg */
static handler_t authn_tkt_redirect(server *srv, connection *con, mod_authn_tkt_plugin_opts *opts, buffer *location, buffer *back)/*{{{*/
{
    /* set default redirect URL */
    if (buffer_string_is_empty(location))
        location = opts->auth_login_url;

    if (buffer_string_is_empty(location)) {
        /* Module is not configured unless login_url is set (or guest_login is enabled) */
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "authn_tkt login-url not configured");
        con->http_status = 403;
        return HANDLER_FINISHED;
    }

    if (!authn_tkt_construct_back_urlencoded(srv, con, back,
                                             opts->auth_cookie_name)) {
        con->http_status = 500;
        return HANDLER_FINISHED;
    }

    if (!buffer_string_is_empty(opts->auth_back_cookie_name)) {
        /* XXX: should this get an expires param, if configured?
         * (prior code omitted expires for auth_back_cookie_name) */
        send_auth_cookie(con,opts,opts->auth_back_cookie_name,back,srv->cur_ts);
        http_header_response_set(con, HTTP_HEADER_LOCATION,
                                 CONST_STR_LEN("Location"),
                                 CONST_BUF_LEN(location));
    }
    else if (!buffer_string_is_empty(opts->auth_back_arg_name)) {
        /* If auth_back_cookie_name not set, add back arg to querystr */
        buffer *url = srv->tmp_buf;
        buffer_copy_buffer(url, location);
        buffer_append_string_len(url, strchr(location->ptr,'?') ? "&" : "?", 1);
        buffer_append_string_buffer(url, opts->auth_back_arg_name);
        buffer_append_string_len(url, "=", 1);
        buffer_append_string_buffer(url, back);
        http_header_response_set(con, HTTP_HEADER_LOCATION,
                                 CONST_STR_LEN("Location"),
                                 CONST_BUF_LEN(url));
    }
    else {
      #if 1
        http_header_response_set(con, HTTP_HEADER_LOCATION,
                                 CONST_STR_LEN("Location"),
                                 CONST_BUF_LEN(location));
      #else
        /* XXX: should back_cookie_name and back_arg_name be the same? */
        log_error_write(srv, __FILE__, __LINE__, "s",
                "need either auth _tkt back-cookie-name or auth _tkt back-arg-name to be set");
        con->http_status = 403;
        con->file_finished = 1;
        return HANDLER_FINISHED;
      #endif
    }

    con->http_status = 302;
    con->file_finished = 1;
    return HANDLER_FINISHED;
}/*}}}*/

/* Generate a ticket digest string from the given details */
static void ticket_digest_MD5(authn_tkt *parsed, time_t timestamp, const buffer *secret)/*{{{*/
{
    uint32_t ts = htonl((uint32_t)timestamp); /*(assumes 32-bit time_t)*/
    li_MD5_CTX ctx;

    /* Generate the initial digest */
    li_MD5_Init(&ctx);
    if (NULL != parsed->addr_buf) {
        li_MD5_Update(&ctx,(unsigned char *)CONST_BUF_LEN(parsed->addr_buf));
    }
    li_MD5_Update(&ctx, (unsigned char *)&ts, sizeof(ts));
    li_MD5_Update(&ctx, (unsigned char *)CONST_BUF_LEN(secret));
    li_MD5_Update(&ctx, (unsigned char *)CONST_BUF_LEN(parsed->uid));
    if (!buffer_string_is_empty(parsed->tokens)) {
        li_MD5_Update(&ctx, (unsigned char *)CONST_BUF_LEN(parsed->tokens));
    }
    if (!buffer_string_is_empty(parsed->user_data)) {
        li_MD5_Update(&ctx,(unsigned char*)CONST_BUF_LEN(parsed->user_data));
    }
    li_MD5_Final(parsed->digest, &ctx);

    /* Generate the second digest */
    li_MD5_Init(&ctx);
    li_MD5_Update(&ctx, parsed->digest, parsed->digest_len);
    li_MD5_Update(&ctx, (unsigned char *)CONST_BUF_LEN(secret));
    li_MD5_Final(parsed->digest, &ctx);
}/*}}}*/

#ifdef USE_OPENSSL_CRYPTO
static void ticket_digest_SHA256(authn_tkt *parsed, time_t timestamp, const buffer *secret)/*{{{*/
{
    uint32_t ts = htonl((uint32_t)timestamp); /*(assumes 32-bit time_t)*/
    SHA256_CTX ctx;

    /* Generate the initial digest */
    SHA256_Init(&ctx);
    if (NULL != parsed->addr_buf) {
        SHA256_Update(&ctx,(unsigned char *)CONST_BUF_LEN(parsed->addr_buf));
    }
    SHA256_Update(&ctx, (unsigned char *)&ts, sizeof(ts));
    SHA256_Update(&ctx, (unsigned char *)CONST_BUF_LEN(secret));
    SHA256_Update(&ctx, (unsigned char *)CONST_BUF_LEN(parsed->uid));
    if (!buffer_string_is_empty(parsed->tokens)) {
        SHA256_Update(&ctx, (unsigned char *)CONST_BUF_LEN(parsed->tokens));
    }
    if (!buffer_string_is_empty(parsed->user_data)) {
        SHA256_Update(&ctx,(unsigned char*)CONST_BUF_LEN(parsed->user_data));
    }
    SHA256_Final(parsed->digest, &ctx);

    /* Generate the second digest */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, parsed->digest, parsed->digest_len);
    SHA256_Update(&ctx, (unsigned char *)CONST_BUF_LEN(secret));
    SHA256_Final(parsed->digest, &ctx);
}/*}}}*/

static void ticket_digest_SHA512(authn_tkt *parsed, time_t timestamp, const buffer *secret)/*{{{*/
{
    uint32_t ts = htonl((uint32_t)timestamp); /*(assumes 32-bit time_t)*/
    SHA512_CTX ctx;

    /* Generate the initial digest */
    SHA512_Init(&ctx);
    if (NULL != parsed->addr_buf) {
        SHA512_Update(&ctx,(unsigned char *)CONST_BUF_LEN(parsed->addr_buf));
    }
    SHA512_Update(&ctx, (unsigned char *)&ts, sizeof(ts));
    SHA512_Update(&ctx, (unsigned char *)CONST_BUF_LEN(secret));
    SHA512_Update(&ctx, (unsigned char *)CONST_BUF_LEN(parsed->uid));
    if (!buffer_string_is_empty(parsed->tokens)) {
        SHA512_Update(&ctx, (unsigned char *)CONST_BUF_LEN(parsed->tokens));
    }
    if (!buffer_string_is_empty(parsed->user_data)) {
        SHA512_Update(&ctx,(unsigned char*)CONST_BUF_LEN(parsed->user_data));
    }
    SHA512_Final(parsed->digest, &ctx);

    /* Generate the second digest */
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, parsed->digest, parsed->digest_len);
    SHA512_Update(&ctx, (unsigned char *)CONST_BUF_LEN(secret));
    SHA512_Final(parsed->digest, &ctx);
}/*}}}*/

#endif

/* Refresh the auth cookie if timeout refresh is set */
static void refresh_cookie(server *srv, connection *con, mod_authn_tkt_plugin_opts *opts, authn_tkt *parsed)/*{{{*/
{
    time_t now = srv->cur_ts;
    uint32_t ts = htonl((uint32_t)now); /*(assumes 32-bit time_t)*/
    char sep[2] = { SEPARATOR, '\0' };
    buffer *ticket = srv->tmp_buf, *ticket_base64 = parsed->tmp_buf;
    void(*ticket_digest)(authn_tkt *,time_t,const buffer *) = parsed->digest_fn;

    ticket_digest(parsed, now, opts->auth_secret);
    buffer_clear(ticket);
    buffer_append_string_encoded_hex_lc(ticket, (char *)parsed->digest,
                                        parsed->digest_len);
  #if 1 /*(ensure full 8 hex chars emitted for 32-bit entity)*/
    buffer_append_string_encoded_hex_lc(ticket, (char *)&ts, sizeof(ts));
  #else
    buffer_append_uint_hex_lc(ticket, (uintmax_t)now);
  #endif
    buffer_append_string_buffer(ticket, parsed->uid);
    if (!buffer_string_is_empty(parsed->tokens)) {
        buffer_append_string_len(ticket, sep, 1);
        buffer_append_string_buffer(ticket, parsed->tokens);
    }
    buffer_append_string_len(ticket, sep, 1);
    buffer_append_string_buffer(ticket, parsed->user_data);

    buffer_clear(ticket_base64);
    buffer_append_base64_encode(ticket_base64,
                                (unsigned char *)CONST_BUF_LEN(ticket),
                                BASE64_STANDARD);

    send_auth_cookie(con,opts,opts->auth_cookie_name,ticket_base64,now);
}/*}}}*/

/* Check whether or not the digest is valid
 * Returns 0 if invalid , 1 if valid, 2 if valid-with-old-secret
 *   (valid-with-old-secret requires a cookie refresh to use current secret)
 */
static int check_digest(mod_authn_tkt_plugin_opts *opts, authn_tkt * const auth_rec)/*{{{*/
{
    void(*ticket_digest)(authn_tkt *, time_t, const buffer *)
      = auth_rec->digest_fn;
    const size_t len = auth_rec->digest_len;
    unsigned char digest[MAX_DIGEST_LENGTH];
    memcpy(digest, auth_rec->digest, len);

    ticket_digest(auth_rec, auth_rec->timestamp, opts->auth_secret);

    if (http_auth_const_time_memeq((char *)digest, len,
                                   (char *)auth_rec->digest, len)) {
        return 1;
    }

  #if 0 /*(debug)*/
    buffer_clear(auth_rec->tmp_buf);
    buffer_append_string_encoded_hex_lc(auth_rec->tmp_buf,
                                        (char *)auth_rec->digest,
                                        auth_rec->digest_len);
    buffer_clear(srv->tmp_buf);
    buffer_append_string_encoded_hex_lc(srv->tmp_buf,
                                        (char *)digest,
                                        auth_rec->digest_len);
    log_error_write(srv, __FILE__, __LINE__, "sbsb", "digest NOT matched",
                    auth_rec->tmp_buf, "ticket", srv->tmp_buf);
  #endif

    if (!buffer_string_is_empty(opts->auth_secret_old)) {
        ticket_digest(auth_rec, auth_rec->timestamp, opts->auth_secret_old);
        if (http_auth_const_time_memeq((char *)digest, len,
                                       (char *)auth_rec->digest, len)) {
            auth_rec->refresh_cookie = 1;
            return 1;
        }
    }

    return 0;
}

/* Check whether or not the given timestamp has timed out
 * Returns 0 if timed out, 1 if OK, 2 if OK and trigger cookie refresh */
static int check_timeout(mod_authn_tkt_plugin_opts *opts, authn_tkt *parsed, time_t now)/*{{{*/
{
    time_t expire = (TIME_T_MAX - parsed->timestamp > opts->auth_timeout)
      ? parsed->timestamp + opts->auth_timeout
      : TIME_T_MAX;

    /* Check if ticket expired */
    if (expire < now) return 0;

    /* Check whether remaining ticket lifetime is below refresh threshold */
    if (expire - now < opts->auth_timeout_refresh) parsed->refresh_cookie = 1;

    return 1;
}/*}}}*/

/* Check for required auth tokens
 * Returns 1 on success, 0 on failure */
static int match_tokens(array *reqtokens, buffer *tokens)/*{{{*/
{
    const char * const end = tokens->ptr+buffer_string_length(tokens);
    for (const char *delim, *tok = tokens->ptr; tok < end; tok = delim+1) {
        const size_t len =
          (size_t)(((delim = strchr(tok,',')) ? delim : (delim=end)) - tok);
        for (size_t i = 0; i < reqtokens->used; ++i) {
            buffer *reqtok = ((data_string *)reqtokens->data[i])->value;
            if (buffer_is_equal_string(reqtok, tok, len)) return 1; /* match */
        }
    }
    return 0; /* Failure if required and no user tokens found */
}/*}}}*/

static int check_tokens(connection *con, mod_authn_tkt_plugin_opts *opts, authn_tkt *auth_rec)/*{{{*/
{
    data_array *da;

    /* no path prefixes with required tokens */
    if (0 == opts->auth_tokens->used) return 1;

    /* search tokens directive for first prefix match against URL path */
    /* (if we have case-insensitive FS, then match case-insensitively here) */
    da = (data_array *)((!con->conf.force_lowercase_filenames)
       ? array_match_key_prefix(opts->auth_tokens, con->uri.path)
       : array_match_key_prefix_nc(opts->auth_tokens, con->uri.path));
    if (NULL == da) return 1; /* no matching path prefix with required tokens */
    if (0 == da->value->used) return 1; /* no tokens required */

    return match_tokens(da->value, auth_rec->tokens);
}/*}}}*/

static void init_guest_auth_rec(mod_authn_tkt_plugin_opts *opts, authn_tkt *auth_rec)/*{{{*/
{
    if (opts->auth_guest_cookie) auth_rec->refresh_cookie = 1;
    buffer_clear(auth_rec->user_data);
    buffer_clear(auth_rec->tokens);
    if (buffer_string_is_empty(opts->auth_guest_user)) {
        buffer_copy_string_len(auth_rec->uid,CONST_STR_LEN(DEFAULT_GUEST_USER));
    }
    else {
        /*(future: might parse at startup and store str parts, flags in opts)*/
        buffer *u = opts->auth_guest_user;
        char *b = u->ptr, *e;
        buffer_clear(auth_rec->uid);
        while (NULL != (e = strchr(b, '%'))) {
            size_t n = 0;
            buffer_append_string_len(auth_rec->uid, b, (size_t)(e - b));
            b = e;
            while (light_isdigit(*(++e))) { n *= 10; n += (*e - '0'); }
            if (*e == 'U') {
                /* Note: this is not cryptographically strong */
                unsigned char x[16];
                li_rand_pseudo_bytes((unsigned char *)x, sizeof(x));
                if (n & 1) ++n;
                n <<= 1;
                if (0 == n || sizeof(x) < n) n = sizeof(x);
                buffer_append_string_encoded_hex_lc(auth_rec->uid,(char *)x,n);
                b = e+1;
                break;
            }
            else {
                buffer_append_string_len(auth_rec->uid, CONST_STR_LEN("%"));
                ++b;
                continue;
            }
        }
        e = u->ptr + buffer_string_length(u);
        if (e - b) buffer_append_string_len(auth_rec->uid, b, (size_t)(e - b));
    }
}/*}}}*/

/* ticket authentication entry point */
static handler_t mod_authn_tkt_check(server *srv, connection *con, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend) /*{{{*/
{
    mod_authn_tkt_plugin_opts *opts;
    mod_authn_tkt_plugin_data *p = p_d;
    authn_tkt * const auth_rec = &p->auth_rec;
    int init_guest = 0;

    mod_authn_tkt_patch_connection(srv, con, p);
    opts = p->conf.auth_opts;
    UNUSED(backend);

    if (opts->auth_require_ssl) {
        /* redirect/login if scheme not "https" and require-ssl is set */
        /* (This option is part of authn_tkt to help users avoid mistakes in
         *  module ordering which might result in cookie auth being performed
         *  prior to redirect to https) */
        if (!buffer_is_equal_caseless_string(con->uri.scheme,
                                             CONST_STR_LEN("https"))) {
          #if 0 /* noisy; use access logs to flag insecure requests */
            log_error_write(srv, __FILE__, __LINE__, "s",
                "redirect/login - unsecured request, "
                "authn_tkt require-ssl is enabled");
          #endif
            /* XXX: should this redirect to same URL but https,
             * instead of to auth_login_url? */
            return authn_tkt_redirect(srv, con, opts, NULL, auth_rec->tmp_buf);
        }
    }

    auth_rec->addr_buf = opts->auth_ignore_ip ? NULL : con->dst_addr_buf;
    auth_rec->refresh_cookie = 0;
    auth_rec->digest_fn = opts->auth_digest_fn;
    auth_rec->digest_len = opts->auth_digest_len;
    buffer_clear(auth_rec->user_data);
    buffer_clear(auth_rec->tokens);

    /* check query string and cookie headers for ticket
     *   - either found (accept) or empty (reset/login) */
    if (authn_tkt_from_querystring(con, p) || authn_tkt_from_cookie(con, p)) {
        /* module is misconfigured unless secret is set */
        if (buffer_string_is_empty(opts->auth_secret)) {
            log_error_write(srv, __FILE__, __LINE__, "s", "need secret");
            con->http_status = 500;
            return HANDLER_FINISHED;
        }

        if (!check_digest(opts, auth_rec)
            && !(init_guest = opts->auth_guest_login)) {
            return authn_tkt_redirect(srv, con, opts, NULL, auth_rec->tmp_buf);
        }

        /* check timeout */
        if (0 != opts->auth_timeout && !init_guest
            && !check_timeout(opts, auth_rec, srv->cur_ts)) {
            if (!(init_guest = opts->auth_guest_fallback)) {
                buffer *redirect_url = opts->auth_timeout_url;
                if (con->request.http_method == HTTP_METHOD_POST
                    && !buffer_string_is_empty(opts->auth_post_timeout_url)) {
                    redirect_url = opts->auth_post_timeout_url;
                }
                /* Delete cookie (set expired) in case we want to set from url*/
                send_auth_cookie(con, opts, opts->auth_cookie_name, NULL, 0);
                return authn_tkt_redirect(srv, con, opts, redirect_url,
                                          auth_rec->tmp_buf);
            }
        }
    }
    else if (!(init_guest = opts->auth_guest_login)) {
        return authn_tkt_redirect(srv, con, opts, NULL, auth_rec->tmp_buf);
    }

    /* initialize auth_rec as guest (if flagged) */
    if (init_guest) init_guest_auth_rec(opts, auth_rec);

    /* check authorization for auth_rec user (required) */
    if (!http_auth_match_rules(require, auth_rec->uid->ptr, NULL, NULL)) {
        log_error_write(srv, __FILE__, __LINE__, "sb",
                        "user NOT matched", auth_rec->uid);
        return authn_tkt_redirect(srv, con, opts, opts->auth_unauth_url,
                                  auth_rec->tmp_buf);
    }

    /* check authorization for auth_rec tokens (optional) */
    if (!check_tokens(con, opts, auth_rec)) {
        log_error_write(srv, __FILE__, __LINE__, "sb",
                        "tokens NOT matched", auth_rec->tokens);
        return authn_tkt_redirect(srv, con, opts, opts->auth_unauth_url,
                                  auth_rec->tmp_buf);
    }

    /* refresh cookie (if flagged) */
    if (auth_rec->refresh_cookie) refresh_cookie(srv, con, opts, auth_rec);

    /* set CGI/FCGI/SCGI environment */ /* XXX: ? set AUTH_TYPE="authn_tkt" ? */
    http_auth_setenv(con, CONST_BUF_LEN(auth_rec->uid), CONST_STR_LEN("Basic"));
    http_header_env_set(con, CONST_STR_LEN("REMOTE_USER_DATA"),
                             CONST_BUF_LEN(auth_rec->user_data));
    http_header_env_set(con, CONST_STR_LEN("REMOTE_USER_TOKENS"),
                             CONST_BUF_LEN(auth_rec->tokens));
    return HANDLER_GO_ON;  /* access granted */
}/*}}}*/

/* configuration processing & checking */
static char *convert_to_seconds(buffer *cfg, int *timeout)/*{{{*/
{
    char *endptr;
    unsigned long int n, m;

    if (buffer_string_is_empty(cfg)) {
        return "bad time string - must not be empty";
    }

    n = strtoul(cfg->ptr, &endptr, 10);

    if (!light_isdigit(cfg->ptr[0]) || n > 65535 || cfg->ptr == endptr) {
        return "bad time string - expecting non-negative number <= 65535";
    }

    switch (*endptr) {
      case '\0':
      case 's': m = 1; break;
      case 'm': m = 60; break;
      case 'h': m = 60 * 60; break;
      case 'd': m = 60 * 60 * 24; break;
      case 'w': m = 60 * 60 * 24 * 7; break;
      case 'M': m = 60 * 60 * 24 * 30; break;
      case 'y': m = 60 * 60 * 24 * 365; break;
      default: return "bad time string - unrecognized unit";
    }

    m *= n;
    if (m < n || m > INT_MAX) {
        return "integer overflow or invalid number";
    }

    *timeout = (int)m;
    return NULL;
}/*}}}*/

static mod_authn_tkt_plugin_opts * plugin_config_init_defaults(void) /*{{{*/
{
    mod_authn_tkt_plugin_opts *o = calloc(1, sizeof(mod_authn_tkt_plugin_opts));
    force_assert(o);

    o->auth_secret = buffer_init();
    o->auth_secret_old = buffer_init();
    o->auth_login_url = buffer_init();
    o->auth_timeout_url = buffer_init();
    o->auth_post_timeout_url = buffer_init();
    o->auth_unauth_url = buffer_init();
    o->auth_timeout_conf = buffer_init();
    o->auth_timeout_refresh_conf = buffer_init();
    o->auth_digest_type_conf = buffer_init();
    o->auth_ignore_ip = 0;
    o->auth_require_ssl = 0;
    o->auth_cookie_secure = -1;
    o->auth_cookie_name = buffer_init();
    o->auth_cookie_domain = buffer_init();
    o->auth_cookie_expires_conf = buffer_init();
    o->auth_back_cookie_name = buffer_init();
    o->auth_back_arg_name = buffer_init();
    o->auth_guest_user = buffer_init();
    o->auth_guest_login = 0;
    o->auth_guest_cookie = 0;
    o->auth_guest_fallback = 0;
    o->auth_tokens = array_init();

    o->auth_timeout = DEFAULT_TIMEOUT_SEC;
    o->auth_timeout_refresh = (int)(0.5 * DEFAULT_TIMEOUT_SEC);
    o->auth_digest_fn = ticket_digest_MD5;
    o->auth_digest_len = MD5_DIGEST_LENGTH;
    o->auth_cookie_expires = 0;

    return o;
}/*}}}*/

static int parse_opts(server *srv, mod_authn_tkt_plugin_opts *opts, data_array *da) /*{{{*/
{
    config_values_t cv[] = {
      { "secret",            NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */   /* TKTAuthSecret */
      { "secret-old",        NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthSecretOld */
      { "login-url",         NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthLoginURL */
      { "timeout-url",       NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthTimeoutURL */
      { "post-timeout-url",  NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthPostTimeoutURL */
      { "unauth-url",        NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthUnauthURL */
      { "timeout",           NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthTimeout */
      { "timeout-refresh",   NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthTimeoutRefresh */
      { "digest-type",       NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthDigestType */
      { "ignore-ip",         NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },          /* TKTAuthIgnoreIP */
      { "require-ssl",       NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 10 */ /* TKTAuthRequireSSL */
      { "cookie-secure",     NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },          /* TKTAuthCookieSecure */
      { "cookie-name",       NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthCookieName */
      { "cookie-domain",     NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthDomain */
      { "cookie-expires",    NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthCookieExpires */
      { "back-cookie-name",  NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthBackCookieName */
      { "back-arg-name",     NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthBackArgName */
      { "guest-user",        NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },           /* TKTAuthGuestUser */
      { "guest-login",       NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },          /* TKTAuthGuestLogin */
      { "guest-cookie",      NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },          /* TKTAuthGuestCookie */
      { "guest-fallback",    NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 20 */ /* TKTAuthGuestFallback */
      { "tokens",            NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },            /* TKTAuthToken */
      { NULL,                NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    if (NULL == da) return 1;

    if (da->type != TYPE_ARRAY || !array_is_kvany(da->value)) {
        log_error_write(srv, __FILE__, __LINE__, "s",
          "unexpected value for auth.method.tkt.opts; expected "
          "( \"key\" => \"value\" )");
        return 0;
    }

    cv[0].destination = opts->auth_secret;
    cv[1].destination = opts->auth_secret_old;
    cv[2].destination = opts->auth_login_url;
    cv[3].destination = opts->auth_timeout_url;
    cv[4].destination = opts->auth_post_timeout_url;
    cv[5].destination = opts->auth_unauth_url;
    cv[6].destination = opts->auth_timeout_conf;
    cv[7].destination = opts->auth_timeout_refresh_conf;
    cv[8].destination = opts->auth_digest_type_conf;
    cv[9].destination = &(opts->auth_ignore_ip);
    cv[10].destination = &(opts->auth_require_ssl);
    cv[11].destination = &(opts->auth_cookie_secure);
    cv[12].destination = opts->auth_cookie_name;
    cv[13].destination = opts->auth_cookie_domain;
    cv[14].destination = opts->auth_cookie_expires_conf;
    cv[15].destination = opts->auth_back_cookie_name;
    cv[16].destination = opts->auth_back_arg_name;
    cv[17].destination = opts->auth_guest_user;
    cv[18].destination = &(opts->auth_guest_login);
    cv[19].destination = &(opts->auth_guest_cookie);
    cv[20].destination = &(opts->auth_guest_fallback);
    cv[21].destination = opts->auth_tokens;

    if (0 != config_insert_values_global(srv, da->value, cv, T_CONFIG_SCOPE_CONNECTION)) {
        return 0;
    }

    /* check scalar config elements */
    if (opts->auth_require_ssl) {
        if (-1 == opts->auth_cookie_secure) {
            /* Backwards compatibility mode for require-ssl */
            /* Set secure_cookie flag if require-ssl is set
             * and secure_cookie is undefined (as opposed to 'off') */
          #if 0 /* noisy; must explicitly configure if insecure desired */
            log_error_write(srv, __FILE__, __LINE__, "s",
                "WARNING: require-ssl on, but no cookie-secure found - "
                "please set cookie-secure explicitly; assuming 'enabled'");
          #endif
            opts->auth_cookie_secure = 1;
        }
    }
    if (!buffer_string_is_empty(opts->auth_timeout_conf)) {
        char *msg = convert_to_seconds(opts->auth_timeout_conf, &(opts->auth_timeout));
        if (msg) {
            log_error_write(srv, __FILE__, __LINE__, "s", msg);
            return 0;
        }
    }
    if (!buffer_string_is_empty(opts->auth_timeout_refresh_conf)) {
        /* The timeout refresh is a double between 0 and 1, signifying what
         * proportion of the timeout should be left before we refresh i.e.
         * 0 means never refresh (hard timeouts); 1 means always refresh;
         * .33 means only refresh if less than a third of the timeout
         * period remains. */
        double refresh = atof(opts->auth_timeout_refresh_conf->ptr);
        if (refresh < 0.0 || refresh > 1.0) {
            log_error_write(srv, __FILE__, __LINE__, "s", "refresh must be between 0.0 and 1.0");
            return 0;
        }
        opts->auth_timeout_refresh = (int)(refresh * opts->auth_timeout);
    }
    if (!buffer_string_is_empty(opts->auth_cookie_expires_conf)) {
        char *msg = convert_to_seconds(opts->auth_cookie_expires_conf, &(opts->auth_cookie_expires));
        if (msg) {
            log_error_write(srv, __FILE__, __LINE__, "ss", "cookie_expires ", msg);
            return 0;
        }
    }
    if (!buffer_string_is_empty(opts->auth_digest_type_conf)) {
        /* MAX_DIGEST_LENGTH must be defined at top of file to largest supported digest */
        if (0 == buffer_is_equal_string(opts->auth_digest_type_conf, CONST_STR_LEN(""))) {
            opts->auth_digest_fn = ticket_digest_MD5;
            opts->auth_digest_len = MD5_DIGEST_LENGTH;
        }
      #ifdef USE_OPENSSL_CRYPTO
        else if (0 == buffer_is_equal_string(opts->auth_digest_type_conf, CONST_STR_LEN("SHA256"))) {
            opts->auth_digest_fn = ticket_digest_SHA256;
            opts->auth_digest_len = SHA256_DIGEST_LENGTH;
        }
        else if (0 == buffer_is_equal_string(opts->auth_digest_type_conf, CONST_STR_LEN("SHA512"))) {
            opts->auth_digest_fn = ticket_digest_SHA512;
            opts->auth_digest_len = SHA512_DIGEST_LENGTH;
        }
      #endif
        else {
          #ifdef USE_OPENSSL_CRYPTO
            log_error_write(srv, __FILE__, __LINE__, "s", "digest-type must be one of: \"MD5\", \"SHA256\", \"SHA512\"");
          #else
            log_error_write(srv, __FILE__, __LINE__, "s", "digest-type must be: \"MD5\" (Rebuild lighttpd with crypo libs for additional options.)");
          #endif
            return 0;
        }
    }
    /*
     * "tokens" = ( "<path>" => ( ..., ... ),
     *              "<path>" => ( ..., ... ) )
     */
    if (array_is_kvarray(opts->auth_tokens)) {
        array *t = opts->auth_tokens;
        for (size_t i = 0; i < t->used; ++i) {
            if (!array_is_vlist(((data_array *)t->data[i])->value)) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                    "unexpected value for tokens.  "
                    "tokens should contain an array as in: "
                    "\"tokens\" = ( \"path\" => ( \"token1\", \"token2\") )");
                return 0;
            }
        }
    }
    else {
        log_error_write(srv, __FILE__, __LINE__, "s",
            "unexpected value for tokens.  "
            "tokens should contain an array as in: "
            "\"tokens\" = ( \"path\" => ( \"token1\", \"token2\") )");
        return 0;
    }

    return 1;
}/*}}}*/

SETDEFAULTS_FUNC(mod_authn_tkt_set_defaults) /*{{{*/
{
    mod_authn_tkt_plugin_data *p = p_d;

    config_values_t cv[] = {
        { "auth.method.tkt.opts", NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },
        { NULL,                   NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
    force_assert(p->config_storage);

    for (size_t i = 0; i < srv->config_context->used; ++i) {
        array *ca = ((data_config *)srv->config_context->data[i])->value;
        data_array *da;
        mod_authn_tkt_plugin_config *s = calloc(1, sizeof(mod_authn_tkt_plugin_config));
        force_assert(s);
        p->config_storage[i] = s;

        if (0 == i) {
            s->auth_opts = plugin_config_init_defaults();
            buffer_copy_string_len(s->auth_opts->auth_cookie_name,
                           CONST_STR_LEN(AUTH_COOKIE_NAME));
        }

        cv[0].destination = NULL;

        if (0 != config_insert_values_global(srv, ca, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

        da = (data_array *)
          array_get_element_klen(ca,CONST_STR_LEN("auth.method.tkt.opts"));
        if (NULL != da) {
            if (0 != i) s->auth_opts = plugin_config_init_defaults();
            if (!parse_opts(srv, s->auth_opts, da)) return HANDLER_ERROR;
        }
    }

    return HANDLER_GO_ON;
}/*}}}*/

int mod_authn_tkt_plugin_init(plugin *p);
int mod_authn_tkt_plugin_init(plugin *p) /*{{{*/
{
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("authn_tkt");
	p->init        = mod_authn_tkt_init;
	p->set_defaults= mod_authn_tkt_set_defaults;
	p->cleanup     = mod_authn_tkt_free;

	p->data        = NULL;

	return 0;
}/*}}}*/
