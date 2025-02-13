/*
 * mod_authn_tkt - a cookie-based authentication for Lighttpd
 *
 * lighttpd module
 *   Copyright Glenn Strauss gstrauss@gluelogic.com
 *   License: BSD 3-clause + see below
 *
 * based on: mod_auth_tkt by Gavin Carr with contributors
 *           (see http://www.openfusion.com.au/labs/mod_auth_tkt),
 *           https://github.com/gavincarr/mod_auth_tkt
 *           License: Apache License 2.0
 */
/*
 * mod_authn_tkt version 0.07
 */
#include "first.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <arpa/inet.h>  /* htonl() ntohl() */
#else
#include <winsock2.h>   /* htonl() ntohl() */
#endif

#include "sys-crypto-md.h"

#include "base.h"
#include "base64.h"
#include "buffer.h"
#include "ck.h"
#include "mod_auth_api.h"
#include "http_date.h"
#include "http_header.h"
#include "log.h"
#include "plugin.h"
#include "rand.h"
#include "response.h"   /* http_response_buffer_append_authority() */

/* Default settings */
#define AUTH_COOKIE_NAME "auth_tkt"
#define SEPARATOR '!'
#define DEFAULT_TIMEOUT_SEC 7200
#define DEFAULT_GUEST_USER "guest"

#define TIMESTAMP_HEXLEN 8  /*(unsigned 32-bit (4 bytes) in hex)*/

/*#define TIME_T_MAX (~((time_t)1 << (sizeof(time_t)*CHAR_BIT-1)))*/
#define TIME_T_MAX INT64_MAX

typedef struct authn_tkt_struct {
	buffer uid;
	buffer tokens;
	buffer user_data;
	buffer tmp_buf;
	buffer *addr_buf; /* not allocated */
	int refresh_cookie;
	uint32_t timestamp; /* unsigned 32-bit big-endian value for time_t */
	unsigned int digest_len;
	li_md_iov_fn digest_fn;
	unsigned char digest[MD_DIGEST_LENGTH_MAX];
} authn_tkt;


typedef struct {
	const buffer *auth_secret;
	const buffer *auth_secret_old;
	const buffer *auth_login_url;
	const buffer *auth_timeout_url;
	const buffer *auth_post_timeout_url;
	const buffer *auth_unauth_url;

	const buffer *auth_cookie_name;
	const buffer *auth_cookie_domain;
	const buffer *auth_back_cookie_name;
	const buffer *auth_back_arg_name;
	const buffer *auth_guest_user;
	const array *auth_tokens;

	li_md_iov_fn auth_digest_fn;
	uint8_t auth_digest_len;
	uint8_t auth_ignore_ip;
	int8_t auth_cookie_secure;
	uint8_t auth_require_ssl;
	uint8_t auth_guest_login;
	uint8_t auth_guest_cookie;
	uint8_t auth_guest_fallback;

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
	mod_authn_tkt_plugin_config defaults;
	mod_authn_tkt_plugin_config conf;
	authn_tkt auth_rec;
	mod_authn_tkt_plugin_opts default_auth_opts;
} mod_authn_tkt_plugin_data;


static handler_t mod_authn_tkt_check(request_st *r, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);

INIT_FUNC(mod_authn_tkt_init) /*{{{*/
{
    static http_auth_scheme_t http_auth_scheme_authn_tkt = { "authn_tkt", mod_authn_tkt_check, NULL };

    mod_authn_tkt_plugin_data *p = ck_calloc(1, sizeof(*p));

    /* register http_auth_scheme_* */
    http_auth_scheme_authn_tkt.p_d = p;
    http_auth_scheme_set(&http_auth_scheme_authn_tkt);

    return p;
}/*}}}*/

FREE_FUNC(mod_authn_tkt_free) /*{{{*/
{
    mod_authn_tkt_plugin_data * const p = p_d;
    free(p->auth_rec.uid.ptr);
    free(p->auth_rec.tokens.ptr);
    free(p->auth_rec.user_data.ptr);
    free(p->auth_rec.tmp_buf.ptr);
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 0: /* auth.method.tkt.opts */
                free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}/*}}}*/

static void mod_authn_tkt_merge_config_cpv(mod_authn_tkt_plugin_config * const pconf, const config_plugin_value_t * const cpv) { /*{{{*/
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* auth.method.tkt.opts */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->auth_opts = cpv->v.v;
        break;
      default:/* should not happen */
        return;
    }
}/*}}}*/

static void mod_authn_tkt_merge_config(mod_authn_tkt_plugin_config * const pconf, const config_plugin_value_t *cpv) { /*{{{*/
    do {
        mod_authn_tkt_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}/*}}}*/

static void mod_authn_tkt_patch_config(request_st * const r, mod_authn_tkt_plugin_data * const p) { /*{{{*/
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_authn_tkt_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}/*}}}*/

/* Send an auth cookie with given value; NULL value is flag to expire cookie */
static void send_auth_cookie(request_st * const r, const mod_authn_tkt_plugin_opts * const opts, const buffer * const cookie_name, const buffer * const value, unix_time64_t now)/*{{{*/
{
    buffer *cookie;
    const buffer *domain;

    http_header_response_insert(r, HTTP_HEADER_SET_COOKIE,
                                CONST_STR_LEN("Set-Cookie"),
                                BUF_PTR_LEN(cookie_name));
    cookie = http_header_response_get(r, HTTP_HEADER_SET_COOKIE,
                                      CONST_STR_LEN("Set-Cookie"));
  #ifdef __COVERITY__
    force_assert(cookie);
  #endif

    if (NULL != value) {
        buffer_append_str3(cookie, CONST_STR_LEN("="),
                                   BUF_PTR_LEN(value),
                                   CONST_STR_LEN("; path=/"));
        if (opts->auth_cookie_expires > 0) {
            now = (TIME_T_MAX - now > opts->auth_cookie_expires)
                ? now + opts->auth_cookie_expires
                : TIME_T_MAX;
            buffer_append_string_len(cookie, CONST_STR_LEN("; expires="));
            http_date_time_append(cookie, now);
        }
    }
    else {
        buffer_append_string_len(cookie,
          CONST_STR_LEN("=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT"));
    }
    /* (Apache mod_auth_tkt prefers X-Forwarded-Host to Host; not done here) */
    /* XXX: if using r->server_name, do we need to omit :port, if present? */
    domain = !opts->auth_cookie_domain
      ? r->server_name
      : opts->auth_cookie_domain;
    if (domain && !buffer_is_blank(domain)) {
        buffer_append_string_len(cookie, CONST_STR_LEN("; domain="));
        buffer_append_string_encoded(cookie, BUF_PTR_LEN(domain),
                                     ENCODING_REL_URI);
    }
    if (opts->auth_cookie_secure > 0) {
        buffer_append_string_len(cookie, CONST_STR_LEN("; secure"));
    }
}/*}}}*/

/* Parse cookie. Returns 1 if valid, and details in *parsed; 0 if not */
static int parse_ticket(authn_tkt *parsed)/*{{{*/
{
    const char *tkt = parsed->tmp_buf.ptr, *sep, *sep2;
    const unsigned int digest_hexlen = (parsed->digest_len << 1);

    /* See if there is a uid/data separator */
    sep = strchr(tkt, SEPARATOR);
    if (NULL == sep) return 0;

    /* Basic length check for min size */
    if (sep - tkt < digest_hexlen + TIMESTAMP_HEXLEN) return 0;

    if (0 != li_hex2bin(parsed->digest, sizeof(parsed->digest),
                        tkt, digest_hexlen)) {
        return 0; /*(invalid hex encoding)*/
    }

    parsed->timestamp = 0;
    if (0 != li_hex2bin((unsigned char *)&parsed->timestamp,
                        sizeof(parsed->timestamp),
                        tkt+digest_hexlen, TIMESTAMP_HEXLEN)) {
        return 0; /*(invalid hex encoding in timestamp)*/
    }

    buffer_copy_string_len(&parsed->uid,
                           tkt + digest_hexlen + TIMESTAMP_HEXLEN,
                           sep - tkt - (digest_hexlen + TIMESTAMP_HEXLEN));

    sep2 = strchr(sep+1, SEPARATOR);
    if (NULL != sep2) {
        buffer_copy_string_len(&parsed->tokens, sep+1, sep2-sep-1);
        sep = sep2;
    }

    /* Copy user data to parsed->user_data */
    ++sep;
    buffer_copy_string_len(&parsed->user_data, sep,
                           tkt + buffer_clen(&parsed->tmp_buf) - sep);

    return 1;
}/*}}}*/


/* Search query string for our ticket */
static int authn_tkt_from_querystring(request_st * const r, mod_authn_tkt_plugin_data * const p)/*{{{*/
{
    const buffer * const name = p->conf.auth_opts->auth_cookie_name;
    const size_t nlen = buffer_clen(name);
    const char *qstr = r->uri.query.ptr;
    if (buffer_is_blank(&r->uri.query)) return 0;
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
          : qstr + buffer_clen(&r->uri.query);

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
            buffer *result = &p->auth_rec.tmp_buf;
            buffer_copy_string_len(result, start, end-start);
            buffer_urldecode_path(result);
            return parse_ticket(&p->auth_rec);
        }
    }
    return 0;
}/*}}}*/

/* Search cookie headers for our ticket */
static int authn_tkt_from_cookie(request_st * const r, mod_authn_tkt_plugin_data * const p)/*{{{*/
{
    const buffer * const name = p->conf.auth_opts->auth_cookie_name;
    const size_t nlen = buffer_clen(name);
    const buffer * const hdr =
      http_header_request_get(r, HTTP_HEADER_COOKIE, CONST_STR_LEN("Cookie"));
    if (NULL == hdr) return 0;
    const char *str = hdr->ptr;
    do { /*(modified from mod_accesslog.c:log_access_record() FORMAT_COOKIE)*/
        while (*str == ' ' || *str == '\t') ++str;
        if (0 == strncmp(str, name->ptr, nlen) && str[nlen] == '=') {
            const char *v = str+nlen+1;
            for (str = v; *str != '\0' && *str != ';'; ++str) ;
            if (str == v) break;
            do { --str; } while (str > v && (*str == ' ' || *str == '\t'));
            /* remove double-quoting, if present (not needed for base64) */
            if (*v == '"') {
                ++v;
                if (*str == '"') --str;
            }
            if (v < str) {
                buffer * const result = &p->auth_rec.tmp_buf;
                buffer_clear(result);
                buffer_append_base64_decode(result,v,str-v+1,BASE64_STANDARD);
                return parse_ticket(&p->auth_rec);
            }
            /* skip empty cookies (such as with misconfigured logoffs) */
        }
        while (*str != ';' && *str != ' ' && *str != '\t' && *str != '\0')
            ++str;
        while (*str == ' ' || *str == '\t') ++str;
    } while (*str++ == ';');
    return 0;
}/*}}}*/

#if 1
/* Strip specified query args from a url and append the rest urlencoded */
static void query_append_urlencoded(buffer *b, buffer *q, const buffer * const omit)/*{{{*/
{
    char sep[] = "?";
    char *qend = q->ptr + buffer_clen(q);
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

static int authn_tkt_construct_back_urlencoded(request_st * const r, buffer * const back, const buffer * const strip_arg)/*{{{*/
{
    buffer * const tb = r->tmp_buf;
    buffer_clear(tb);
    if (0 != http_response_buffer_append_authority(r, tb))
        return 0;
    buffer_clear(back);
    buffer_append_str2(back, BUF_PTR_LEN(&r->uri.scheme), CONST_STR_LEN("://"));
    buffer_append_string_encoded(back, BUF_PTR_LEN(tb),
                                 ENCODING_REL_URI_PART);
    buffer_append_string_encoded(back, BUF_PTR_LEN(&r->uri.path),
                                 ENCODING_REL_URI_PART);
    if (!buffer_is_blank(&r->uri.query)) {
      #if 1
        /* XXX: why strip auth_cookie_name instead of back_arg_name? */
        /* Strip any auth_cookie_name arguments from the current args */
        query_append_urlencoded(back, &r->uri.query, strip_arg);
      #else
        buffer_append_string_len(back, "?", 1);
        buffer_append_string_encoded(back, BUF_PTR_LEN(&r->uri.query),
                                     ENCODING_REL_URI_PART);
      #endif
    }
    return 1;
}/*}}}*/

/* External redirect to the given url, setting back cookie or arg */
static handler_t authn_tkt_redirect(request_st * const r, const mod_authn_tkt_plugin_opts * const opts, const buffer *location, buffer * const back)/*{{{*/
{
    /* set default redirect URL */
    if (!location)
        location = opts->auth_login_url;

    if (!location) {
        /* Module is not configured unless login_url is set (or guest_login is enabled) */
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "authn_tkt login-url not configured");
        r->http_status = 403;
        return HANDLER_FINISHED;
    }

    if (!authn_tkt_construct_back_urlencoded(r, back, opts->auth_cookie_name)) {
        r->http_status = 500;
        return HANDLER_FINISHED;
    }

    buffer * const url =
      http_header_response_set_ptr(r, HTTP_HEADER_LOCATION,
                                   CONST_STR_LEN("Location"));
    buffer_copy_buffer(url, location);

    if (opts->auth_back_cookie_name) {
        /* XXX: should this get an expires param, if configured?
         * (prior code omitted expires for auth_back_cookie_name) */
        send_auth_cookie(r, opts, opts->auth_back_cookie_name, back,
                         log_epoch_secs);
    }
    else if (opts->auth_back_arg_name) {
        /* If auth_back_cookie_name not set, add back arg to querystr */
        buffer_append_string_len(url, strchr(location->ptr,'?') ? "&" : "?", 1);
        buffer_append_str3(url, BUF_PTR_LEN(opts->auth_back_arg_name),
                                CONST_STR_LEN("="),
                                BUF_PTR_LEN(back));
    }
    else {
      #if 0
        /* XXX: should back_cookie_name and back_arg_name be the same? */
        log_error(r->conf.errh, __FILE__, __LINE__,
          "need either auth _tkt back-cookie-name or auth _tkt back-arg-name "
          "to be set");
        r->http_status = 403;
        r->resp_body_finished = 1;
        return HANDLER_FINISHED;
      #endif
    }

    r->http_status = 302;
    r->resp_body_finished = 1;
    return HANDLER_FINISHED;
}/*}}}*/

/* Generate a ticket digest string from the given details */
static void ticket_digest(authn_tkt *parsed, uint32_t ts, const buffer *secret)/*{{{*/
{
    size_t n = 0;
    struct const_iovec iov[6];
    if (NULL != parsed->addr_buf) {
        iov[n].iov_base = parsed->addr_buf->ptr;
        iov[n].iov_len  = buffer_clen(parsed->addr_buf);
        ++n;
    }
    iov[n].iov_base     = &ts;
    iov[n].iov_len      = sizeof(ts);
    iov[n+1].iov_base   = secret->ptr;
    iov[n+1].iov_len    = buffer_clen(secret);
    iov[n+2].iov_base   = parsed->uid.ptr;
    iov[n+2].iov_len    = buffer_clen(&parsed->uid);
    n += 3;

    if (!buffer_is_blank(&parsed->tokens)) {
        iov[n].iov_base = parsed->tokens.ptr;
        iov[n].iov_len  = buffer_clen(&parsed->tokens);
        ++n;
    }
    if (!buffer_is_blank(&parsed->user_data)) {
        iov[n].iov_base = parsed->user_data.ptr;
        iov[n].iov_len  = buffer_clen(&parsed->user_data);
        ++n;
    }
    parsed->digest_fn(parsed->digest, iov, n);

    /* Generate the second digest */
    iov[0].iov_base     = parsed->digest;
    iov[0].iov_len      = parsed->digest_len;
    iov[1].iov_base     = secret->ptr;
    iov[1].iov_len      = buffer_clen(secret);
    parsed->digest_fn(parsed->digest, iov, 2);
}/*}}}*/

/* Refresh the auth cookie if timeout refresh is set */
static void refresh_cookie(request_st * const r, const mod_authn_tkt_plugin_opts * const opts, authn_tkt * const parsed)/*{{{*/
{
    unix_time64_t now = log_epoch_secs;
    uint32_t ts = htonl((uint32_t)now);
    char sep[2] = { SEPARATOR, '\0' };
    buffer *ticket = r->tmp_buf, *ticket_base64 = &parsed->tmp_buf;

    ticket_digest(parsed, ts, opts->auth_secret);
    buffer_clear(ticket);
    buffer_append_string_encoded_hex_lc(ticket, (char *)parsed->digest,
                                        parsed->digest_len);
    /*(ensure 8 hex chars emitted for 4 bytes of uint32_t)*/
    buffer_append_string_encoded_hex_lc(ticket, (char *)&ts, sizeof(ts));
    buffer_append_buffer(ticket, &parsed->uid);
    if (!buffer_is_blank(&parsed->tokens))
        buffer_append_str2(ticket, sep, 1, BUF_PTR_LEN(&parsed->tokens));
    buffer_append_str2(ticket, sep, 1, BUF_PTR_LEN(&parsed->user_data));

    buffer_clear(ticket_base64);
    buffer_append_base64_encode(ticket_base64,
                                (unsigned char *)ticket->ptr,
                                buffer_clen(ticket),
                                BASE64_STANDARD);

    send_auth_cookie(r, opts, opts->auth_cookie_name, ticket_base64, now);
}/*}}}*/

/* Check whether or not the digest is valid
 * Returns 0 if invalid , 1 if valid, 2 if valid-with-old-secret
 *   (valid-with-old-secret requires a cookie refresh to use current secret)
 */
static int check_digest(const mod_authn_tkt_plugin_opts * const opts, authn_tkt * const auth_rec)/*{{{*/
{
    const size_t len = auth_rec->digest_len;
    unsigned char digest[MD_DIGEST_LENGTH_MAX];
    memcpy(digest, auth_rec->digest, len);

    ticket_digest(auth_rec, auth_rec->timestamp, opts->auth_secret);

    if (ck_memeq_const_time_fixed_len(digest, auth_rec->digest, len))
        return 1;

  #if 0 /*(debug)*/
    buffer_clear(&auth_rec->tmp_buf);
    buffer_append_string_encoded_hex_lc(&auth_rec->tmp_buf,
                                        (char *)auth_rec->digest,
                                        auth_rec->digest_len);
    buffer * const tb = r->tmp_buf
    buffer_clear(tb);
    buffer_append_string_encoded_hex_lc(tb,
                                        (char *)digest,
                                        auth_rec->digest_len);
    log_error(r->conf.errh, __FILE__, __LINE__,
              "digest NOT matched %s ticket %s",
              auth_rec->tmp_buf.ptr, tb->ptr);
  #endif

    if (opts->auth_secret_old) {
        ticket_digest(auth_rec, auth_rec->timestamp, opts->auth_secret_old);
        if (ck_memeq_const_time_fixed_len(digest, auth_rec->digest, len)) {
            auth_rec->refresh_cookie = 1;
            return 1;
        }
    }

    return 0;
}

/* Check whether or not the given timestamp has timed out
 * Returns 0 if timed out, 1 if OK, 2 if OK and trigger cookie refresh */
static int check_timeout(const mod_authn_tkt_plugin_opts * const opts, authn_tkt * const parsed, const unix_time64_t now)/*{{{*/
{
    const unix_time64_t hts = (unix_time64_t)ntohl(parsed->timestamp);
    unix_time64_t expire = (TIME_T_MAX - hts > opts->auth_timeout)
      ? hts + opts->auth_timeout
      : TIME_T_MAX;

    /* Check if ticket expired */
    if (expire < now) return 0;

    /* Check whether remaining ticket lifetime is below refresh threshold */
    if (expire - now < opts->auth_timeout_refresh) parsed->refresh_cookie = 1;

    return 1;
}/*}}}*/

/* Check for required auth tokens
 * Returns 1 on success, 0 on failure */
__attribute_pure__
static int match_tokens(const array * const reqtokens, const buffer * const tokens)/*{{{*/
{
    const char * const end = tokens->ptr+buffer_clen(tokens);
    for (const char *delim, *tok = tokens->ptr; tok < end; tok = delim+1) {
        const size_t len =
          (size_t)(((delim = strchr(tok,',')) ? delim : (delim=end)) - tok);
        for (size_t i = 0; i < reqtokens->used; ++i) {
            const buffer *reqtok = &((data_string *)reqtokens->data[i])->value;
            if (buffer_is_equal_string(reqtok, tok, len)) return 1; /* match */
        }
    }
    return 0; /* Failure if required and no user tokens found */
}/*}}}*/

__attribute_pure__
static int check_tokens(const request_st * const r, const mod_authn_tkt_plugin_opts * const opts, const authn_tkt * const auth_rec)/*{{{*/
{
    data_array *da;

    /* no path prefixes with required tokens */
    if (NULL == opts->auth_tokens) return 1;

    /* search tokens directive for first prefix match against URL path */
    /* (if we have case-insensitive FS, then match case-insensitively here) */
    da = (data_array *)((!r->conf.force_lowercase_filenames)
       ? array_match_key_prefix(opts->auth_tokens, &r->uri.path)
       : array_match_key_prefix_nc(opts->auth_tokens, &r->uri.path));
    if (NULL == da) return 1; /* no matching path prefix with required tokens */
    if (0 == da->value.used) return 1; /* no tokens required */

    return match_tokens(&da->value, &auth_rec->tokens);
}/*}}}*/

static void init_guest_auth_rec(const mod_authn_tkt_plugin_opts * const opts, authn_tkt * const auth_rec)/*{{{*/
{
    if (opts->auth_guest_cookie) auth_rec->refresh_cookie = 1;
    buffer_clear(&auth_rec->user_data);
    buffer_clear(&auth_rec->tokens);
    if (!opts->auth_guest_user) {
        buffer_copy_string_len(&auth_rec->uid,
                               CONST_STR_LEN(DEFAULT_GUEST_USER));
    }
    else {
        /*(future: might parse at startup and store str parts, flags in opts)*/
        const buffer *u = opts->auth_guest_user;
        char *b = u->ptr, *e;
        buffer_clear(&auth_rec->uid);
        while (NULL != (e = strchr(b, '%'))) {
            size_t n = 0;
            buffer_append_string_len(&auth_rec->uid, b, (size_t)(e - b));
            b = e;
            while (light_isdigit(*(++e))) { n *= 10; n += (*e - '0'); }
            if (*e == 'U') {
                /* Note: this is not cryptographically strong */
                unsigned char x[16];
                li_rand_pseudo_bytes((unsigned char *)x, sizeof(x));
                if (n & 1) ++n;
                n <<= 1;
                if (0 == n || sizeof(x) < n) n = sizeof(x);
                buffer_append_string_encoded_hex_lc(&auth_rec->uid,(char *)x,n);
                b = e+1;
                break;
            }
            else {
                buffer_append_string_len(&auth_rec->uid, CONST_STR_LEN("%"));
                ++b;
                continue;
            }
        }
        e = u->ptr + buffer_clen(u);
        if (e - b) buffer_append_string_len(&auth_rec->uid, b, (size_t)(e - b));
    }
}/*}}}*/

/* ticket authentication entry point */
static handler_t mod_authn_tkt_check(request_st * const r, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend) /*{{{*/
{
    UNUSED(backend);
    mod_authn_tkt_plugin_data *p = p_d;
    mod_authn_tkt_patch_config(r, p);
    const mod_authn_tkt_plugin_opts * const opts = p->conf.auth_opts;
    authn_tkt * const auth_rec = &p->auth_rec;

    if (opts->auth_require_ssl) {
        /* redirect/login if scheme not "https" and require-ssl is set */
        /* (This option is part of authn_tkt to help users avoid mistakes in
         *  module ordering which might result in cookie auth being performed
         *  prior to redirect to https) */
        if (r->con->proto_default_port != 443) { /* r->uri.scheme "https" */
          #if 0 /* noisy; use access logs to flag insecure requests */
            log_error(r->conf.errh, __FILE__, __LINE__,
                "redirect/login - unsecured request, "
                "authn_tkt require-ssl is enabled");
          #endif
            /* XXX: should this redirect to same URL but https,
             * instead of to auth_login_url? */
            return authn_tkt_redirect(r, opts, NULL, &auth_rec->tmp_buf);
        }
    }

    auth_rec->addr_buf = opts->auth_ignore_ip ? NULL : &r->con->dst_addr_buf;
    auth_rec->refresh_cookie = 0;
    auth_rec->digest_fn = opts->auth_digest_fn;
    auth_rec->digest_len = opts->auth_digest_len;
    buffer_clear(&auth_rec->user_data);
    buffer_clear(&auth_rec->tokens);
    int init_guest = 0;

    /* check query string and cookie headers for ticket
     *   - either found (accept) or empty (reset/login) */
    if (authn_tkt_from_querystring(r, p) || authn_tkt_from_cookie(r, p)) {
        /* module is misconfigured unless secret is set */
        if (!opts->auth_secret) {
            log_error(r->conf.errh, __FILE__, __LINE__, "need secret");
            r->http_status = 500;
            return HANDLER_FINISHED;
        }

        if (!check_digest(opts, auth_rec)
            && !(init_guest = opts->auth_guest_login)) {
            return authn_tkt_redirect(r, opts, NULL, &auth_rec->tmp_buf);
        }

        /* check timeout */
        if (0 != opts->auth_timeout && !init_guest
            && !check_timeout(opts, auth_rec, log_epoch_secs)) {
            if (!(init_guest = opts->auth_guest_fallback)) {
                const buffer *redirect_url = opts->auth_timeout_url;
                if (r->http_method == HTTP_METHOD_POST
                    && opts->auth_post_timeout_url) {
                    redirect_url = opts->auth_post_timeout_url;
                }
                /* Delete cookie (set expired) in case we want to set from url*/
                send_auth_cookie(r, opts, opts->auth_cookie_name, NULL, 0);
                return authn_tkt_redirect(r, opts, redirect_url,
                                          &auth_rec->tmp_buf);
            }
        }
    }
    else if (!(init_guest = opts->auth_guest_login)) {
        return authn_tkt_redirect(r, opts, NULL, &auth_rec->tmp_buf);
    }

    /* initialize auth_rec as guest (if flagged) */
    if (init_guest) init_guest_auth_rec(opts, auth_rec);

    /* check authorization for auth_rec user (required) */
    if (!http_auth_match_rules(require, auth_rec->uid.ptr, NULL, NULL)) {
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "user NOT matched %s", auth_rec->uid.ptr);
        return authn_tkt_redirect(r, opts, opts->auth_unauth_url,
                                  &auth_rec->tmp_buf);
    }

    /* check authorization for auth_rec tokens (optional) */
    if (!check_tokens(r, opts, auth_rec)) {
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "tokens NOT matched %s", auth_rec->tokens.ptr);
        return authn_tkt_redirect(r, opts, opts->auth_unauth_url,
                                  &auth_rec->tmp_buf);
    }

    /* refresh cookie (if flagged) */
    if (auth_rec->refresh_cookie) refresh_cookie(r, opts, auth_rec);

    /* set CGI/FCGI/SCGI environment */ /* XXX: ? set AUTH_TYPE="authn_tkt" ? */
    http_auth_setenv(r, BUF_PTR_LEN(&auth_rec->uid), CONST_STR_LEN("Basic"));
    http_header_env_set(r, CONST_STR_LEN("REMOTE_USER_DATA"),
                           BUF_PTR_LEN(&auth_rec->user_data));
    http_header_env_set(r, CONST_STR_LEN("REMOTE_USER_TOKENS"),
                           BUF_PTR_LEN(&auth_rec->tokens));
    return HANDLER_GO_ON;  /* access granted */
}/*}}}*/

/* configuration processing & checking */
static char *convert_to_seconds(const buffer * const cfg, int * const timeout)/*{{{*/
{
    char *endptr;
    unsigned long int n, m;

    if (buffer_is_blank(cfg)) {
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

static void plugin_config_init_defaults(mod_authn_tkt_plugin_opts * const opts) /*{{{*/
{
    static const buffer default_auth_cookie_name =
      { CONST_STR_LEN(AUTH_COOKIE_NAME)+1, 0 };

    /*memset(opts, 0, sizeof(mod_authn_tkt_plugin_opts));*/
    opts->auth_cookie_secure = -1;
    opts->auth_timeout = DEFAULT_TIMEOUT_SEC;
    opts->auth_timeout_refresh = DEFAULT_TIMEOUT_SEC / 2;
    opts->auth_digest_fn  = MD5_iov;
    opts->auth_digest_len = MD5_DIGEST_LENGTH;
    opts->auth_cookie_name = &default_auth_cookie_name;
}/*}}}*/

static int parse_opts(server * const srv, mod_authn_tkt_plugin_opts * const opts, const array * const a) /*{{{*/
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("secret"),            /* TKTAuthSecret */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("secret-old"),        /* TKTAuthSecretOld */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("login-url"),         /* TKTAuthLoginURL */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("timeout-url"),       /* TKTAuthTimeoutURL */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("post-timeout-url"),  /* TKTAuthPostTimeoutURL */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("unauth-url"),        /* TKTAuthUnauthURL */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("timeout"),           /* TKTAuthTimeout */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("timeout-refresh"),   /* TKTAuthTimeoutRefresh */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("digest-type"),       /* TKTAuthDigestType */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ignore-ip"),         /* TKTAuthIgnoreIP */
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("require-ssl"),       /* TKTAuthRequireSSL */
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cookie-secure"),     /* TKTAuthCookieSecure */
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cookie-name"),       /* TKTAuthCookieName */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cookie-domain"),     /* TKTAuthDomain */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cookie-expires"),    /* TKTAuthCookieExpires */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("back-cookie-name"),  /* TKTAuthBackCookieName */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("back-arg-name"),     /* TKTAuthBackArgName */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("guest-user"),        /* TKTAuthGuestUser */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("guest-login"),       /* TKTAuthGuestLogin */
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("guest-cookie"),      /* TKTAuthGuestCookie */
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("guest-fallback"),    /* TKTAuthGuestFallback */
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("tokens"),            /* TKTAuthToken */
        T_CONFIG_ARRAY_KVARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    config_plugin_value_t cvlist[sizeof(cpk)/sizeof(cpk[0])+1];
    memset(cvlist, 0, sizeof(cvlist));

    if (!config_plugin_values_init_block(srv, a, cpk, "auth.method.tkt.opts",
                                         cvlist))
        return 0;

    const buffer *auth_timeout_refresh_conf = NULL;

    config_plugin_value_t *cpv = cvlist;
    for (; -1 != cpv->k_id; ++cpv) {
        switch (cpv->k_id) {
          case 0: /* secret */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_secret = cpv->v.b;
            break;
          case 1: /* secret-old */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_secret_old = cpv->v.b;
            break;
          case 2: /* login-url */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_login_url = cpv->v.b;
            break;
          case 3: /* timeout-url */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_timeout_url = cpv->v.b;
            break;
          case 4: /* post-timeout-url */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_post_timeout_url = cpv->v.b;
            break;
          case 5: /* unauth-url */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_unauth_url = cpv->v.b;
            break;
          case 6: /* timeout */
            if (!buffer_is_blank(cpv->v.b)) {
                const char * const msg =
                  convert_to_seconds(cpv->v.b, &opts->auth_timeout);
                if (msg) {
                    log_error(srv->errh, __FILE__, __LINE__, "%s", msg);
                    return 0;
                }
            }
            break;
          case 7: /* timeout-refresh */
            if (!buffer_is_blank(cpv->v.b))
                auth_timeout_refresh_conf = cpv->v.b;
            break;
          case 8: /* digest-type */
            if (!buffer_is_blank(cpv->v.b)) {
                if (buffer_eq_slen(cpv->v.b, CONST_STR_LEN("MD5"))) {
                    opts->auth_digest_fn  = MD5_iov;
                    opts->auth_digest_len = MD5_DIGEST_LENGTH;
                }
              #ifdef USE_LIB_CRYPTO_SHA256
                else if (buffer_eq_slen(cpv->v.b, CONST_STR_LEN("SHA256"))) {
                    opts->auth_digest_fn  = SHA256_iov;
                    opts->auth_digest_len = SHA256_DIGEST_LENGTH;
                }
              #endif
              #ifdef SHA512_DIGEST_LENGTH
                else if (buffer_eq_slen(cpv->v.b, CONST_STR_LEN("SHA512"))) {
                    opts->auth_digest_fn  = SHA512_iov;
                    opts->auth_digest_len = SHA512_DIGEST_LENGTH;
                }
              #endif
                else {
                  #if defined(SHA512_DIGEST_LENGTH)
                    log_error(srv->errh, __FILE__, __LINE__,
                      "digest-type must be one of: "
                      "\"MD5\", \"SHA256\", \"SHA512\"");
                  #elif defined(USE_LIB_CRYPTO_SHA256)
                    log_error(srv->errh, __FILE__, __LINE__,
                      "digest-type must be one of: "
                      "\"MD5\", \"SHA256\"");
                  #else
                    log_error(srv->errh, __FILE__, __LINE__,
                      "digest-type must be: \"MD5\" "
                      "(Rebuild lighttpd with crypto libs for "
                      "additional options.)");
                  #endif
                    return 0;
                }
            }
            break;
          case 9: /* ignore-ip */
            opts->auth_ignore_ip = (0 != cpv->v.u);
            break;
          case 10:/* require-ssl */
            opts->auth_require_ssl = (0 != cpv->v.u);
            break;
          case 11:/* cookie-secure */
            opts->auth_cookie_secure = (0 != cpv->v.u);
            break;
          case 12:/* cookie-name */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_cookie_name = cpv->v.b;
            break;
          case 13:/* cookie-domain */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_cookie_domain = cpv->v.b;
            break;
          case 14:/* cookie-expires */
            if (!buffer_is_blank(cpv->v.b)) {
                 const char * const msg =
                  convert_to_seconds(cpv->v.b, &opts->auth_cookie_expires);
                if (msg) {
                    log_error(srv->errh, __FILE__, __LINE__,
                              "cookie-expires %s", msg);
                    return 0;
                }
            }
            break;
          case 15:/* back-cookie-name */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_back_cookie_name = cpv->v.b;
            break;
          case 16:/* back-arg-name */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_back_arg_name = cpv->v.b;
            break;
          case 17:/* guest-user */
            if (!buffer_is_blank(cpv->v.b))
                opts->auth_guest_user = cpv->v.b;
            break;
          case 18:/* guest-login */
            opts->auth_guest_login = (0 != cpv->v.u);
            break;
          case 19:/* guest-cookie */
            opts->auth_guest_cookie = (0 != cpv->v.u);
            break;
          case 20:/* guest-fallback */
            opts->auth_guest_fallback = (0 != cpv->v.u);
            break;
          case 21:/* tokens */
            if (cpv->v.a->used) {
                /*
                 * "tokens" = ( "<path>" => ( ..., ... ),
                 *              "<path>" => ( ..., ... ) )
                 */
                const array * const t = cpv->v.a;
                for (uint32_t i = 0; i < t->used; ++i) {
                    if (!array_is_vlist(&((data_array *)t->data[i])->value)) {
                        log_error(srv->errh, __FILE__, __LINE__,
                          "unexpected value for tokens.  "
                          "tokens should contain an array as in: "
                          "\"tokens\" = "
                          "( \"path\" => ( \"token1\", \"token2\") )");
                        return 0;
                    }
                }
                opts->auth_tokens = t;
            }
            break;
          default:
            break;
        }
    }

    if (opts->auth_require_ssl) {
        if (-1 == opts->auth_cookie_secure) {
            /* Backwards compatibility mode for require-ssl */
            /* Set secure_cookie flag if require-ssl is set
             * and secure_cookie is undefined (as opposed to 'off') */
          #if 0 /* noisy; must explicitly configure if insecure desired */
            log_error(srv->errh, __FILE__, __LINE__,
                "WARNING: require-ssl on, but no cookie-secure found - "
                "please set cookie-secure explicitly; assuming 'enabled'");
          #endif
            opts->auth_cookie_secure = 1;
        }
    }

    if (auth_timeout_refresh_conf) {
        /* The timeout refresh is a double between 0 and 1, signifying what
         * proportion of the timeout should be left before we refresh i.e.
         * 0 means never refresh (hard timeouts); 1 means always refresh;
         * .33 means only refresh if less than a third of the timeout
         * period remains. */
        double refresh = atof(auth_timeout_refresh_conf->ptr);
        if (refresh < 0.0 || refresh > 1.0) {
            log_error(srv->errh, __FILE__, __LINE__,
                      "refresh must be between 0.0 and 1.0");
            return 0;
        }
        opts->auth_timeout_refresh = (int)(refresh * opts->auth_timeout);
    }

    return 1;
}/*}}}*/

SETDEFAULTS_FUNC(mod_authn_tkt_set_defaults) /*{{{*/
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("auth.method.tkt.opts"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    mod_authn_tkt_plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_authn_tkt"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* auth.method.tkt.opts */
                if (cpv->v.a->used) {
                    mod_authn_tkt_plugin_opts * const x =
                      ck_calloc(1, sizeof(mod_authn_tkt_plugin_opts));
                    const array * const a = cpv->v.a;
                    cpv->vtype = T_CONFIG_LOCAL;
                    cpv->v.v = x;
                    plugin_config_init_defaults(x);
                    if (!parse_opts(srv, x, a)) return HANDLER_ERROR;
                }
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    plugin_config_init_defaults(&p->default_auth_opts);
    p->defaults.auth_opts = &p->default_auth_opts;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_authn_tkt_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}/*}}}*/

int mod_authn_tkt_plugin_init(plugin *p);
int mod_authn_tkt_plugin_init(plugin *p) /*{{{*/
{
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "authn_tkt";
	p->init        = mod_authn_tkt_init;
	p->set_defaults= mod_authn_tkt_set_defaults;
	p->cleanup     = mod_authn_tkt_free;

	p->data        = NULL;

	return 0;
}/*}}}*/
