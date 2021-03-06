#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <win32netcompat.h>
#endif
#include <sys/time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include "mruby.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/string.h"

/*
 * OpenSSL::SSL_CTX
 */

struct mrb_openssl_ssl_ctx {
  SSL_CTX *ctx;
};

static void mrb_openssl_ssl_ctx_free(mrb_state *mrb, void *ptr);

const static struct mrb_data_type mrb_openssl_ssl_ctx_type = { "OpenSSL::SSL_CTX", mrb_openssl_ssl_ctx_free };

static void
mrb_openssl_ssl_ctx_free(mrb_state *mrb, void *ptr)
{
  struct mrb_openssl_ssl_ctx *mrb_ctx = ptr;
  if (mrb_ctx->ctx != NULL) {
    SSL_CTX_free(mrb_ctx->ctx);
  }
  mrb_free(mrb, ptr);
}

static const SSL_METHOD *
method_str_to_val(mrb_state *mrb, mrb_value str)
{
  const char *cp;
  size_t len;

  cp  = RSTRING_PTR(str);
  len = RSTRING_LEN(str);
  if (strncmp("TLSv1.0", cp, len) == 0) {
    return TLSv1_client_method();
  } else if (strncmp("TLSv1.1", cp, len) == 0) {
    return TLSv1_1_client_method();
  } else if (strncmp("TLSv1.2", cp, len) == 0) {
    return TLSv1_2_client_method();
  } else if (strncmp("any", cp, len) == 0) {
    return SSLv23_client_method();
  }

  mrb_raisef(mrb, E_RUNTIME_ERROR, "TLS/SSL version %S is not supported", str);
  return NULL;
}

static mrb_value
mrb_openssl_ssl_ctx_init(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl_ctx *mrb_ctx;
  SSL_CTX *ctx;
  const SSL_METHOD *method;
  mrb_value str;

  mrb_get_args(mrb, "S", &str);
  method = method_str_to_val(mrb, str);

  ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "SSL_CTX_new failed");
  }

  mrb_ctx = (struct mrb_openssl_ssl_ctx *)mrb_malloc(mrb, sizeof(*mrb_ctx));
  mrb_ctx->ctx = ctx;
  DATA_TYPE(self) = &mrb_openssl_ssl_ctx_type;
  DATA_PTR(self)  = mrb_ctx;
  return self;
}

static mrb_value
mrb_openssl_ssl_ctx_load_verify_locations(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl_ctx *mrb_ctx;
  mrb_value str;
  char *cp;

  mrb_ctx = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_ctx_type);
  mrb_get_args(mrb, "S", &str);
  cp = mrb_str_to_cstr(mrb, str);
  if (SSL_CTX_load_verify_locations(mrb_ctx->ctx, cp, NULL) != 1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_CTX_load_verify_locations(\"%S\") failed", str);
  }
  return self;
}

static mrb_value
mrb_openssl_ssl_ctx_set_alpn_protos(mrb_state *mrb, mrb_value self)
{
#if OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined(LIBRESSL_VERSION_NUMBER)
  struct mrb_openssl_ssl_ctx *mrb_ctx;
  mrb_value buf, str;
  mrb_int len;
  unsigned char *cp;

  mrb_ctx = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_ctx_type);
  mrb_get_args(mrb, "S", &str);
  len = RSTRING_LEN(str);
  buf = mrb_str_buf_new(mrb, len+1);
  cp = (unsigned char *)RSTRING_PTR(buf);
  *cp = (unsigned char)len; /* XXX len must be <= 255 */
  memcpy(cp+1, RSTRING_PTR(str), len);
  if (SSL_CTX_set_alpn_protos(mrb_ctx->ctx, cp, len+1) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "SSL_CTX_set_alpn_protos() failed");
  }
  return self;
#else
  mrb_raise(mrb, E_NOTIMP_ERROR, "SSL_CTX_set_alpn_protos() is not available");
  return self;
#endif
}

static mrb_value
mrb_openssl_ssl_ctx_set_verify_depth(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl_ctx *mrb_ctx;
  mrb_int n;

  mrb_ctx = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_ctx_type);
  mrb_get_args(mrb, "i", &n);
  SSL_CTX_set_verify_depth(mrb_ctx->ctx, n);
  return self;
}

static int
ssl_ctx_verify_callback_ignorevalidity(int ok, X509_STORE_CTX *ctx)
{
  if (ok == 0) {
    int ecode = X509_STORE_CTX_get_error(ctx);
    if (ecode == X509_V_ERR_CERT_NOT_YET_VALID || ecode == X509_V_ERR_CERT_HAS_EXPIRED) {
      X509_STORE_CTX_set_error(ctx, X509_V_OK);
      return 1;
    }
  }
  return ok;
}

static mrb_value
mrb_openssl_ssl_ctx_set_verify(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl_ctx *mrb_ctx;
  mrb_value b = mrb_nil_value();
  mrb_get_args(mrb, "|o", &b);
  mrb_ctx = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_ctx_type);
  if (mrb_bool(b)) { // :ignore_certificate_validity
    SSL_CTX_set_verify(mrb_ctx->ctx, SSL_VERIFY_PEER, ssl_ctx_verify_callback_ignorevalidity);
  } else {
    SSL_CTX_set_verify(mrb_ctx->ctx, SSL_VERIFY_PEER, NULL);
  }
  return self;
}

/*
 * OpenSSL::SSL
 */

struct mrb_openssl_ssl {
  SSL *ssl;
};
static void mrb_openssl_ssl_free(mrb_state *mrb, void *ptr);

const static struct mrb_data_type mrb_openssl_ssl_type = { "OpenSSL::SSL", mrb_openssl_ssl_free };

static void
mrb_openssl_ssl_free(mrb_state *mrb, void *ptr)
{
  struct mrb_openssl_ssl *mrb_ssl = ptr;
  if (mrb_ssl->ssl != NULL) {
    SSL_free(mrb_ssl->ssl);
  }
  mrb_free(mrb, ptr);
}

int
mrb_openssl_match_dns_id(const char *ref_id, const char *pr_id)
{
  const char *dotp, *pr_domain, *ref_domain;

  if (strchr(pr_id, '*') == NULL) {
    /* no wildcard characters - it's easy */
    return strcasecmp(ref_id, pr_id) == 0;
  }

  /* Note: we don't support partial matching like "f*.com". */

  if (pr_id[0] != '*' || pr_id[1] != '.') {
    /* reject any wildcard identifier DOES NOT start with "*." */
    return 0;
  }

  /* where pr_id = "*.example.com", pr_domain points to "example.com" */
  pr_domain = pr_id + 2;

  if (strchr(pr_domain, '*') != NULL) {
    /* reject multiple wildcard characters (e.g. "*.*.com", "*.example.*") */
    return 0;
  }

  /* where pr_domain = "example.com", dotp points to ".com" */
  dotp = strchr(pr_domain, '.');
  if (dotp == NULL) {
    /* reject "*.tld" and "*." */
    return 0;
  }

  if (! isalnum(dotp[1])) {
    /* reject invalid domain name (e.g. "*.com.", "*.net..", "*.foo.-org") */
    return 0;
  }

  ref_domain = strchr(ref_id, '.');
  if (ref_domain == NULL) {
    /* if ref_id has no dot, it never matches */
    return 0;
  }
  ref_domain++;

  return strcasecmp(pr_domain, ref_domain) == 0;
}

static mrb_value
mrb_openssl_ssl_check_identity(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl *mrb_ssl;
  ASN1_STRING *as;
  GENERAL_NAME *name;
  STACK_OF(GENERAL_NAME) *altnames;
  X509 *cert;
  X509_NAME *subj;
  int addrlen, cplen, i, j, n, ok;
  char addrbuf[16];
  const char *cp, *idstr;
  mrb_value id;

  mrb_ssl = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_type);
  mrb_get_args(mrb, "S", &id);
  idstr = mrb_str_to_cstr(mrb, id);

  cert = SSL_get_peer_certificate(mrb_ssl->ssl);
  if (cert == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "SSL_get_peer_certificate() failed");
  }

  if (inet_pton(AF_INET, idstr, addrbuf) == 1) {
    addrlen = 4;
  } else if (inet_pton(AF_INET6, idstr, addrbuf) == 1) {
    addrlen = 16;
  } else {
    addrlen = -1;
  }

  altnames = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  if (altnames != NULL) {
    ok = -1;

    n = sk_GENERAL_NAME_num(altnames);
    for (i = 0; i < n; i++) {
      name = sk_GENERAL_NAME_value(altnames, i);
      if (addrlen == -1 && name->type == GEN_DNS) {
        ok = 0;
        cp = (const char *)ASN1_STRING_data(name->d.ia5);
        cplen = ASN1_STRING_length(name->d.ia5);
        if (strlen(cp) != cplen) {
          /* contains NUL character! it should be a malicious certificate. */
          ok = 0;
          break;
        }
        if (mrb_openssl_match_dns_id(idstr, cp)) {
          ok = 1;
          break;
        }
      } else if (addrlen != -1 && name->type == GEN_IPADD) {
        ok = 0;
        cp = (const char *)ASN1_STRING_data(name->d.iPAddress);
        cplen = ASN1_STRING_length(name->d.iPAddress);
        if (cplen == addrlen && memcmp(cp, addrbuf, cplen) == 0) {
          ok = 1;
          break;
        }
      }
    }
    sk_GENERAL_NAME_free(altnames);

    if (ok == 1) {
      X509_free(cert);
      return mrb_true_value();
    } else if (ok == 0) {
      X509_free(cert);
      if (addrlen == -1) {
        mrb_raisef(mrb, E_RUNTIME_ERROR, "dNSName of server certificate does not match \"%S\"", id);
      }
      else {
        mrb_raisef(mrb, E_RUNTIME_ERROR, "iPAddress of server certificate does not match \"%S\"", id);
      }
    }
  }

  if (addrlen != -1) {
    X509_free(cert);
    mrb_raise(mrb, E_RUNTIME_ERROR, "identity is an IP address but server certificate does not have iPAddress");
  }

  subj = X509_get_subject_name(cert);
  if (subj == NULL) {
    X509_free(cert);
    mrb_raise(mrb, E_RUNTIME_ERROR, "server certificate has neither subjectAltName nor subjectName");
  }

  j = -1;
  do {
    i = j;
    j = X509_NAME_get_index_by_NID(subj, NID_commonName, i);
  } while (j != -1);
  if (i == -1) {
    X509_free(cert);
    mrb_raise(mrb, E_RUNTIME_ERROR, "server certificate has no commonName");
  }

   as = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subj, i));
   if (as == NULL) {
     X509_free(cert);
     mrb_raise(mrb, E_RUNTIME_ERROR, "X509_NAME_ENTRY_get_data failed");
   }
   cp = (const char *)ASN1_STRING_data(as);
   cplen = ASN1_STRING_length(as);
   if (strlen(cp) != cplen) {
     X509_free(cert);
     mrb_raise(mrb, E_RUNTIME_ERROR, "CN includes NUL char!");
   }

   if (! mrb_openssl_match_dns_id(idstr, cp)) {
     char buf[128];
     snprintf(buf, sizeof(buf), "CN differs from Host: CN=%s, Host=%s", cp, idstr);
     X509_free(cert);
     mrb_raise(mrb, E_RUNTIME_ERROR, buf);
   }

   X509_free(cert);
   return mrb_true_value();
}

static mrb_value
mrb_openssl_ssl_connect(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl *mrb_ssl;
  int ret;

  mrb_ssl = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_type);
  ret = SSL_connect(mrb_ssl->ssl);
  if (ret != 1) {
    mrb_value reason;
    unsigned long e, ecode = 0;
    long result;
    while ((e = ERR_get_error()) != 0) {
      ecode = e;
    }
    reason = mrb_str_new_cstr(mrb, ERR_reason_error_string(ecode));

    result = SSL_get_verify_result(mrb_ssl->ssl);
    if (result != X509_V_OK) {
      mrb_str_cat_cstr(mrb, reason, ": ");
      mrb_str_cat_cstr(mrb, reason, X509_verify_cert_error_string(result));
    }

    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_connect() failed: %S", reason);
  }
  return self;
}

static mrb_value
mrb_openssl_ssl_get_verify_result(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl *mrb_ssl;
  long result;

  mrb_ssl = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_type);
  result = SSL_get_verify_result(mrb_ssl->ssl);
  if (result != X509_V_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "certificate verification error");
  }
  return mrb_true_value();
}

static mrb_value
mrb_openssl_ssl_set_fd(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl *mrb_ssl;
  mrb_int fd;

  mrb_ssl = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_type);
  mrb_get_args(mrb, "i", &fd);
  if (SSL_set_fd(mrb_ssl->ssl, fd) == 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_set_fd(%S) failed", mrb_fixnum_value(fd));
  }
  return self;
}

static mrb_value
mrb_openssl_ssl_set_tlsext_host_name(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl *mrb_ssl;
  mrb_value str;
  char *cp;

  mrb_ssl = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_type);
  mrb_get_args(mrb, "S", &str);
  cp = mrb_str_to_cstr(mrb, str);
  if (SSL_set_tlsext_host_name(mrb_ssl->ssl, cp) == 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_set_tlsext_host_name(\"%S\") failed", str);
  }
  return self;
}

static mrb_value
mrb_openssl_ssl_read(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl *mrb_ssl;
  mrb_value buf;
  mrb_int len = 0;
  size_t bufsize;
  int n;

  mrb_ssl = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_type);
  mrb_get_args(mrb, "|i", &len);

  if (len > 0) {
    bufsize = len;
  } else {
    bufsize = 16384;    /* TLS record size */
  }
  buf = mrb_str_buf_new(mrb, bufsize);
  n = SSL_read(mrb_ssl->ssl, RSTRING_PTR(buf), bufsize);
  if (n == 0) {
    return mrb_nil_value();
  } else if (n < 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_read returns %S", mrb_fixnum_value(n));
  }
  mrb_str_resize(mrb, buf, n);
  return buf;
}

static mrb_value
mrb_openssl_ssl_shutdown(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl *mrb_ssl;
  int r;

  mrb_ssl = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_type);
  r = SSL_shutdown(mrb_ssl->ssl);
  if (r < 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_shutdown returns %S", mrb_fixnum_value(r));
  }
  return mrb_fixnum_value(r);
}

static mrb_value
mrb_openssl_ssl_write(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl *mrb_ssl;
  mrb_int len;
  int n;
  char *cp;

  mrb_ssl = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_type);
  mrb_get_args(mrb, "s", &cp, &len);
  n = SSL_write(mrb_ssl->ssl, cp, len);
  return mrb_fixnum_value(n);
}

static mrb_value
mrb_openssl_ssl_init(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl *mrb_ssl;
  struct mrb_openssl_ssl_ctx *mrb_ctx;
  SSL *ssl;
  mrb_value v_ctx;

  mrb_get_args(mrb, "o", &v_ctx);
  mrb_ctx = mrb_data_get_ptr(mrb, v_ctx, &mrb_openssl_ssl_ctx_type);

  mrb_ssl = (struct mrb_openssl_ssl *)mrb_malloc(mrb, sizeof(*mrb_ssl));

  ssl = SSL_new(mrb_ctx->ctx);
  if (ssl == NULL) {
    mrb_free(mrb, mrb_ssl);
    mrb_raise(mrb, E_RUNTIME_ERROR, "SSL_new failed");
  }

  mrb_ssl->ssl = ssl;
  DATA_TYPE(self) = &mrb_openssl_ssl_type;
  DATA_PTR(self)  = mrb_ssl;
  return self;
}

void
mrb_mruby_tls_openssl_gem_init(mrb_state *mrb)
{
  struct RClass *c_ctx, *c_ssl, *m;

  SSL_load_error_strings();
  SSL_library_init();

  m = mrb_define_module(mrb, "OpenSSL");

  c_ssl = mrb_define_class_under(mrb, m, "SSL", mrb->object_class);
  MRB_SET_INSTANCE_TT(c_ssl, MRB_TT_DATA);
  mrb_define_method(mrb, c_ssl, "initialize", mrb_openssl_ssl_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, c_ssl, "check_identity", mrb_openssl_ssl_check_identity, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c_ssl, "connect", mrb_openssl_ssl_connect, MRB_ARGS_NONE());
  mrb_define_method(mrb, c_ssl, "get_verify_result", mrb_openssl_ssl_get_verify_result, MRB_ARGS_NONE());
  mrb_define_method(mrb, c_ssl, "read", mrb_openssl_ssl_read, MRB_ARGS_OPT(2));
  mrb_define_method(mrb, c_ssl, "set_fd", mrb_openssl_ssl_set_fd, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c_ssl, "set_tlsext_host_name", mrb_openssl_ssl_set_tlsext_host_name, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c_ssl, "shutdown", mrb_openssl_ssl_shutdown, MRB_ARGS_NONE());
  mrb_define_method(mrb, c_ssl, "write", mrb_openssl_ssl_write, MRB_ARGS_REQ(1));

  c_ctx = mrb_define_class_under(mrb, m, "SSL_CTX", mrb->object_class);
  MRB_SET_INSTANCE_TT(c_ctx, MRB_TT_DATA);
  mrb_define_method(mrb, c_ctx, "initialize", mrb_openssl_ssl_ctx_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, c_ctx, "load_verify_locations", mrb_openssl_ssl_ctx_load_verify_locations, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c_ctx, "set_alpn_protos", mrb_openssl_ssl_ctx_set_alpn_protos, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c_ctx, "set_verify", mrb_openssl_ssl_ctx_set_verify, MRB_ARGS_NONE());
  mrb_define_method(mrb, c_ctx, "set_verify_depth", mrb_openssl_ssl_ctx_set_verify_depth, MRB_ARGS_REQ(1));
}

void
mrb_mruby_tls_openssl_gem_final(mrb_state *mrb)
{
}
