#include <sys/time.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

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

static mrb_value
mrb_openssl_ssl_ctx_init(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl_ctx *mrb_ctx;
  SSL_CTX *ctx;

  ctx = SSL_CTX_new(TLSv1_client_method());
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

static mrb_value
mrb_openssl_ssl_ctx_set_verify(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl_ctx *mrb_ctx;

  mrb_ctx = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_ctx_type);
  SSL_CTX_set_verify(mrb_ctx->ctx, SSL_VERIFY_PEER, NULL);
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

static int
wildcard_name_match(const char *pat, int patlen, const char *name)
{
  const char *cp;

  // "pat" must begin with "*.".
  if (patlen < 2 || pat[0] != '*' || pat[1] != '.') {
    return 0;
  }

  // skip first label, or return false.
  cp = strchr(name, '.');
  if (cp == NULL) {
    return 0;
  }

  return strcasecmp(pat + 2, cp + 1) == 0;
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
  int addrlen, i, j, k, n, ok;
  char *utf8str;
  char addrbuf[16], addrbuf2[16];
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
      if (name == NULL)
        continue;
      cp = (const char *)ASN1_STRING_data(name->d.ia5);
      k = ASN1_STRING_length(name->d.ia5);
      if (addrlen == -1 && name->type == GEN_DNS) {
        ok = 0;
        if (strlen(cp) != k)
          continue;
        if (wildcard_name_match(cp, k, idstr)) {
          ok = 1;
          break;
        }
        if (strcasecmp(cp, idstr) == 0) {
          ok = 1;
          break;
        }
      } else if (addrlen != -1 && name->type == GEN_IPADD) {
        ok = 0;
        if (k == addrlen && memcmp(cp, addrbuf, k) == 0) {
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
   n = ASN1_STRING_to_UTF8((unsigned char **)&utf8str, as);
   if (utf8str == NULL) {
     X509_free(cert);
     mrb_raise(mrb, E_RUNTIME_ERROR, "ASN1_STRING_to_UTF8 failed");
   }
   if (strlen(utf8str) != n) {
     OPENSSL_free(utf8str);
     X509_free(cert);
     mrb_raise(mrb, E_RUNTIME_ERROR, "CN includes NUL char!");
   }

   if (addrlen == 4) {
     ok = (inet_pton(AF_INET, utf8str, addrbuf2) == 1 &&
           memcmp(addrbuf, addrbuf2, addrlen) == 0);
   } else if (addrlen == 16) {
     ok = (inet_pton(AF_INET6, utf8str, addrbuf2) == 1 &&
           memcmp(addrbuf, addrbuf2, addrlen) == 0);
   } else {
     ok = (strcasecmp(utf8str, idstr) == 0);
   }
   if (! ok) {
     char buf[128];
     snprintf(buf, sizeof(buf), "CN differs from Host: CN=%s, Host=%s", utf8str, idstr);
     OPENSSL_free(utf8str);
     X509_free(cert);
     mrb_raise(mrb, E_RUNTIME_ERROR, buf);
   }

   OPENSSL_free(utf8str);
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
    mrb_value reason = mrb_str_new_cstr(mrb, ERR_reason_error_string(ERR_peek_last_error()));
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
