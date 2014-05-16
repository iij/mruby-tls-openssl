#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
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
  cp = RSTRING_PTR(buf);
  *cp = (unsigned char)len; /* XXX len must be <= 255 */
  memcpy(cp+1, RSTRING_PTR(str), len);
  if (SSL_CTX_set_alpn_protos(mrb_ctx->ctx, cp, len+1) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "SSL_CTX_set_alpn_protos() failed");
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

static mrb_value
mrb_openssl_ssl_connect(mrb_state *mrb, mrb_value self)
{
  struct mrb_openssl_ssl *mrb_ssl;

  mrb_ssl = mrb_data_get_ptr(mrb, self, &mrb_openssl_ssl_type);
  if (SSL_connect(mrb_ssl->ssl) != 1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "SSL_connect() failed");
  }
  return self;
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
  mrb_define_method(mrb, c_ssl, "connect", mrb_openssl_ssl_connect, MRB_ARGS_NONE());
  mrb_define_method(mrb, c_ssl, "read", mrb_openssl_ssl_read, MRB_ARGS_OPT(2));
  mrb_define_method(mrb, c_ssl, "set_fd", mrb_openssl_ssl_set_fd, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c_ssl, "shutdown", mrb_openssl_ssl_shutdown, MRB_ARGS_NONE());
  mrb_define_method(mrb, c_ssl, "write", mrb_openssl_ssl_write, MRB_ARGS_REQ(1));

  c_ctx = mrb_define_class_under(mrb, m, "SSL_CTX", mrb->object_class);
  MRB_SET_INSTANCE_TT(c_ctx, MRB_TT_DATA);
  mrb_define_method(mrb, c_ctx, "initialize", mrb_openssl_ssl_ctx_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, c_ctx, "set_alpn_protos", mrb_openssl_ssl_ctx_set_alpn_protos, MRB_ARGS_REQ(1));
}

void
mrb_mruby_tls_openssl_gem_final(mrb_state *mrb)
{
}
