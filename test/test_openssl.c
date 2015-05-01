#include "mruby.h"
#include "mruby/string.h"

extern int mrb_openssl_match_dns_id(const char *, const char *);

mrb_value
mrb_tls_openssl_test_match_dns_id(mrb_state *mrb, mrb_value klass)
{
  mrb_value refid, prid;
  int result;

  mrb_get_args(mrb, "SS", &refid, &prid);
  result = mrb_openssl_match_dns_id(mrb_str_to_cstr(mrb, refid), mrb_str_to_cstr(mrb, prid));
  return mrb_bool_value(result);
}

void
mrb_mruby_tls_openssl_gem_test(mrb_state *mrb)
{
  struct RClass *c = mrb_define_module(mrb, "OpenSSLTest");

  mrb_define_class_method(mrb, c, "match_dns_id", mrb_tls_openssl_test_match_dns_id, MRB_ARGS_REQ(2));
}
