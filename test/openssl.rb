assert('certificate identity matching') do
  def ok(ref_id, pr_id)
    msg = "matching TLS identity: reference=#{ref_id.inspect}, presented=#{pr_id.inspect}"
    assert_true(OpenSSLTest.match_dns_id(ref_id, pr_id), msg)
  end
  def ng(ref_id, pr_id)
    msg = "matching TLS identity: reference=#{ref_id.inspect}, presented=#{pr_id.inspect}"
    assert_false(OpenSSLTest.match_dns_id(ref_id, pr_id), msg)
  end

  ok "www.example.com", "www.example.com"
  ok "WwW.ExAmPlE.CoM", "wWw.eXaMpLe.cOm"

  ok "www.example.com", "*.example.com"
  ok "WwW.ExAmPlE.CoM", "*.eXaMpLe.cOm"
  ok "www.a.example.com", "*.a.example.com"

  ng "www.example.com", "*"
  ng "www.example.com", "w*.example.com"
  ng "www.example.com", "*w.example.com"
  ng "www.example.com", "www.*.com"
  ng "example.com", "*."
  ng "example.com", "*.com"
  ng "example.com.", "*.com."

  ng "example.com", "*.example.com"
  ng "foo.bar.example.com", "*.example.com"
  ng "foo.bar.example.com", "*.*.example.com"
end
