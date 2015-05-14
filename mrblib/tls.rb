class TLS
  def self.open(hostname, opts={})
    tls = self.new(hostname, opts)
    if block_given?
      yield tls
      tls.close
    end
    tls
  end

  def initialize(host, opts={})
    if host.is_a? String
      @sock = TCPSocket.new(host, opts[:port] || 443)
    else
      @sock = host
      host = nil
    end

    @ctx = OpenSSL::SSL_CTX.new (opts[:version] || "any")
    if opts[:certs]
      @ctx.load_verify_locations opts[:certs]
      @ctx.set_verify opts[:ignore_certificate_validity]
      @ctx.set_verify_depth 5
    end
    if opts[:alpn]
      @ctx.set_alpn_protos opts[:alpn]
    end
    @ssl = OpenSSL::SSL.new(@ctx)
    @ssl.set_fd(@sock.fileno)
    if opts[:sni]
      if opts[:sni].is_a? String
        servername = opts[:sni]
      else
        servername = opts[:identity] || host
      end
      unless servername
        raise RuntimeError, 'requested SNI but identity is not known'
      end
      @ssl.set_tlsext_host_name(servername)
    end

    @ssl.connect

    if opts[:certs]
      @ssl.get_verify_result
      if opts[:identity]
        @ssl.check_identity opts[:identity]
      end
    end
  end

  def close
    @ssl.shutdown
  end

  def read(length=nil, outbuf=nil)
    return @ssl.read(length) if length

    result = ""
    while true
      s = @ssl.read
      break unless s
      result += s
    end
    result
  end

  def write(str)
    n = 0
    while str.size > 0
      i = @ssl.write(str)
      n += i
      str = str[i..-1]
    end
    n
  end
end
