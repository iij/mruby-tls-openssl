class TLS
  def self.open(hostname, port=443, opts={})
    tls = self.new(hostname, port, opts)
    if block_given?
      yield tls
      tls.close
    end
    tls
  end

  def initialize(sock, port=443, opts={})
    if sock.is_a? String
      sock = TCPSocket.new(sock, port)
    end
    @sock = sock

    @ctx = OpenSSL::SSL_CTX.new (opts[:version] || :any)
    if opts[:certs]
      @ctx.load_verify_locations opts[:certs]
      @ctx.set_verify
      @ctx.set_verify_depth 5
    end
    if opts[:alpn]
      @ctx.set_alpn_protos opts[:alpn]
    end
    @ssl = OpenSSL::SSL.new(@ctx)
    @ssl.set_fd(sock.fileno)
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
