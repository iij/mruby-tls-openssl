module HTTP2
  class Client
    FRAME_TYPE_HEADERS  = 0
    FRAME_TYPE_HEADERS  = 1
    FRAME_TYPE_SETTINGS = 4

    FRAME_FLAGS_ACK = 0x1

    def initialize(tls)
      @tls = tls
      @readbuf = ""
    end

    def make_frame(type, flags, stream, payload)
      [payload.size, type, flags, stream].pack("nCCN") + payload
    end

    def send_magic
      n = @tls.write "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
      puts "@tls.write -> #{n}"
    end

    def send_settings_frame
      #payload = [4, 100, 7, 256*256].pack "NNNN"
      frame = make_frame(4, 0, 0, "")
      puts "send_settings_frame: #{frame.inspect}"
      @tls.write frame
    end

    def send_settings_frame_ack
      frame = make_frame(FRAME_TYPE_SETTINGS, FRAME_FLAGS_ACK, 0, "")
      @tls.write frame
    end

    def send_headers_frame
      def make_a_header(key, val)
        "\x00" + [key.length].pack("C") + key + [val.length].pack("C") + val
      end

      payload = "\x00\x00"
      payload = ""
      payload += make_a_header(":method", "GET")
      payload += make_a_header(":scheme", "https")
      payload += make_a_header(":authority", "1.2.3.4:80")
      payload += make_a_header(":path", "/ltmain.sh")

      frame = make_frame(FRAME_TYPE_HEADERS, 5, 1, payload)
      @tls.write frame
    end

    def recv_settings_frame
      s = @tls.read(1000)
      p s
      a = s.unpack("nCCNa*")
      p a
    end

    def recv_headers_frame
      buf = @tls.read(1000)
      while buf.size > 0
        len, type, flags, stream = buf.unpack("nCCN")
        puts "Frame len=#{len}, type=#{type}, flags=#{flags}, stream-id=#{stream}"
        s = buf[8, len]
        puts "  payload=#{s.inspect}"

        buf.slice!(0, 8+len)
      end
    end

    def recv_data
      buf = @tls.read(1000)
      len, type, flags, stream = buf.unpack("nCCN")
      puts "Frame len=#{len}, type=#{type}, flags=#{flags}, stream-id=#{stream}"
      s = buf[8, len]
      puts "  payload=#{s.inspect}"
    end
  end
end


tls = TLS.new "nghttp2.org", 443, { :alpn => "h2-12" }
http2 = HTTP2::Client.new tls
http2.send_magic
http2.send_settings_frame
http2.recv_settings_frame

puts "recv settings ack"
http2.send_settings_frame_ack
http2.recv_settings_frame

puts "send headers"
http2.send_headers_frame
http2.recv_headers_frame

http2.recv_data

tls.close
