# Required mrbgems: mruby-pack, mruby-regexp-pcre(or some regexp mrbgem)

# TODO:
# - connect via proxy

module HTTP2
  FRAME_TYPE_DATA     = 0
  FRAME_TYPE_HEADERS  = 1
  FRAME_TYPE_SETTINGS = 4
  FRAME_TYPE_BLOCK    = 11

  class Client
    FRAME_FLAG_SETTINGS_ACK = 0x1

    def initialize(host, port=443)
      @tls = TLS.new host, port, { :alpn => "h2-13" }
      @tls = TLS.new host, port, {
        :alpn => "h2-13", :certs => "nghttp2.crt"  #, :identity => host
      }
      @recvbuf = ""
      @my_next_stream_id = 1
      @window = 0
      @streams = {}

      @settings = {
        :header_table_size => 4096,
        :enable_push => 1,
        :max_concurrent_streams => -1,  # no limit
        :enable_push => 1,
        :initial_window_size => 65535,
        :compress_data => 0
      }

      self.connect
    end

    def close
      # send goaway
      @tls.close
    end

    def connect
      self.send_magic
      self.send_settings_frame
      self.wait_for :settings_ack
    end

    def get path, &block
      stream = self.new_stream
      self.send_headers_frame path
      self.wait_for :data_end
      $stdout.write stream.response_body
    end

    def make_frame(type, flags, stream, payload)
      [payload.size, type, flags, stream].pack("nCCN") + payload
    end

    def new_stream
      id = @my_next_stream_id
      @my_next_stream_id += 2
      stream = Stream.new(self, id, @settings)
      @streams[id] = stream
      stream
    end

    def send_frame f
      @tls.write f.to_bytes
    end

    def send_magic
      @tls.write "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    end

    def send_settings_frame
      payload = ""
      frame = make_frame(4, 0, 0, "")
      puts "send_settings_frame: #{frame.inspect}" if $debug
      @tls.write frame
    end

    def send_headers_frame path
      def make_a_header(key, val)
        "\x00" + [key.length].pack("C") + key + [val.length].pack("C") + val
      end

      payload = "\x00\x00"
      payload = ""
      payload += make_a_header(":method", "GET")
      payload += make_a_header(":scheme", "https")
      payload += make_a_header(":authority", "1.2.3.4:80")
      payload += make_a_header(":path", path)

      frame = make_frame(FRAME_TYPE_HEADERS, 5, 1, payload)
      @tls.write frame
    end

    def send_window_update(stream_id, inc)
      self.send_frame WindowUpdateFrame.make_update(stream_id, inc)
      self.send_frame WindowUpdateFrame.make_update(0, inc)
    end

    def recv_frame
      loop do
        f = Frame.parse @recvbuf
        if f
          @recvbuf[0, f.bytelen] = ""
          return f
        end
        bytes = @tls.read(1000)
        @recvbuf += bytes
      end
    end

    def stream id
      @streams[id]
    end

    def wait_for cond
      while frame = self.recv_frame
        if frame.is_a? SettingsFrame
          if frame.ack?
            break if cond == :settings_ack
          else
            @settings = frame.settings
            self.send_frame SettingsFrame.make_ack_frame
          end
        elsif frame.is_a? DataFrame
          stream = @streams[frame.stream_id]
          stream.recv_data_frame(frame)
          break if cond == :data_end and frame.end_stream?
        end
        p frame if $debug
      end
    end
  end

  class Stream
    def initialize(client, id, settings)
      @client = client
      @id     = id
      @window = settings[:initial_window_size]

      @response_body = ""
    end

    attr_reader :response_body

    def close
    end

    def recv_data_frame dframe
      @response_body += dframe.payload
      @client.send_window_update(@id, dframe.len)
    end
  end

  class Frame
    def initialize(len, type, flags, stream_id, payload)
      @len       = len
      @type      = type
      @flags     = flags
      @stream_id = stream_id
      @payload   = payload
    end

    attr_reader :len, :type, :flags, :stream_id, :payload

    def self.parse buf
      return nil if buf.size < 8
      len, type, flags, stream_id = buf.unpack("nCCN")
      return nil if buf.size < 8 + len
      payload = buf[8, len]

      args = [ len, type, flags, stream_id, payload ]
      case type
      when HTTP2::FRAME_TYPE_DATA
        f = DataFrame.parse(*args)
      when HTTP2::FRAME_TYPE_HEADERS
        f = HeadersFrame.parse(*args)
      when HTTP2::FRAME_TYPE_SETTINGS
        f = SettingsFrame.parse(*args)
      when HTTP2::FRAME_TYPE_BLOCK
        f = BlockFrame.parse(*args)
      else
      raise "unsupported frame type: #{type}"
      end
      f
    end

    def bytelen
      8 + @len
    end

    def to_bytes
      [ @len, @type, @flags, @stream_id ].pack("nCCN") + @payload
    end

    def inspect
      format "<HTTP2::%s len=%d flags=0x%02x stream-id=%d>", self.class, @len, @flags, @stream_id
    end
  end

  class DataFrame < Frame
    def self.parse(len, type, flags, stream_id, payload)
      f = self.new(len, type, flags, stream_id, payload)
    end

    def end_stream?
      (@flags & 1) > 0
    end
  end

  class HeadersFrame < Frame
    def self.parse(len, type, flags, stream_id, payload)
      f = self.new(len, type, flags, stream_id, payload)
    end
  end

  class SettingsFrame < Frame
    def self.make_ack_frame
      self.new(0, 4, 1, 0, "")
    end

    def self.parse(len, type, flags, stream_id, payload)
      if (flags & 1) == 0
        s = payload.dup
        h = {}
        while s.length > 0
          t, v = s.unpack("nN")
          case t
          when 1
            h[:header_table_size] = v
          when 2
            h[:enable_push] = v
          when 3
            h[:max_concurrent_streams] = v
          when 4
            h[:initial_window_size] = v
          when 5
            h[:compress_data] = v
          else
            raise "unknown settings parameter: #{t} = #{v}"
          end
          s = s[6..-1]
        end
        f = self.new len, type, flags, stream_id, payload
        f.settings = h
      else
        # SETTINGS ACK frame
        f = self.new len, type, flags, stream_id, payload
      end
      f
    end

    attr_accessor :settings

    def ack?
      (flags & 1) == 1
    end
  end

  class WindowUpdateFrame < Frame
    def self.parse(len, type, flags, stream_id, payload)
      f = self.new(len, type, flags, stream_id, payload)
    end

    def self.make_update(stream_id, inc)
      payload = [ inc ].pack("N")
      self.new(payload.size, 8, 0, stream_id, payload)
    end
  end

  class BlockFrame < Frame
    def self.parse(len, type, flags, stream_id, payload)
      f = self.new(len, type, flags, stream_id, payload)
    end
  end
end


$debug = false
if ARGV.size != 1
  puts "usage: mruby http2.rb <url>"
  exit
end

unless ARGV[0] =~ Regexp.new('https://([^:/]+)(:\d+)?(/.*)')
  puts "unsupported url: #{ARGV[0]}"
  exit 1
end
host = $1
port = ($2) ? $2[1..-1].to_i : 443
path = $3 || ""

http2 = HTTP2::Client.new host, port
http2.get path
http2.close
