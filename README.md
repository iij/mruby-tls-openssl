# mruby-tls-openssl

"mruby-tls-openssl" is a TLS library for mruby using OpenSSL.  
Though very small number of APIs are implemented currently, you can write a [HTTP2 client](https://github.com/iij/mruby-tls-openssl/blob/master/http2.rb) with it.

## API

 - TLS.new(host, opts={})
   - Open a new TLS connection to `host`.  `host` can be either a hostname
     (String) or a TCP socket (TCPSocket).
   - Supported keys in `opts`:
     - :alpn => str
       - send str as a protocol for ALPN
     - :certs => str
       - pathname of the file contains trusted root CA certificate(s)
     - :identity => str
       - a server's identity expected
     - :ignore_certificate_validity => boolean
       - ignore "Not Before" and "Not After" fields of certificates
     - :port => Integer
       - port number (used only when `host` is a string)
     - :version => str
       - TLS version: one of "TLSv1.0", "TLSv1.1", "TLSv1.2", or "any"
 - TLS#read(len=)
   - Read `len` bytes from TLS connection.
 - TLS#write(str)
   - Write str to TLS connection.
 - TLS#close
   - Close TLS connection

## Example

```Ruby
# verify server's identity
tls = TLS.new "github.com", { :port => 443, :certs => "digicert.crt", :identity => "github.com" }
tls.write "GET / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n"
p tls.read
tls.close
```

## How to use TLS ALPN Extension

If you want to use TLS ALPN Extension, build and install OpenSSL 1.0.2
into `openssldir` directory:

```
% cd mruby-tls-openssl
% curl https://www.openssl.org/source/openssl-1.0.2-beta1.tar.gz | tar xzf -
% cd openssl-1.0.2-beta1
% ./config --openssldir=`pwd`/../openssldir no-shared no-threads
% make
% make install_sw
```

then build mruby.


## Compile with LibreSSL

To try [LibreSSL](http://www.libressl.org), install it to `openssldir`:

```
% cd mruby-tls-openssl
% curl -O http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.0.1.tar.gz
% tar xzf libressl-2.0.1.tar.gz
% cd libressl-2.0.1
% ./configure --disable-shared --prefix=`pwd`/../openssldir
% make
% make install
```


## License

Copyright (c) 2014 Internet Initiative Japan Inc.

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in 
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.
