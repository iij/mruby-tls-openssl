mruby-tls-openssl
=================

TLS library for mruby using OpenSSL

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
