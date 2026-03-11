# SSL certificates for local HTTPS

Generate self-signed certs (run from repo root or nginx dir):

```bash
cd ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -config openssl.cnf -extensions v3_req
```

Or from project root:

```bash
./nginx/ssl/gen-certs.sh
```

Then start nginx; it will use `cert.pem` and `key.pem` for HTTPS on port 443.
