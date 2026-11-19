# gunicorn com TLS mutuo + CRL (RT-04, RT-05). Carregado com `-c gunicorn_conf.py`.
import ssl

bind = "0.0.0.0:8443"
workers = 2
certfile = "/pki/ingest.cert.pem"
keyfile = "/pki/ingest.key.pem"
ca_certs = "/pki/ca.cert.pem"
cert_reqs = ssl.CERT_REQUIRED


def ssl_context(conf, default_ssl_context_factory):
    ctx = default_ssl_context_factory()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    # certificado revogado na CRL do projeto e recusado no handshake
    ctx.load_verify_locations(cafile="/pki/crl.pem")
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    return ctx
