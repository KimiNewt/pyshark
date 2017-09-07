from pyshark.extensions import dns, http, ssl

EXTENSIONS = [dns.DNSExtension, http.HTTPExtension, ssl.SSLExtension]
