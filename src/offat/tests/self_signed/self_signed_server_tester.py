#!/usr/bin/python3

# Generate a cert:
# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

import http.server
import ssl


class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    pass


httpd = http.server.HTTPServer(("localhost", 4443), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(
    httpd.socket, keyfile="key.pem", certfile="cert.pem", server_side=True
)

print("Serving on https://localhost:4443")
httpd.serve_forever()
