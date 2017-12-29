# vim: set fileencoding=utf-8:
'''
tests/conftest.py - command line options for warcprox tests

Copyright (C) 2015-2017 Internet Archive

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
USA.
'''

import pytest
import threading
import logging
import ssl
import tempfile
import OpenSSL
import os
import re
import http.server
import sys
import warcprox
import warnings
import requests
import socket

# def pytest_addoption(parser):
#     parser.addoption(
#             '--rethinkdb-dedup-url', dest='rethinkdb_dedup_url', help=(
#                 'rethinkdb dedup url, e.g. rethinkdb://db0.foo.org,'
#                 'db1.foo.org:38015/my_warcprox_db/my_dedup_table'))
#     parser.addoption(
#             '--rethinkdb-big-table-url', dest='rethinkdb_big_table_url', help=(
#                 'rethinkdb big table url (table will be populated with '
#                 'various capture information and is suitable for use as '
#                 'index for playback), e.g. rethinkdb://db0.foo.org,'
#                 'db1.foo.org:38015/my_warcprox_db/captures'))
#     parser.addoption(
#             '--rethinkdb-trough-db-url', dest='rethinkdb_trough_db_url', help=(
#                 '🐷   url pointing to trough configuration rethinkdb database, '
#                 'e.g. rethinkdb://db0.foo.org,db1.foo.org:38015'
#                 '/trough_configuration'))

logging.basicConfig(
        # stream=sys.stdout, level=logging.DEBUG, # level=warcprox.TRACE,
        stream=sys.stdout, level=warcprox.TRACE, format=(
            '%(asctime)s %(process)d %(levelname)s %(threadName)s '
            '%(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s'))
logging.getLogger('requests.packages.urllib3').setLevel(logging.WARN)
warnings.simplefilter('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter('ignore', category=requests.packages.urllib3.exceptions.InsecurePlatformWarning)

# monkey patch dns lookup so we can test domain inheritance on localhost
orig_getaddrinfo = socket.getaddrinfo
orig_gethostbyname = socket.gethostbyname
orig_socket_connect = socket.socket.connect

def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host.endswith('.localhost'):
        return orig_getaddrinfo('localhost', port, family, type, proto, flags)
    else:
        return orig_getaddrinfo(host, port, family, type, proto, flags)

def _gethostbyname(host):
    if host.endswith('.localhost'):
        return orig_gethostbyname('localhost')
    else:
        return orig_gethostbyname(host)

def _socket_connect(self, address):
    if address[0].endswith('.localhost'):
        return orig_socket_connect(self, ('localhost', address[1]))
    else:
        return orig_socket_connect(self, address)

socket.gethostbyname = _gethostbyname
socket.getaddrinfo = _getaddrinfo
socket.socket.connect = _socket_connect

def chunkify(buf, chunk_size=13):
    i = 0
    result = b''
    while i < len(buf):
        chunk_len = min(len(buf) - i, chunk_size)
        result += ('%x\r\n' % chunk_len).encode('ascii')
        result += buf[i:i+chunk_len]
        result += b'\r\n'
        i += chunk_size
    result += b'0\r\n\r\n'
    return result

# def gzipify(buf):
#     with io.BytesIO() as outbuf:
#         with gzip.GzipFile(fileobj=outbuf, mode='wb') as gz:
#             gz.write(buf)
#         return outbuf.getvalue()

class _TestHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    def build_response(self):
        m = re.match(r'^/([^/]+)/([^/]+)$', self.path)
        if m is not None:
            special_header = 'warcprox-test-header: {}!'.format(m.group(1)).encode('utf-8')
            payload = 'I am the warcprox test payload! {}!\n'.format(10*m.group(2)).encode('utf-8')
            headers = (b'HTTP/1.1 200 OK\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  special_header + b'\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
        elif self.path == '/missing-content-length':
            headers = (b'HTTP/1.1 200 OK\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  b'\r\n')
            payload = b'This response is missing a Content-Length http header.'
        elif self.path.startswith('/test_payload_digest-'):
            content_body = (
                    b'Hello. How are you. I am the test_payload_digest '
                    b'content body. The entity body is a possibly content-'
                    b'encoded version of me. The message body is a possibly '
                    b'transfer-encoded version of the entity body.\n')
            gzipped = (
                    b"\x1f\x8b\x08\x00jA\x06Z\x02\xffm\x8d1\x0e\xc20\x10\x04{^"
                    b"\xb1\x1f\xc0\xef\x08=}t\x897\xc1\x92\xed\x8b|\x07\xc8"
                    b"\xbf'\n\xa2@J9\xab\x19\xed\xc0\x9c5`\xd07\xa4\x11]\x9f"
                    b"\x017H\x81?\x08\xa7\xf9\xb8I\xcf*q\x8ci\xdd\x11\xb3VguL"
                    b"\x1a{\xc0}\xb7vJ\xde\x8f\x01\xc9 \xd8\xd4,M\xb9\xff\xdc"
                    b"+\xeb\xac\x91\x11/6KZ\xa1\x0b\n\xbfq\xa1\x99\xac<\xab"
                    b"\xbdI\xb5\x85\xed,\xf7\xff\xdfp\xf9\x00\xfc\t\x02\xb0"
                    b"\xc8\x00\x00\x00")
            double_gzipped = (
                    b"\x1f\x8b\x08\x00jA\x06Z\x02\xff\x01\x89\x00v\xff\x1f\x8b"
                    b"\x08\x00jA\x06Z\x02\xffm\x8d1\x0e\xc20\x10\x04{^\xb1\x1f"
                    b"\xc0\xef\x08=}t\x897\xc1\x92\xed\x8b|\x07\xc8\xbf'\n\xa2"
                    b"@J9\xab\x19\xed\xc0\x9c5`\xd07\xa4\x11]\x9f\x017H\x81?"
                    b"\x08\xa7\xf9\xb8I\xcf*q\x8ci\xdd\x11\xb3VguL\x1a{\xc0}"
                    b"\xb7vJ\xde\x8f\x01\xc9 \xd8\xd4,M\xb9\xff\xdc+\xeb\xac"
                    b"\x91\x11/6KZ\xa1\x0b\n\xbfq\xa1\x99\xac<\xab\xbdI\xb5"
                    b"\x85\xed,\xf7\xff\xdfp\xf9\x00\xfc\t\x02\xb0\xc8\x00\x00"
                    b"\x00\xf9\xdd\x8f\xed\x89\x00\x00\x00")
            if self.path == '/test_payload_digest-plain':
                payload = content_body
                actual_headers = (b'Content-Type: text/plain\r\n'
                               +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n')
            elif self.path == '/test_payload_digest-gzip':
                payload = gzipped
                actual_headers = (b'Content-Type: application/gzip\r\n'
                               +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n')
            elif self.path == '/test_payload_digest-ce-gzip':
                payload = gzipped
                actual_headers = (b'Content-Type: text/plain\r\n'
                               +  b'Content-Encoding: gzip\r\n'
                               +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n')
            elif self.path == '/test_payload_digest-gzip-ce-gzip':
                payload = double_gzipped
                actual_headers = (b'Content-Type: application/gzip\r\n'
                               +  b'Content-Encoding: gzip\r\n'
                               +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n')
            elif self.path == '/test_payload_digest-te-chunked':
                payload = chunkify(content_body)
                actual_headers = (b'Content-Type: text/plain\r\n'
                               +  b'Transfer-Encoding: chunked\r\n')
            elif self.path == '/test_payload_digest-gzip-te-chunked':
                payload = chunkify(gzipped)
                actual_headers = (b'Content-Type: application/gzip\r\n'
                               +  b'Transfer-Encoding: chunked\r\n')
            elif self.path == '/test_payload_digest-ce-gzip-te-chunked':
                payload = chunkify(gzipped)
                actual_headers = (b'Content-Type: text/plain\r\n'
                               +  b'Content-Encoding: gzip\r\n'
                               +  b'Transfer-Encoding: chunked\r\n')
            elif self.path == '/test_payload_digest-gzip-ce-gzip-te-chunked':
                payload = chunkify(double_gzipped)
                actual_headers = (b'Content-Type: application/gzip\r\n'
                               +  b'Content-Encoding: gzip\r\n'
                               +  b'Transfer-Encoding: chunked\r\n')
            else:
                raise Exception('bad path')
            headers = b'HTTP/1.1 200 OK\r\n' + actual_headers +  b'\r\n'
            logging.info('headers=%r payload=%r', headers, payload)
        elif self.path == '/empty-response':
            headers = b''
            payload = b''
        else:
            payload = b'404 Not Found\n'
            headers = (b'HTTP/1.1 404 Not Found\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
        return headers, payload

    def do_GET(self):
        logging.info('GET %s', self.path)
        headers, payload = self.build_response()
        self.connection.sendall(headers)
        self.connection.sendall(payload)

    def do_HEAD(self):
        logging.info('HEAD %s', self.path)
        headers, payload = self.build_response()
        self.connection.sendall(headers)

@pytest.fixture(scope="module")
def cert(request):
    with tempfile.NamedTemporaryFile(
            prefix='warcprox-test-https-', suffix='.pem', delete=False) as f:
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        req = OpenSSL.crypto.X509Req()
        req.get_subject().CN = 'localhost'
        req.set_pubkey(key)
        req.sign(key, 'sha1')
        cert = OpenSSL.crypto.X509()
        cert.set_subject(req.get_subject())
        cert.set_serial_number(0)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(2*60*60) # valid for 2hrs
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(key, 'sha1')

        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.SSL.FILETYPE_PEM, key))
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.SSL.FILETYPE_PEM, cert))

        logging.info('generated self-signed certificate {}'.format(f.name))
        f.close()
        yield f.name

@pytest.fixture(scope="module")
def http_daemon(request):
    http_daemon = http.server.HTTPServer(
            ('localhost', 0), RequestHandlerClass=_TestHttpRequestHandler)
    http_daemon.base_url = 'http://%s:%s' % (
            http_daemon.server_address[0], http_daemon.server_address[1])
    logging.info('starting %s', http_daemon.base_url)
    http_daemon_thread = threading.Thread(
            name='HttpDaemonThread', target=http_daemon.serve_forever)
    http_daemon_thread.start()

    yield http_daemon

    logging.info("stopping http daemon")
    http_daemon.shutdown()
    http_daemon.server_close()
    http_daemon_thread.join()

@pytest.fixture(scope="module")
def https_daemon(request, cert):
    # http://www.piware.de/2011/01/creating-an-https-server-in-python/
    https_daemon = http.server.HTTPServer(
            ('localhost', 0), RequestHandlerClass=_TestHttpRequestHandler)
    https_daemon.socket = ssl.wrap_socket(
            https_daemon.socket, certfile=cert, server_side=True)
    https_daemon.base_url = 'https://%s:%s' % (
            https_daemon.server_address[0], https_daemon.server_address[1])
    logging.info('starting %s', https_daemon.base_url)
    https_daemon_thread = threading.Thread(
            name='HttpsDaemonThread', target=https_daemon.serve_forever)
    https_daemon_thread.start()

    yield https_daemon

    logging.info("stopping https daemon")
    https_daemon.shutdown()
    https_daemon.server_close()
    https_daemon_thread.join()

def test_httpds_no_proxy(http_daemon, https_daemon):
    url = 'http://localhost:{}/'.format(http_daemon.server_port)
    response = requests.get(url)
    assert response.status_code == 404
    assert response.content == b'404 Not Found\n'

    url = 'https://localhost:{}/'.format(https_daemon.server_port)
    response = requests.get(url, verify=False)
    assert response.status_code == 404
    assert response.content == b'404 Not Found\n'

    url = 'http://localhost:{}/a/b'.format(http_daemon.server_port)
    response = requests.get(url)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'a!'
    assert response.content == b'I am the warcprox test payload! bbbbbbbbbb!\n'

    url = 'https://localhost:{}/c/d'.format(https_daemon.server_port)
    response = requests.get(url, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'c!'
    assert response.content == b'I am the warcprox test payload! dddddddddd!\n'

    # ensure monkey-patched dns resolution is working
    url = 'https://foo.bar.localhost:{}/c/d'.format(https_daemon.server_port)
    response = requests.get(url, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'c!'
    assert response.content == b'I am the warcprox test payload! dddddddddd!\n'

def wait(callback, timeout):
    import time
    start = time.time()
    while time.time() - start < timeout:
        if callback():
            return
        time.sleep(0.1)
    raise Exception('timed out waiting for %s to return truthy' % callback)

