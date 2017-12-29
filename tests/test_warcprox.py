#!/usr/bin/env python
'''
tests/test_warcprox.py - automated tests for warcprox

Copyright (C) 2013-2017 Internet Archive

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

import contextlib
import os
import tempfile
import logging
import warcprox
import warcprox.main
import threading
import requests
from .conftest import wait
import warcio.archiveiterator
import pytest
import re
import rethinkdb as r

@contextlib.contextmanager
def warcprox_controller(*argv):
    orig_dir = os.getcwd()
    with tempfile.TemporaryDirectory() as work_dir:
        logging.info('changing to working directory %r', work_dir)
        os.chdir(work_dir)

        args = warcprox.main.parse_args(argv)
        warcprox_ = warcprox.main.init_controller(args)

        logging.info('starting warcprox with args %s', argv)
        warcprox_thread = threading.Thread(
                name='WarcproxThread', target=warcprox_.run_until_shutdown)
        warcprox_thread.start()

        # if proxy thread is alive and we can get this lock, we're ready to go
        wait(lambda: warcprox_.proxy_thread and warcprox_.proxy_thread.is_alive(), 10.0)
        with warcprox_._start_stop_lock:
            pass

        yield warcprox_

        logging.info('shutting down warcprox')
        warcprox_.stop.set()
        warcprox_thread.join()
        logging.info('changing back to working directory %r', orig_dir)
        os.chdir(orig_dir)

def proxies(warcprox_):
    proxy_url = 'http://localhost:%s' % warcprox_.proxy.server_port
    return {'http': proxy_url, 'https': proxy_url}

class NotifyMe:
    def __init__(self):
        self.the_list = []
    def notify(self, recorded_url, records):
        self.the_list.append((recorded_url, records))

# see https://github.com/pytest-dev/pytest/issues/349#issuecomment-189370273
@pytest.fixture(params=['http_daemon', 'https_daemon'])
def httpd_base_url(request):
    return request.getfuncargvalue(request.param).base_url

def randstr(length=8):
    chars = 'abcdefghijklmopqrstuvwxyz0123456789'
    return ''.join(random.choice(chars) for _ in range(length))

@pytest.fixture(scope='module')
def rethinkdb_db():
    db = randstr()
    try:
        logging.info('attempting to create rethinkdb db %s', db)
        r.db_create(db).run(r.connect())
        yield db
        try:
            logging.info('dropping db %s', db)
            r.db_drop(db).run(r.connect())
        except:
            logging.warn('problem dropping db %s', exc_info=True)
    except:
        logging.info('rethinkdb not running on localhost:28015')
        yield None

@pytest.fixture(scope='function')
def available_dedup_options():
    dedup_options = ['--dedup-db-file=%s' % randstr()]
    if rethinkdb_db:
        dedup_options.append(
                '--rethinkdb-dedup-url=rethinkdb://localhost/%s/dedup_%s' % (
                    rethinkdb_db, randstr()))
        dedup_options.append(
                '--rethinkdb-big-table-url=rethinkdb://localhost/%s/big_table_%s' % (
                    rethinkdb_db, randstr()))
    return dedup_options

@pytest.mark.parametrize('dedup_option', available_dedup_options)
def test_archive_url(httpd_base_url, dedup_option):
    url = '%s/a/b' % httpd_base_url

    with warcprox_controller(
            '--port=0', '--plugin=%s.%s' % (
                __name__, NotifyMe.__name__)) as warcprox_:
        listener = warcprox_.warc_writer_threads[0].listeners[-1]
        assert listener.the_list == []

        # fetch/archive
        response = requests.get(url, proxies=proxies(warcprox_), verify=False)
        assert response.status_code == 200
        assert response.headers['warcprox-test-header'] == 'a!'
        assert response.content == b'I am the warcprox test payload! bbbbbbbbbb!\n'

        # our listener tells us when it's done writing
        wait(lambda: len(listener.the_list) > 0, 10.0)
        assert len(listener.the_list) == 1
        (recorded_url, (principal_record, request_record)) = listener.the_list[0]
        assert recorded_url.url == url.encode('ascii')
        assert principal_record.warc_filename

        # read the warc
        warc_path = os.path.join(
                './warcs', '%s.open' % principal_record.warc_filename)
        with open(warc_path, 'rb') as f:
            rec_iter = iter(warcio.archiveiterator.ArchiveIterator(f))
            record = next(rec_iter)
            assert record.rec_type == 'warcinfo'
            record = next(rec_iter)
            assert record.rec_type == 'response'
            assert record.rec_headers.get_header('warc-target-uri') == url
            record = next(rec_iter)
            assert record.rec_type == 'request'
            assert record.rec_headers.get_header('warc-target-uri') == url
            with pytest.raises(StopIteration):
                next(rec_iter)


def test_dedup(httpd_base_url):
    url = '%s/e/f' % httpd_base_url

    with warcprox_controller(
            '--port=0', '--plugin=%s.%s' % (
                __name__, NotifyMe.__name__)) as warcprox_:
        listener = warcprox_.warc_writer_threads[0].listeners[-1]
        assert listener.the_list == []

        # check not in dedup db
        dedup_lookup = warcprox_.warc_writer_threads[0].dedup_db.lookup(
                b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
        assert dedup_lookup is None

        # fetch/archive
        response = requests.get(url, proxies=proxies(warcprox_), verify=False)
        assert response.status_code == 200
        assert response.headers['warcprox-test-header'] == 'e!'
        assert response.content == b'I am the warcprox test payload! ffffffffff!\n'

        # wait for it to finish writing
        wait(lambda: len(listener.the_list) > 0, 10.0)
        len(listener.the_list) == 1

        # check that a response record was written
        (recorded_url, (principal_record, request_record)) = listener.the_list[0]
        assert recorded_url.url == url.encode('ascii')
        assert principal_record.warc_filename
        assert principal_record.type == b'response'
        response_record = principal_record

        # check in dedup db
        # {u'id': u'<urn:uuid:e691dc0f-4bb9-4ad8-9afb-2af836aa05e4>', u'url': u'https://localhost:62841/c/d', u'date': u'2013-11-22T00:14:37Z'}
        dedup_lookup = warcprox_.warc_writer_threads[0].dedup_db.lookup(
                b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
        assert dedup_lookup
        assert dedup_lookup['url'] == url.encode('ascii')
        assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['id'])
        assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['date'])
        record_id = dedup_lookup['id']
        dedup_date = dedup_lookup['date']

        # fetch again
        response = requests.get(url, proxies=proxies(warcprox_), verify=False)
        assert response.status_code == 200
        assert response.headers['warcprox-test-header'] == 'e!'
        assert response.content == b'I am the warcprox test payload! ffffffffff!\n'

        # wait for it to finish writing
        wait(lambda: len(listener.the_list) > 1, 10.0)
        len(listener.the_list) == 2

        # check that a response record was written
        (recorded_url, (principal_record, request_record)) = listener.the_list[-1]
        assert recorded_url.url == url.encode('ascii')
        assert principal_record.warc_filename
        assert principal_record.type == b'revisit'
        assert principal_record.get_header(b'WARC-Refers-To-Target-URI') == url.encode('ascii')
        assert principal_record.get_header(b'WARC-Refers-To-Date') == response_record.date

