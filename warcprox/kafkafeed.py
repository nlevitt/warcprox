import kafka
import datetime
import json
import logging
from hanzo import warctools

class CaptureFeed:
    logger = logging.getLogger('warcprox.kafkafeed.CaptureFeed')

    def __init__(self, broker_list, topic):
        self.broker_list = broker_list
        self.topic = topic.encode('utf-8')
        self._producer = kafka.SimpleProducer(kafka.KafkaClient(broker_list))

    def notify(self, recorded_url, records):
        if records[0].type not in (b'revisit', b'response'):
            return

        try:
            payload_digest = records[0].get_header(warctools.WarcRecord.PAYLOAD_DIGEST).decode('utf-8')
        except:
            payload_digest = '-'

        # {"status_code":200,"content_digest":"sha1:3VU56HI3BTMDZBL2TP7SQYXITT7VEAJQ","host":"www.kaosgl.com","via":"http://www.kaosgl.com/sayfa.php?id=4427","account_id":"877","seed":"http://www.kaosgl.com/","warc_filename":"ARCHIVEIT-6003-WEEKLY-JOB171310-20150903100014694-00002.warc.gz","url":"http://www.kaosgl.com/resim/HomofobiKarsitiBulusma/trabzon05.jpg","size":29700,"start_time_plus_duration":"20150903175709637+1049","timestamp":"2015-09-03T17:57:10.707Z","mimetype":"image/jpeg","collection_id":"6003","is_test_crawl":"false","job_name":"6003-20150902172136074","warc_offset":856320200,"thread":6,"hop_path":"RLLLLLE","extra_info":{},"annotations":"duplicate:digest","content_length":29432}

        now = datetime.datetime.utcnow()
        d = {
            'timestamp': '{:%Y-%m-%dT%H:%M:%S}.{:03d}Z'.format(now, now.microsecond//1000),
            'size': recorded_url.size,
            'status_code': recorded_url.status,
            'url': recorded_url.url.decode('utf-8'),
            'mimetype': recorded_url.mimetype,
            'content_digest': payload_digest,
            'warc_filename': records[0].warc_filename,
            'warc_offset': records[0].offset,
            'host': recorded_url.host,
            'annotations': 'duplicate:digest' if records[0].type == 'revisit' else '',
            'content_length': recorded_url.response_recorder.len - recorded_url.response_recorder.payload_offset,
            'start_time_plus_duration': '{:%Y%m%d%H%M%S}{:03d}+{}'.format(
                recorded_url.timestamp, recorded_url.timestamp.microsecond//1000, 
                int(recorded_url.duration.total_seconds() * 1000)),
            # 'hop_path': ?  # only used for seed redirects, which are n/a to brozzler (?)
            # 'via': ?
            # 'thread': ? # not needed
        }

        # fields expected to be populated here are (for archive-it):
        # account_id, collection_id, is_test_crawl, seed, job_name
        if recorded_url.warcprox_meta and 'capture-feed-extra-fields' in recorded_url.warcprox_meta:
            for (k,v) in recorded_url.warcprox_meta['capture-feed-extra-fields'].items():
                d[k] = v

        msg = json.dumps(d, separators=(',', ':')).encode('utf-8')
        self.logger.debug('feeding kafka %s', msg)
        self._producer.send_messages(self.topic, msg)
