import logging
import sys
import pytest
import mock
import socket
import io


from epp import client
from epp import rpc_server


sample_greeting = b'''<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd"><greeting>
<svID>CoCCA EPP Server - epp.cocca.iors.cx</svID><svDate>2021-04-14T21:18:21.756Z</svDate>
<svcMenu><version>1.0</version><lang>en</lang><objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
<objURI>urn:ietf:params:xml:ns:domain-1.0</objURI><objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
<svcExtension><extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>
<extURI>urn:ietf:params:xml:ns:auxcontact-0.1</extURI>
<extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI><extURI>urn:ietf:params:xml:ns:fee-1.0</extURI>
<extURI>https://production.coccaregistry.net/cocca-activation-1.0</extURI></svcExtension></svcMenu>
<dcp><access><all/></access><statement><purpose><admin/><prov/></purpose><recipient><ours/>
<public/></recipient><retention><stated/></retention></statement></dcp></greeting></epp>'''


sample_login_response = b'''<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd"><response><result code="1000">
<msg>Command completed successfully</msg></result><trID><svTRID>1618435101871</svTRID></trID>
</response></epp>'''


def fake_response(xml_response):
    return client.int_to_net(len(xml_response) + 4, client.get_format_32()) + xml_response


def srv(xml_response=None):
    with mock.patch('epp.client.socket.socket.connect') as mock_socket_connect:
        with mock.patch('epp.client.ssl.wrap_socket') as mock_wrap_socket:
            mock_socket_connect.return_value = True
            fake_responses = fake_response(sample_greeting) + fake_response(sample_login_response)
            if xml_response is not None:
                fake_responses += fake_response(xml_response)
            fake_stream = io.BytesIO(fake_responses)
            setattr(fake_stream, 'send', lambda _: True)
            mock_wrap_socket.return_value = fake_stream
            srv = rpc_server.EPP_RPC_Server(
                epp_params=['localhost', '800', 'epp_login', 'epp_password', ],
                rabbitmq_params=['localhost', '5672', 'rabbit_login', 'rabbit_password', ],
                queue_name='testing_messages',
                verbose=True,
            )
            assert srv.epp is None
            assert srv.connection is None
            assert srv.epp_params == ['localhost', '800', 'epp_login', 'epp_password', ]
            assert srv.rabbitmq_params == ['localhost', '5672', 'rabbit_login', 'rabbit_password', ]
            assert srv.queue_name == 'testing_messages'
            assert srv.verbose is True
            assert srv.connect_epp() is True
            assert srv.epp is not None
            return srv


class TestEPP_RPC_Server(object):

    def test_bad_rpc_request(self):
        assert srv().do_process_epp_command(
            {'bad': 'request'}
        )['error'] == "failed reading epp request: KeyError('cmd')"

    def test_bad_rpc_response(self):
        assert srv(
            xml_response=b'bad response'
        ).do_process_epp_command(
            {'cmd': 'poll_req'}
        )['error'] == "failed reading epp response: ParseError('syntax error: line 1, column 0')"

    def test_cmd_poll_req(self):
        assert srv(
            xml_response=b'''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
            <response><result code="1300"><msg>Command completed successfully; no messages</msg></result>
            <trID><clTRID>d58b93272193ff4eb9c80197b42036ff</clTRID><svTRID>1618771312959</svTRID></trID></response></epp>'''
        ).do_process_epp_command(
            {'cmd': 'poll_req'}
        ) == {'epp': {'@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                      'response': {'result': {'@code': '1300', 'msg': 'Command completed successfully; no messages'},
                                   'trID': {'clTRID': 'd58b93272193ff4eb9c80197b42036ff', 'svTRID': '1618771312959'}}}}

    def test_cmd_poll_ack(self):
        assert srv(
            xml_response=b'''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
            <response><result code="1000"><msg>Command completed successfully</msg></result>
            <trID><clTRID>d58b93272193ff4eb9c80197b42036ff</clTRID><svTRID>1618771312959</svTRID></trID></response></epp>'''
        ).do_process_epp_command(
            {'cmd': 'poll_ack', 'args': {'msg_id': '1234'}}
        ) == {'epp': {'@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                      'response': {'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                                   'trID': {'clTRID': 'd58b93272193ff4eb9c80197b42036ff', 'svTRID': '1618771312959'}}}}

    def test_cmd_domain_check(self):
        assert srv(
            xml_response=b'''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
            <response><result code="1000"><msg>Command completed successfully</msg></result>
            <resData><domain:chkData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
            xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:cd><domain:name avail="1">a123.ai</domain:name></domain:cd></domain:chkData></resData>
            <trID><clTRID>1861d8f112a475bcc0f438e02baafee0</clTRID><svTRID>1618781342237</svTRID></trID></response></epp>'''
        ).do_process_epp_command(
            {'cmd': 'domain_check', 'args': {'domains': ['a123.ai']}}
        ) == {'epp': {'@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                      'response': {'resData': {'chkData': {
                          '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd',
                          'cd': {'name': {'#text': 'a123.ai', '@avail': '1'}}}},
                          'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                          'trID': {'clTRID': '1861d8f112a475bcc0f438e02baafee0', 'svTRID': '1618781342237'}}}}

