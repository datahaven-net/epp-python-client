import logging
import sys
import pytest
import mock
import socket
import io

from freezegun import freeze_time


from epp import epp_client
from epp import rpc_server


sample_greeting = '''<?xml version="1.0" encoding="UTF-8"?>
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


sample_login_response = '''<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd"><response><result code="1000">
<msg>Command completed successfully</msg></result><trID><svTRID>1618435101871</svTRID></trID>
</response></epp>'''


def fake_response(xml_response):
    return epp_client.int_to_net(len(xml_response) + 4, epp_client.get_format_32()) + xml_response.encode()


def verify_cmd(json_request, xml_request, xml_response, json_response):
    with freeze_time('2020-01-01'):
        with mock.patch('epp.epp_client.EPPConnection.write') as mock_write:
            assert srv(
                xml_response=xml_response,
            ).do_process_epp_command(
                request_json=json_request,
            ) == json_response
            mock_write.assert_called_with(xml_request)


def srv(xml_response=None):
    with mock.patch('epp.epp_client.socket.socket.connect') as mock_socket_connect:
        with mock.patch('epp.epp_client.ssl.wrap_socket') as mock_wrap_socket:
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
        )['error'] == "failed reading EPP request: KeyError('cmd')"

    def test_unknown_command(self):
        assert srv(
            xml_response='bad response'
        ).do_process_epp_command(
            {'cmd': 'something_crazy'}
        )['error'] == "unknown command or empty response received: 'something_crazy'"

    def test_bad_rpc_response(self):
        assert srv(
            xml_response='bad response'
        ).do_process_epp_command(
            {'cmd': 'poll_req'}
        )['error'] == "failed reading EPP response: ParseError('syntax error: line 1, column 0')"

    def test_cmd_poll_req(self):
        verify_cmd(
            json_request={
                'cmd': 'poll_req',
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <poll op="req"/>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1300"><msg>Command completed successfully; no messages</msg></result>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618771312959</svTRID></trID></response></epp>''',
            json_response={'epp': {'@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'result': {'@code': '1300', 'msg': 'Command completed successfully; no messages'},
                'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618771312959'}, }, },
            },
        )

    def test_cmd_poll_ack(self):
        verify_cmd(
            json_request={
                'cmd': 'poll_ack',
                'args': {
                    'msg_id': '1234',
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <poll op="ack" msgID="1234"/>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618771312959</svTRID></trID></response></epp>''',
            json_response={'epp': {'@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618771312959'}, }, },
            },
        )

    def test_cmd_host_check(self):
        verify_cmd(
            json_request={
                'cmd': 'host_check',
                'args': {
                    'hosts': ['ns1.google.com', 'ns999.google.com', ],
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <check>
            <host:check xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                <host:name>ns1.google.com</host:name>
                <host:name>ns999.google.com</host:name>
            </host:check>
        </check>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result>
<resData><host:chkData xmlns:host="urn:ietf:params:xml:ns:host-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
<host:cd><host:name avail="0">ns1.google.com</host:name><host:reason>The host already exists</host:reason></host:cd>
<host:cd><host:name avail="1">ns999.google.com</host:name></host:cd></host:chkData></resData>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618833298423</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'resData': {'chkData': {
                    '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd',
                    'cd': [
                        {'name': {'#text': 'ns1.google.com', '@avail': '0'}, 'reason': 'The host already exists'},
                        {'name': {'#text': 'ns999.google.com', '@avail': '1'}, },
                    ], }, },
                    'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                    'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618833298423'}, }, },
            },
        )

    def test_cmd_host_info(self):
        verify_cmd(
            json_request={
                'cmd': 'host_info',
                'args': {
                    'name': 'ns1234.google.com',
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <info>
            <host:info xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                <host:name>ns1234.google.com</host:name>
            </host:info>
        </info>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result><msgQ count="2" id="786"/><resData>
<host:infData xmlns:host="urn:ietf:params:xml:ns:host-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
<host:name>ns1234.google.com</host:name><host:roid>epp_id_1234</host:roid>
<host:status s="ok">No changes pending</host:status><host:clID>registrar01</host:clID>
<host:crID>registrar01</host:crID><host:crDate>2021-04-20T08:07:40.471Z</host:crDate></host:infData></resData>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618906647718</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'msgQ': {'@count': '2', '@id': '786'},
                    'resData': {'infData': {
                        '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd',
                        'clID': 'registrar01',
                        'crDate': '2021-04-20T08:07:40.471Z',
                        'crID': 'registrar01',
                        'name': 'ns1234.google.com',
                        'roid': 'epp_id_1234',
                        'status': {'#text': 'No changes pending', '@s': 'ok'}, }, },
                        'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                        'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618906647718'}, },
            }, },
        )

    def test_cmd_host_create(self):
        verify_cmd(
            json_request={
                'cmd': 'host_create',
                'args': {
                    'name': 'ns1234.google.com',
                    'ip_address': [
                        {'ip': '123.45.67.89', 'version': 'v4' },
                        {'ip': '2001:0db8:85a3:0000:0000:8a2e:0370:7334', 'version': 'v6' },
                    ],
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <create>
            <host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                <host:name>ns1234.google.com</host:name>
                <host:addr ip="v4">123.45.67.89</host:addr>
                <host:addr ip="v6">2001:0db8:85a3:0000:0000:8a2e:0370:7334</host:addr>
            </host:create>
        </create>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result><msgQ count="2" id="786"/><resData>
<host:creData xmlns:host="urn:ietf:params:xml:ns:host-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
<host:name>ns1234.google.com</host:name><host:crDate>2021-04-20T08:07:40.471Z</host:crDate></host:creData></resData>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618906060479</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'msgQ': {'@count': '2', '@id': '786'},
                    'resData': {'creData': {
                        '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd',
                        'crDate': '2021-04-20T08:07:40.471Z', 'name': 'ns1234.google.com'}, },
                    'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                    'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618906060479'}, },
            }, },
        )


    def test_cmd_contact_check(self):
        verify_cmd(
            json_request={
                'cmd': 'contact_check',
                'args': {
                    'contacts': ['epp_id_01', 'epp_id_02', 'id_not_exist_zzz', ],
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <check>
            <contact:check xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>epp_id_01</contact:id>
                <contact:id>epp_id_02</contact:id>
                <contact:id>id_not_exist_zzz</contact:id>
            </contact:check>
        </check>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result><msgQ count="2" id="786"/><resData>
<contact:chkData xmlns:contact="urn:ietf:params:xml:ns:contact-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd">
<contact:cd><contact:id avail="0">epp_id_01</contact:id></contact:cd>
<contact:cd><contact:id avail="0">epp_id_02</contact:id></contact:cd>
<contact:cd><contact:id avail="1">id_not_exist_zzz</contact:id></contact:cd>
</contact:chkData></resData>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618910859206</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'msgQ': {'@count': '2', '@id': '786'},
                    'resData': {'chkData': {
                        '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd',
                        'cd': [
                            {'id': {'#text': 'epp_id_01', '@avail': '0'}, },
                            {'id': {'#text': 'epp_id_02', '@avail': '0', }, },
                            {'id': {'#text': 'id_not_exist_zzz', '@avail': '1'}, },
                        ], }, },
                        'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                        'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618910859206'}, },
            }, },
        )

    def test_cmd_contact_info(self):
        verify_cmd(
            json_request={
                'cmd': 'contact_info',
                'args': {
                    'contact': 'epp_id_123',
                    'auth_info': '123456',
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <info>
            <contact:info xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>epp_id_123</contact:id>
                <contact:authInfo><contact:pw>123456</contact:pw></contact:authInfo>
            </contact:info>
        </info>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result><msgQ count="2" id="786"/>
<resData><contact:infData xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"
xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd"><contact:id>epp_id_123</contact:id>
<contact:roid>epp_roid_xyz</contact:roid><contact:status s="ok">No changes pending</contact:status>
<contact:status s="linked">In use by 1 domain</contact:status><contact:postalInfo type="loc">
<contact:name>Redacted | EU Data Subject</contact:name><contact:org>veso</contact:org><contact:addr>
<contact:street>Redacted | EU Data Subject</contact:street><contact:city>a city</contact:city><contact:sp>a province</contact:sp>
<contact:pc>1234AB</contact:pc><contact:cc>NL</contact:cc></contact:addr></contact:postalInfo><contact:postalInfo type="int">
<contact:name>Redacted | EU Data Subject</contact:name><contact:org>veso</contact:org><contact:addr>
<contact:street>Redacted | EU Data Subject</contact:street><contact:city>a city</contact:city><contact:sp>a province</contact:sp>
<contact:pc>1234AB</contact:pc><contact:cc>NL</contact:cc></contact:addr></contact:postalInfo>
<contact:voice>Redacted | EU Data Subject</contact:voice><contact:email>Redacted | EU Data Subject</contact:email>
<contact:clID>Redacted</contact:clID><contact:crID>Redacted</contact:crID><contact:crDate>2020-12-11T09:12:19.183Z</contact:crDate>
<contact:disclose flag="0"><contact:name type="loc"/><contact:name type="int"/><contact:org type="loc"/>
<contact:org type="int"/><contact:addr type="loc"/><contact:addr type="int"/><contact:voice/><contact:fax/>
<contact:email/></contact:disclose></contact:infData></resData>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618915678592</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'msgQ': {'@count': '2', '@id': '786'},
                    'resData': {'infData': {
                        '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd',
                        'clID': 'Redacted',
                        'crDate': '2020-12-11T09:12:19.183Z',
                        'crID': 'Redacted',
                        'disclose': {'@flag': '0',
                                     'addr': [{'@type': 'loc'},
                                              {'@type': 'int'}, ],
                                     'email': None,
                                     'fax': None,
                                     'name': [{'@type': 'loc'},
                                              {'@type': 'int'}, ],
                                     'org': [{'@type': 'loc'},
                                             {'@type': 'int'}, ],
                                     'voice': None},
                        'email': 'Redacted | EU Data Subject',
                        'id': 'epp_id_123',
                        'postalInfo': [{'@type': 'loc',
                                        'addr': {'cc': 'NL',
                                                 'city': 'a city',
                                                 'pc': '1234AB',
                                                 'sp': 'a province',
                                                 'street': 'Redacted | EU Data Subject'},
                                        'name': 'Redacted | EU Data Subject',
                                        'org': 'veso'},
                                       {'@type': 'int',
                                        'addr': {'cc': 'NL',
                                                 'city': 'a city',
                                                 'pc': '1234AB',
                                                 'sp': 'a province',
                                                 'street': 'Redacted | EU Data Subject'},
                                        'name': 'Redacted | EU Data Subject',
                                        'org': 'veso'}, ],
                        'roid': 'epp_roid_xyz',
                        'status': [{'#text': 'No changes pending',
                                    '@s': 'ok'},
                                   {'#text': 'In use by 1 domain',
                                    '@s': 'linked'}],
                        'voice': 'Redacted | EU Data Subject'}, },
                    'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                    'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618915678592'}, },
            }, },
        )

    def test_cmd_contact_create(self):
        verify_cmd(
            json_request={
                'cmd': 'contact_create',
                'args': {
                    'id': 'epp_id_new_123',
                    'voice': '+1234567890',
                    'fax': '0987654321',
                    'email': 'tester@earth.com',
                    'auth_info': '123456',
                    'contacts': [{
                        "type": "int",
                        "name": "Tester",
                        "org":"TestingCorp",
                        "address": {
                            "street":["Street", "1234", ],
                            "city": "TrialTown",
                            "sp": "North Side",
                            "cc": "AI",
                            "pc": "1234AB",
                        },
                    }, {
                        "type": "loc",
                        "name": "Tester",
                        "org":"TestingCorp",
                        "address": {
                            "street":["Street", "1234", ],
                            "city": "TrialTown",
                            "sp": "North Side",
                            "cc": "AI",
                            "pc": "1234AB",
                        },
                    }, ],
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <create>
            <contact:create xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>epp_id_new_123</contact:id>
                <contact:postalInfo type="int">
                    <contact:name>Tester</contact:name>
                    <contact:org>TestingCorp</contact:org>
                    <contact:addr>
                        <contact:street>Street, 1234</contact:street>
                        <contact:city>TrialTown</contact:city>
                        <contact:sp>North Side</contact:sp>
                        <contact:pc>1234AB</contact:pc>
                        <contact:cc>AI</contact:cc>
                    </contact:addr>
                </contact:postalInfo>
                <contact:postalInfo type="loc">
                    <contact:name>Tester</contact:name>
                    <contact:org>TestingCorp</contact:org>
                    <contact:addr>
                        <contact:street>Street, 1234</contact:street>
                        <contact:city>TrialTown</contact:city>
                        <contact:sp>North Side</contact:sp>
                        <contact:pc>1234AB</contact:pc>
                        <contact:cc>AI</contact:cc>
                    </contact:addr>
                </contact:postalInfo>
                <contact:voice>+1234567890</contact:voice>
                <contact:fax>0987654321</contact:fax>
                <contact:email>tester@earth.com</contact:email>
                <contact:authInfo><contact:pw>123456</contact:pw></contact:authInfo>
            
            </contact:create>
        </create>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result><msgQ count="2" id="786"/>
<resData><contact:creData xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"
xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd">
<contact:id>epp_id_new_123</contact:id><contact:crDate>2021-04-20T11:32:38.833Z</contact:crDate></contact:creData></resData>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618918358838</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'msgQ': {'@count': '2', '@id': '786'},
                    'resData': {'creData': {
                        '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd',
                        'crDate': '2021-04-20T11:32:38.833Z',
                        'id': 'epp_id_new_123'}},
                    'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                    'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618918358838'}, },
            }, },
        )

    def test_cmd_contact_delete(self):
        verify_cmd(
            json_request={
                'cmd': 'contact_delete',
                'args': {
                    'contact': 'epp_id_123',
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <delete>
            <contact:delete xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>epp_id_123</contact:id>
            </contact:delete>
        </delete>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result><msgQ count="2" id="786"/>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618921358722</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'msgQ': {'@count': '2', '@id': '786'},
                     'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                     'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618921358722'}, },
            }, },
        )

    def test_cmd_domain_check(self):
        verify_cmd(
            json_request={
                'cmd': 'domain_check',
                'args': {
                    'domains': ['a123.tld'],
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <check>
            <domain:check xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>a123.tld</domain:name>
            </domain:check>
        </check>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result>
<resData><domain:chkData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
<domain:cd><domain:name avail="1">a123.tld</domain:name></domain:cd></domain:chkData></resData>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618781342237</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
               'response': {'resData': {'chkData': {
                    '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd',
                    'cd': {'name': {'#text': 'a123.tld', '@avail': '1'}, }, }, },
                    'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                    'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618781342237'}, },
            }, },
        )

    def test_cmd_domain_info(self):
        verify_cmd(
            json_request={
                'cmd': 'domain_info',
                'args': {
                    'name': 'atest50.tld',
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <info>
            <domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name hosts="all">atest50.tld</domain:name>
            </domain:info>
        </info>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result>
<resData><domain:infData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
<domain:name>atest50.tld</domain:name><domain:roid>registrar_xyz</domain:roid><domain:status s="ok">Active</domain:status>
<domain:registrant>registrant01</domain:registrant><domain:contact type="billing">billing01</domain:contact>
<domain:contact type="admin">admin02</domain:contact><domain:contact type="tech">tech03</domain:contact>
<domain:ns><domain:hostObj>ns1.google.com</domain:hostObj><domain:hostObj>ns2.google.com</domain:hostObj></domain:ns>
<domain:clID>Redacted</domain:clID><domain:crID>Redacted</domain:crID><domain:crDate>2020-03-11T09:33:38.698Z</domain:crDate>
<domain:upID>Redacted</domain:upID><domain:upDate>2020-03-17T00:00:00.607Z</domain:upDate>
<domain:exDate>2024-03-11T09:33:38.756Z</domain:exDate>
<domain:authInfo><domain:pw>Authinfo Incorrect</domain:pw></domain:authInfo></domain:infData></resData>
<extension><rgp:infData xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:rgp-1.0 rgp-1.0.xsd"/>
</extension><trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618822341053</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'extension': {'infData': {
                    '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:rgp-1.0 rgp-1.0.xsd'}},
                'resData': {'infData': {
                    '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd',
                    'authInfo': {'pw': 'Authinfo Incorrect'},
                    'clID': 'Redacted',
                    'contact': [{'#text': 'billing01',
                                 '@type': 'billing'},
                                {'#text': 'admin02',
                                 '@type': 'admin'},
                                {'#text': 'tech03',
                                 '@type': 'tech'}, ],
                    'crDate': '2020-03-11T09:33:38.698Z',
                    'crID': 'Redacted',
                    'exDate': '2024-03-11T09:33:38.756Z',
                    'name': 'atest50.tld',
                    'ns': {'hostObj': ['ns1.google.com',
                                       'ns2.google.com'], },
                    'registrant': 'registrant01',
                    'roid': 'registrar_xyz',
                    'status': {'#text': 'Active',
                               '@s': 'ok'},
                    'upDate': '2020-03-17T00:00:00.607Z',
                    'upID': 'Redacted'}},
                     'result': {'@code': '1000',
                                'msg': 'Command completed successfully'},
                     'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec',
                              'svTRID': '1618822341053'}, },
            }, },
        )

    def test_cmd_domain_create(self):
        verify_cmd(
            json_request={
                'cmd': 'domain_create',
                'args': {
                    'name': 'atest51.tld',
                    'registrant': 'registrant02',
                    'nameservers': ['ns1.google.com', 'ns2.google.com', ],
                    'period': 5,
                    'period_units': 'y',
                    'contacts': {
                        'admin': 'admin02',
                        'billing': 'billing02',
                        'tech': 'tech02',
                    },
                    'auth_info': 'abc123',
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <create>
            <domain:create xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>atest51.tld</domain:name>
                <domain:period unit="y">5</domain:period>
                <domain:ns>
                    <domain:hostObj>ns1.google.com</domain:hostObj>
                    <domain:hostObj>ns2.google.com</domain:hostObj>
                </domain:ns>
                <domain:registrant>registrant02</domain:registrant>
                <domain:contact type="admin">admin02</domain:contact>
                <domain:contact type="billing">billing02</domain:contact>
                <domain:contact type="tech">tech02</domain:contact>
                <domain:authInfo><domain:pw>abc123</domain:pw></domain:authInfo>
            </domain:create>
        </create>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result><resData>
<domain:creData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
<domain:name>atest91.tld</domain:name><domain:crDate>2021-04-19T09:56:45.522Z</domain:crDate>
<domain:exDate>2022-04-19T09:56:45.594Z</domain:exDate></domain:creData></resData>
<extension><fee:creData xmlns:fee="urn:ietf:params:xml:ns:fee-1.0"><fee:currency>USD</fee:currency>
<fee:fee grace-period="P5D">50.00</fee:fee><fee:balance>122273.00</fee:balance>
<fee:creditLimit>0.00</fee:creditLimit></fee:creData></extension>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618826205527</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'extension': {'creData': {
                    'balance': '122273.00', 'creditLimit': '0.00', 'currency': 'USD',
                    'fee': {'#text': '50.00', '@grace-period': 'P5D'}, }, },
                    'resData': {'creData': {
                        '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd',
                        'crDate': '2021-04-19T09:56:45.522Z', 'exDate': '2022-04-19T09:56:45.594Z', 'name': 'atest91.tld'}, },
                    'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                    'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618826205527'}, },
            }, },
        )

    def test_cmd_domain_delete(self):
        verify_cmd(
            json_request={
                'cmd': 'domain_delete',
                'args': {
                    'name': 'fakedomain.com',
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <delete>
            <domain:delete xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>fakedomain.com</domain:name>
            </domain:delete>
        </delete>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1619202519557</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {
                    'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                    'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1619202519557'}, },
            }, },
        )

    def test_cmd_domain_renew(self):
        verify_cmd(
            json_request={
                'cmd': 'domain_renew',
                'args': {
                    'name': 'fakedomain.com',
                    'cur_exp_date': '2022-07-11T12:43:35.458Z',
                    'period': '2',
                    'period_units': 'y',
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <renew>
            <domain:renew xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>fakedomain.com</domain:name>
                <domain:curExpDate>2022-07-11T12:43:35.458Z</domain:curExpDate>
                <domain:period unit="y">2</domain:period>
            </domain:renew>
        </renew>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result><msgQ count="2" id="786"/><resData>
<domain:renData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
<domain:name>fakedomain.com</domain:name><domain:exDate>2024-07-11T12:43:35.458Z</domain:exDate></domain:renData></resData>
<extension><fee:renData xmlns:fee="urn:ietf:params:xml:ns:fee-1.0"><fee:currency>USD</fee:currency>
<fee:fee grace-period="P5D">100.00</fee:fee><fee:balance>122173.00</fee:balance>
<fee:creditLimit>0.00</fee:creditLimit></fee:renData></extension>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1618922127154</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'extension': {'renData': {
                    'balance': '122173.00', 'creditLimit': '0.00', 'currency': 'USD', 'fee': {
                        '#text': '100.00', '@grace-period': 'P5D'}, }, },
                    'msgQ': {'@count': '2', '@id': '786'},
                    'resData': {'renData': {
                        '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd',
                        'exDate': '2024-07-11T12:43:35.458Z', 'name': 'fakedomain.com'}, },
                    'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                    'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1618922127154'}, },
            }, },
        )

    def test_cmd_domain_update(self):
        verify_cmd(
            json_request={
                'cmd': 'domain_update',
                'args': {
                    'name': 'atest51.tld',
                    'change_registrant': 'registrant03',
                    'add_nameservers': ['ns3.google.com', ],
                    'remove_nameservers': ['ns2.google.com', 'ns3.google.com', ],
                    'rgp_restore_report': {
                        'pre_data': 'Pre-delete registration data not provided',
                        'post_data': 'Post-restore registration data not provided',
                        'del_time': '2020-01-01',
                        'res_time': '2024-07-11T12:43:35.458Z',
                        'res_reason': 'Customer abcd@people.com requested to restore domain',
                        'statement1': 'The information in this report is correct',
                        'statement2': 'Generated by zone automation process',
                        'other': 'No other information provided',
                    },
                    'add_contacts': [
                        {'type': 'admin', 'id': 'admin03', },
                    ],
                    'remove_contacts': [
                        {'type': 'tech', 'id': 'tech02', },
                    ],
                    'add_statuses': [
                        {'name': 'clientTransferProhibited', 'value': '2024-07-11T12:43:35.458Z by customer', },
                    ],
                    'remove_statuses': [
                        {'name': 'clientDeleteProhibited', },
                    ],
                    'auth_info': 'abc123',
                    'add_secdns': {
                        'key_tag': 'test-key-123',
                        'alg': '3',
                        'digest_type': '1',
                        'digest': '38EC35D5B3A34B33C99B',
                    },
                    'rem_secdns': {
                        'key_tag': 'test-key-123',
                        'alg': '3',
                        'digest_type': '1',
                        'digest': '38EC35D5B3A34B33C99B',
                        'keydata_flags': '257',
                        'keydata_protocol': '3',
                        'keydata_alg': '1',
                        'keydata_pubkey': 'AQPJ////4Q==',
                    },
                    'change_secdns': {
                        'max_sig_life': '11111111',
                    },
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <update>
            <domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>atest51.tld</domain:name>
                <domain:add>
                    <domain:ns>
                        <domain:hostObj>ns3.google.com</domain:hostObj>
                    </domain:ns>
                    <domain:contact type="admin">admin03</domain:contact>
                    <domain:status s="clientTransferProhibited" lang="en">2024-07-11T12:43:35.458Z by customer</domain:status>
                </domain:add>
                <domain:rem>
                    <domain:ns>
                        <domain:hostObj>ns2.google.com</domain:hostObj>
                        <domain:hostObj>ns3.google.com</domain:hostObj>
                    </domain:ns>
                    <domain:contact type="tech">tech02</domain:contact>
                    <domain:status s="clientDeleteProhibited" />
                </domain:rem>
                <domain:chg>
                    <domain:registrant>registrant03</domain:registrant>
                    <domain:authInfo><domain:pw>abc123</domain:pw></domain:authInfo>
                </domain:chg>
            </domain:update>
        </update>
        <extension>
            <rgp:update xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0">
                <rgp:restore op="report">
                    <rgp:report>
                        <rgp:preData>Pre-delete registration data not provided</rgp:preData>
                        <rgp:postData>Post-restore registration data not provided</rgp:postData>
                        <rgp:delTime>2020-01-01</rgp:delTime>
                        <rgp:resTime>2024-07-11T12:43:35.458Z</rgp:resTime>
                        <rgp:resReason>Customer abcd@people.com requested to restore domain</rgp:resReason>
                        <rgp:statement>The information in this report is correct</rgp:statement>
                        <rgp:statement>Generated by zone automation process</rgp:statement>
                        <rgp:other>No other information provided</rgp:other>
                    </rgp:report>
                </rgp:restore>
            </rgp:update>
            <secDNS:update xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
                <secDNS:add>
                    <secDNS:dsData>
                        <secDNS:keyTag>test-key-123</secDNS:keyTag>
                        <secDNS:alg>3</secDNS:alg>
                        <secDNS:digestType>1</secDNS:digestType>
                        <secDNS:digest>38EC35D5B3A34B33C99B</secDNS:digest>
                    </secDNS:dsData>
                </secDNS:add>
                <secDNS:rem>
                    <secDNS:dsData>
                        <secDNS:keyTag>test-key-123</secDNS:keyTag>
                        <secDNS:alg>3</secDNS:alg>
                        <secDNS:digestType>1</secDNS:digestType>
                        <secDNS:digest>38EC35D5B3A34B33C99B</secDNS:digest>
                        <secDNS:keyData>
                            <secDNS:flags>257</secDNS:flags>
                            <secDNS:protocol>3</secDNS:protocol>
                            <secDNS:alg>1</secDNS:alg>
                            <secDNS:pubKey>AQPJ////4Q==</secDNS:pubKey>
                        </secDNS:keyData>
                    </secDNS:dsData>
                </secDNS:rem>
                <secDNS:chg>
                    <secDNS:maxSigLife>11111111</secDNS:maxSigLife>
                </secDNS:chg>
            </secDNS:update>
        </extension>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result><msgQ count="2" id="786"/>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1619202519557</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'msgQ': {
                    '@count': '2', '@id': '786'},
                'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1619202519557'}, },
            }, },
        )

    def test_cmd_domain_transfer(self):
        verify_cmd(
            json_request={
                'cmd': 'domain_transfer',
                'args': {
                    'name': 'atest51.tld',
                    'op': 'request',
                    'period': 2,
                    'period_units': 'y',
                    'auth_info': 'abc123',
                },
            },
            xml_request='''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <transfer op="request">
            <domain:transfer xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>atest51.tld</domain:name>
                <domain:period unit="y">2</domain:period>
                <domain:authInfo><domain:pw>abc123</domain:pw></domain:authInfo>
            </domain:transfer>
        </transfer>
        <clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID>
    </command>
</epp>''',
            xml_response='''<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<response><result code="1000"><msg>Command completed successfully</msg></result><msgQ count="9" id="792"/><resData>
<domain:trnData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
<domain:name>atest51.tld</domain:name><domain:trStatus>serverApproved</domain:trStatus><domain:reID>registrar_02</domain:reID>
<domain:reDate>2021-04-30T13:30:18.035Z</domain:reDate><domain:acID>registrar_01</domain:acID>
<domain:acDate>2021-04-30T13:30:18.35Z</domain:acDate><domain:exDate>2026-07-05T07:37:32.152Z</domain:exDate></domain:trnData></resData>
<trID><clTRID>c5bc8f94103f1a47019a09049dff5aec</clTRID><svTRID>1619789418042</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'msgQ': {'@count': '9', '@id': '792'},
                    'resData': {'trnData': {
                        '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd',
                        'acDate': '2021-04-30T13:30:18.35Z',
                        'acID': 'registrar_01',
                        'exDate': '2026-07-05T07:37:32.152Z',
                        'name': 'atest51.tld',
                        'reDate': '2021-04-30T13:30:18.035Z',
                        'reID': 'registrar_02',
                        'trStatus': 'serverApproved',
                    }, },
                    'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                    'trID': {'clTRID': 'c5bc8f94103f1a47019a09049dff5aec', 'svTRID': '1619789418042'}, },
            }, },
        )
