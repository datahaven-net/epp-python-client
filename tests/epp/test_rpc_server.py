import logging
import sys
import pytest
import mock
import socket
import io

from freezegun import freeze_time


from epp import client
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
    return client.int_to_net(len(xml_response) + 4, client.get_format_32()) + xml_response.encode()


def verify_cmd(json_request, xml_request, xml_response, json_response):
    with freeze_time('2020-01-01'):
        with mock.patch('epp.client.EPPConnection.write') as mock_write:
            assert srv(
                xml_response=xml_response,
            ).do_process_epp_command(
                request_json=json_request,
            ) == json_response
            mock_write.assert_called_with(xml_request)


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

    def test_unknown_command(self):
        assert srv(
            xml_response='bad response'
        ).do_process_epp_command(
            {'cmd': 'something_crazy'}
        )['error'] == "unknown command: 'something_crazy'"

    def test_bad_rpc_response(self):
        assert srv(
            xml_response='bad response'
        ).do_process_epp_command(
            {'cmd': 'poll_req'}
        )['error'] == "failed reading epp response: ParseError('syntax error: line 1, column 0')"

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

#         verify_cmd(
#             json_request={
#                 'cmd': 'host_check',
#                 'args': {
#                     'hosts_list': ['ns1.google.com', 'ns99999.google.com', ],
#                 },
#             },
#             xml_request,
#             xml_response,
#             json_response,
#         )

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
<trID><clTRID>bcd86e4c150a285b6c6dbf9d3a430053</clTRID><svTRID>1618833298423</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'resData': {'chkData': {
                    '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd',
                    'cd': [
                        {'name': {'#text': 'ns1.google.com', '@avail': '0'}, 'reason': 'The host already exists'},
                        {'name': {'#text': 'ns999.google.com', '@avail': '1'}, },
                    ], }, },
                    'result': {'@code': '1000', 'msg': 'Command completed successfully'},
                    'trID': {'clTRID': 'bcd86e4c150a285b6c6dbf9d3a430053', 'svTRID': '1618833298423'}, }, },
            },
        )

    def test_cmd_host_create(self):
        return
        verify_cmd(
            json_request={
                'cmd': 'host_create',
                'args': {
                    'hosts_list': ['ns1.google.com', 'ns99999.google.com', ],
                },
            },
            xml_request='',
            xml_response='',
            json_response={},
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
                                 '@type': 'tech'}],
                    'crDate': '2020-03-11T09:33:38.698Z',
                    'crID': 'Redacted',
                    'exDate': '2024-03-11T09:33:38.756Z',
                    'name': 'atest50.tld',
                    'ns': {'hostObj': ['ns1.google.com',
                                       'ns2.google.com']},
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
                <domain:registrant>registrant02</domain:registrant>
                <domain:period unit="y">5</domain:period>
                <domain:ns><domain:hostObj>ns1.google.com</domain:hostObj></domain:ns>
                <domain:ns><domain:hostObj>ns2.google.com</domain:hostObj></domain:ns>
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
<trID><clTRID>29e1ed69f65f611ffb6dd3e9eee07360</clTRID><svTRID>1618826205527</svTRID></trID></response></epp>''',
            json_response={'epp': {
                '@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd',
                'response': {'extension': {'creData': {'balance': '122273.00',
                                            'creditLimit': '0.00',
                                            'currency': 'USD',
                                            'fee': {'#text': '50.00',
                                                    '@grace-period': 'P5D'}, }, },
                    'resData': {'creData': {'@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation': 'urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd',
                                            'crDate': '2021-04-19T09:56:45.522Z',
                                            'exDate': '2022-04-19T09:56:45.594Z',
                                            'name': 'atest91.tld'}, },
                    'result': {'@code': '1000',
                               'msg': 'Command completed successfully'},
                    'trID': {'clTRID': '29e1ed69f65f611ffb6dd3e9eee07360',
                            'svTRID': '1618826205527'}, },
            }, },
        )
