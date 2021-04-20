import logging
import pytest
import mock
import socket
import io

from epp import epp_client


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


sample_logout_response = b'''<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd"><response><result code="1500">
<msg>Command completed successfully; ending session</msg></result>
<trID><svTRID>1618435120843</svTRID></trID></response></epp>'''


sample_unknown_command_response = b'''<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd"><response><result code="2000">
<msg>Unknown command</msg></result>
<trID><svTRID>1618663648910</svTRID></trID></response></epp>'''


def conn():
    logging.getLogger('epp.client').setLevel(logging.DEBUG)
    return epp_client.EPPConnection(
        host='localhost',
        port=800,
        user='tester',
        password='secret',
        verbose=True,
        raise_errors=True,
    )


def fake_response(xml_response):
    return epp_client.int_to_net(len(xml_response) + 4, epp_client.get_format_32()) + xml_response


class TestEPPConnection(object):

    def test_init(self):
        c = conn()
        assert c.host == 'localhost'
        assert c.port == 800
        assert c.user == 'tester'
        assert c.password == 'secret'
        assert c.socket == None
        assert c.ssl == None
        assert c.format_32 == '>I'
        assert c.verbose is True

    def test_make_cltrid(self):
        assert epp_client.make_cltrid(tm=1234567890) == '2841f3341738c9dc0d3ca84b0ce9d25d'

    def test_int_to_net(self):
        assert epp_client.int_to_net(len(sample_greeting), epp_client.get_format_32()) == b'\x00\x00\x03\xe3'

    def test_int_from_net(self):
        assert epp_client.int_from_net(b'\x00\x01\x02\x03', epp_client.get_format_32()) == 66051

    def test_connection_refused(self):
        with pytest.raises(ConnectionRefusedError):
            conn().open()

    @mock.patch('socket.socket.connect')
    @mock.patch('ssl.wrap_socket')
    def test_wrap_socket_failed(self, mock_wrap_socket, mock_socket_connect):
        mock_socket_connect.return_value = True
        mock_wrap_socket.side_effect = socket.error('failed')
        with pytest.raises(socket.error):
            conn().open()

    @mock.patch('socket.socket.connect')
    @mock.patch('ssl.wrap_socket')
    def test_greeting_failed(self, mock_wrap_socket, mock_socket_connect):
        mock_socket_connect.return_value = True
        mock_wrap_socket.return_value = io.BytesIO(epp_client.int_to_net(12, epp_client.get_format_32()) + b'bad greeting')
        with pytest.raises(AttributeError):
            conn().open()

    @mock.patch('socket.socket.connect')
    @mock.patch('ssl.wrap_socket')
    def test_login_failed(self, mock_wrap_socket, mock_socket_connect):
        mock_socket_connect.return_value = True
        fake_stream = io.BytesIO(
            fake_response(sample_greeting) +
            fake_response(b'bad login response'))
        setattr(fake_stream, 'send', lambda _: True)
        mock_wrap_socket.return_value = fake_stream
        with pytest.raises(AttributeError):
            conn().open()

    @mock.patch('socket.socket.connect')
    @mock.patch('ssl.wrap_socket')
    def test_open_success(self, mock_wrap_socket, mock_socket_connect):
        mock_socket_connect.return_value = True
        fake_stream = io.BytesIO(
            fake_response(sample_greeting) +
            fake_response(sample_login_response))
        setattr(fake_stream, 'send', lambda _: True)
        mock_wrap_socket.return_value = fake_stream
        assert conn().open() is True

    @mock.patch('socket.socket.connect')
    @mock.patch('ssl.wrap_socket')
    def test_close_failed(self, mock_wrap_socket, mock_socket_connect):
        mock_socket_connect.return_value = True
        fake_stream = io.BytesIO(
            fake_response(sample_greeting) +
            fake_response(sample_login_response) +
            fake_response(b'bad logout response'))
        setattr(fake_stream, 'send', lambda _: True)
        mock_wrap_socket.return_value = fake_stream
        c = conn()
        assert c.open() is True
        with pytest.raises(AttributeError):
            c.close()

    @mock.patch('socket.socket.connect')
    @mock.patch('ssl.wrap_socket')
    def test_close_success(self, mock_wrap_socket, mock_socket_connect):
        mock_socket_connect.return_value = True
        fake_stream = io.BytesIO(
            fake_response(sample_greeting) +
            fake_response(sample_login_response) +
            fake_response(sample_logout_response))
        setattr(fake_stream, 'send', lambda _: True)
        mock_wrap_socket.return_value = fake_stream
        c = conn()
        assert c.open() is True
        assert c.close() is True

    @mock.patch('socket.socket.connect')
    @mock.patch('ssl.wrap_socket')
    def test_call(self, mock_wrap_socket, mock_socket_connect):
        mock_socket_connect.return_value = True
        fake_stream = io.BytesIO(
            fake_response(sample_greeting) +
            fake_response(sample_login_response) +
            fake_response(sample_unknown_command_response) +
            fake_response(sample_logout_response))
        setattr(fake_stream, 'send', lambda _: True)
        mock_wrap_socket.return_value = fake_stream
        c = conn()
        assert c.open() is True
        assert c.call(cmd='<?xml version="1.0" encoding="UTF-8"?><test></test>') == sample_unknown_command_response
        assert c.close() is True

    @mock.patch('socket.socket.connect')
    @mock.patch('ssl.wrap_socket')
    def test_call_with_soup(self, mock_wrap_socket, mock_socket_connect):
        mock_socket_connect.return_value = True
        fake_stream = io.BytesIO(
            fake_response(sample_greeting) +
            fake_response(sample_login_response) +
            fake_response(sample_unknown_command_response) +
            fake_response(sample_logout_response))
        setattr(fake_stream, 'send', lambda _: True)
        mock_wrap_socket.return_value = fake_stream
        c = conn()
        assert c.open() is True
        resp = c.call(
            cmd='<?xml version="1.0" encoding="UTF-8"?><test></test>',
            soup=True,
        )
        assert resp.find('result').get('code') == '2000'
        assert resp.find('msg').text == 'Unknown command'
        assert c.close() is True
