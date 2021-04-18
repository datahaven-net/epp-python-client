import logging
import os
import sys
import pytest
import mock
import socket
import io


from epp import rpc_client
from epp import rpc_error


sample_epp_gate_response = '''{"epp": {"@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation":
"urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd", "response": {"result":
{"@code": "1000", "msg": "Command completed successfully"},
"trID": {"clTRID": "f1f93d544f600b1cda5a2f593e4e186b", "svTRID": "1618756117373"}}}}'''


class TestEPP_RPC_Client(object):

    @mock.patch('epp.rpc_client.EPP_RPC_Client.connect')
    @mock.patch('epp.rpc_client.EPP_RPC_Client.request')
    def test_do_rpc_request(self, mock_request, mock_connect):
        os.environ['RPC_CLIENT_CONF'] = '{"host": "localhost", "port": 5672, "username": "test", "password": "test"}'
        mock_connect.return_value = True
        mock_request.return_value = '{"fake": "response"}'
        assert rpc_client.do_rpc_request(json_request={'fake': 'request', }) == '{"fake": "response"}'

    @mock.patch('epp.rpc_client.EPP_RPC_Client.connect')
    @mock.patch('epp.rpc_client.EPP_RPC_Client.request')
    def test_bad_response(self, mock_request, mock_connect):
        os.environ['RPC_CLIENT_CONF'] = '{"host": "localhost", "port": 5672, "username": "test", "password": "test"}'
        mock_connect.return_value = True
        mock_request.return_value = '{"bad": "response"}'
        with pytest.raises(rpc_error.EPPBadResponse):
            rpc_client.run(json_request={'fake': 'request', })

    @mock.patch('epp.rpc_client.EPP_RPC_Client.connect')
    @mock.patch('epp.rpc_client.EPP_RPC_Client.request')
    def test_good_response(self, mock_request, mock_connect):
        os.environ['RPC_CLIENT_CONF'] = '{"host": "localhost", "port": 5672, "username": "test", "password": "test"}'
        mock_connect.return_value = True
        mock_request.return_value = sample_epp_gate_response
        resp = rpc_client.run(json_request={'fake': 'request', })
        assert resp['epp']['response']['result']['@code'] == '1000'
        assert resp['epp']['response']['result']['msg'] == 'Command completed successfully'
        assert resp['epp']['response']['trID']['clTRID'] == 'f1f93d544f600b1cda5a2f593e4e186b'
        assert resp['epp']['response']['trID']['svTRID'] == '1618756117373'

    @mock.patch('epp.rpc_client.EPP_RPC_Client.connect')
    @mock.patch('epp.rpc_client.EPP_RPC_Client.request')
    def test_cmd(self, mock_request, mock_connect):
        os.environ['RPC_CLIENT_CONF'] = '{"host": "localhost", "port": 5672, "username": "test", "password": "test"}'
        mock_connect.return_value = True
        mock_request.return_value = sample_epp_gate_response
        resp = rpc_client.cmd_contact_check(contacts_ids=['id_abc', 'id_123', ])
        assert resp['epp']['response']['result']['@code'] == '1000'
        assert resp['epp']['response']['result']['msg'] == 'Command completed successfully'
        assert resp['epp']['response']['trID']['clTRID'] == 'f1f93d544f600b1cda5a2f593e4e186b'
        assert resp['epp']['response']['trID']['svTRID'] == '1618756117373'
