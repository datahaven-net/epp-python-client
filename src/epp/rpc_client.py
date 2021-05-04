import os
import time
import json
import copy
import traceback
import random
import string
import pika  # @UnresolvedImport
import uuid
import logging

#------------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------

from epp import rpc_error

#------------------------------------------------------------------------------

DEBUG = False

_CachedClient = None

#------------------------------------------------------------------------------

def _enc(s):
    if not isinstance(s, str):
        try:
            s = s.decode('utf-8')
        except:
            s = s.decode('utf-8', errors='replace')
    return s


def _tr(_s):
    s = _enc(_s)
    try:
        from transliterate import translit  # @UnresolvedImport
        s = translit(s, reversed=True)
    except:
        pass
    return s

#------------------------------------------------------------------------------

class XML2JsonOptions(object):
    pretty = True

#------------------------------------------------------------------------------

class EPP_RPC_Client(object):

    def __init__(self, rabbitmq_credentials=None, rabbitmq_connection_timeout=None, rabbitmq_queue_name=None):
        json_conf = {}
        if os.environ.get('RPC_CLIENT_CONF'):
            json_conf = json.loads(os.environ['RPC_CLIENT_CONF'])
            logger.info('loaded config from env: RPC_CLIENT_CONF')
        if os.environ.get('RPC_CLIENT_CONF_PATH'):
            json_conf = json.loads(open(os.environ['RPC_CLIENT_CONF_PATH'], 'r').read())
            logger.info('loaded config from env: RPC_CLIENT_CONF_PATH')
        logger.debug('config: %r', json_conf)
        if rabbitmq_credentials:
            self.rabbitmq_host, self.rabbitmq_port, self.rabbitmq_username, self.rabbitmq_password = rabbitmq_credentials
            logger.info('loaded credentials from "rabbitmq_credentials" explicitly')
        else:
            self.rabbitmq_host = json_conf['host']
            self.rabbitmq_port = json_conf['port']
            self.rabbitmq_username = json_conf['username']
            self.rabbitmq_password = json_conf['password']
        self.rabbitmq_connection_timeout = int(rabbitmq_connection_timeout or json_conf.get('timeout', 0))
        self.rabbitmq_connection = None
        self.rabbitmq_queue_name = json_conf.get('queue_name', rabbitmq_queue_name) or 'epp_messages'
        logger.debug('queue name is %r', self.rabbitmq_queue_name)
        self.channel = None
        self.reply_queue = None
        self.reply = None

    def connect(self):
        try:
            self.rabbitmq_connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=self.rabbitmq_host,
                    port=int(self.rabbitmq_port),
                    credentials=pika.credentials.PlainCredentials(
                        username=self.rabbitmq_username,
                        password=self.rabbitmq_password,
                    ),
                    heartbeat=5,
                )
            )
        except pika.exceptions.ConnectionClosed as exc:
            raise rpc_error.EPPConnectionFailed(str(exc))
        if self.rabbitmq_connection_timeout:
            self.rabbitmq_connection.call_later(self.rabbitmq_connection_timeout, self.on_timeout)
        self.channel = self.rabbitmq_connection.channel()
        result = self.channel.queue_declare(queue='', exclusive=True)
        self.reply_queue = result.method.queue
        self.channel.basic_consume(
            queue=self.reply_queue,
            on_message_callback=self.on_response,
            auto_ack=True,
        )

    def on_timeout(self, *a, **kw):
        logger.info('EPP_RPC_Client timeout !!!!!!!!!!!!!!')
        try: 
            self.rabbitmq_connection.close()
        except Exception as exc:
            logger.error('connection left unclean: %r', repr(exc))

    def on_response(self, ch, method, props, body):
        if self.corr_id == props.correlation_id:
            self.reply = body

    def request(self, query):
        self.reply = None
        self.corr_id = str(uuid.uuid4())
        self.channel.basic_publish(
            exchange='',
            routing_key=self.rabbitmq_queue_name,
            properties=pika.BasicProperties(
                reply_to=self.reply_queue,
                correlation_id=self.corr_id,
            ),
            body=str(query)
        )
        while self.reply is None:
            self.rabbitmq_connection.process_data_events()
        return self.reply

#------------------------------------------------------------------------------

def make_client(cache_client=True, rabbitmq_credentials=None, rabbitmq_connection_timeout=None, rabbitmq_queue_name=None):
    global _CachedClient
    if cache_client:
        client = _CachedClient
        if not client:
            client = EPP_RPC_Client(
                rabbitmq_credentials=rabbitmq_credentials,
                rabbitmq_connection_timeout=rabbitmq_connection_timeout,
                rabbitmq_queue_name=rabbitmq_queue_name,
            )
            client.connect()
            _CachedClient = client
    else:
        client = EPP_RPC_Client(
            rabbitmq_credentials=rabbitmq_credentials,
            rabbitmq_connection_timeout=rabbitmq_connection_timeout,
            rabbitmq_queue_name=rabbitmq_queue_name,
        )
        client.connect()
    return client


def do_rpc_request(json_request, cache_client=True, health_marker_filepath=None,
                   rabbitmq_credentials=None, rabbitmq_connection_timeout=None, rabbitmq_queue_name=None):
    """
    Sends EPP message in JSON format towards COCCA back-end via RabbitMQ server.
    Here RabbitMQ is connecting your application with another Python process running `rpc_server.py`, so-called EPP Gate.
    Method returns XML response message received back from the Gate via RabbitMQ.

    You can pass RabbitMQ connection parameters while making RPC request using input parameters:

        rabbitmq_credentials=('localhost', 800, '<rabbitmq username>', '<rabbitmq password>', )
        rabbitmq_connection_timeout=5

    Another way to pass sensitive secrets to the client is via environment variable `RPC_CLIENT_CONF_PATH`.
    Environment variable `RPC_CLIENT_CONF_PATH` must store the local path to a Json-formatted configuration file.

        {
            "host": "localhost",
            "port": "800",
            "username": "<rabbitmq username>",
            "password": "<rabbitmq password>",
            "timeout": 5,
            "queue_name": "epp_messages"
        }

    Additionally, an extra "auto-healing" mechanism may be used to re-connect Gate server with the COCCA back-end after a fault.
    When COCCA back-end drops the connection from the server-side - the EPP Gate needs to be "restarted".
    EPP connection must re-login to be able to send and receive XML messages again - this is done inside `rpc_server.py` process.

    You can run EPP Gate via "systemd" service manager and it may consist of 3 units:

        1. `epp-gate.service` : service which execute `rpc_server.py` script and keep it running all the time
        2. `epp-gate-watcher.service` : background service which is able to "restart" `epp-gate.service` when needed
        3. `epp-gate-health.path` : systemd trigger which is monitoring `health` file for any modifications

    To indicate that connection is currently down the client part need to print a line in the local `health` file.
    RPC server process then will be restarted automatically and EPP Gate suppose to become healthy right away.

    We also must "retry" one time the last failed message after Gate restarted,
    RabbitMQ will deliver response automatically back.

    To enable that functionality pass local file path the `health` file in the `health_marker_filepath` parameter.
    """
    global _CachedClient
    try:
        client = make_client(
            cache_client=cache_client,
            rabbitmq_credentials=rabbitmq_credentials,
            rabbitmq_connection_timeout=rabbitmq_connection_timeout,
            rabbitmq_queue_name=rabbitmq_queue_name,
        )
        reply = client.request(json.dumps(json_request))
        if not reply:
            logger.error('empty response from RPCClient')
            raise ValueError('empty response from RPCClient')
    except Exception as exc:
        logger.exception('ERROR from RPCClient')
        if not health_marker_filepath:
            raise exc
        with open(health_marker_filepath, 'a') as fout:
            fout.write('{} at {}\n'.format(exc, time.asctime()))
        # retry after 2 seconds, EPP Gate suppose to be restarted already
        time.sleep(2)
        # if the issue is still here it will raise EPPBadResponse() in run() method anyway
        _CachedClient = None
        client = make_client(
            cache_client=cache_client,
            rabbitmq_credentials=rabbitmq_credentials,
            rabbitmq_connection_timeout=rabbitmq_connection_timeout,
            rabbitmq_queue_name=rabbitmq_queue_name,
        )
        client.connect()
        reply = client.request(json.dumps(json_request))
    return reply

#------------------------------------------------------------------------------

def run(json_request, raise_for_result=True, logs=True, **args):
    try:
        json.dumps(json_request)
    except Exception as exc:
        logger.error('epp request failed, invalid json input')
        raise rpc_error.EPPBadResponse('epp request failed, invalid json input')

    if logs:
        if DEBUG:
            logger.debug('        >>> EPP: %s', json_request)
        else:
            logger.info('        >>> EPP: %s', json_request.get('cmd', 'unknown'))

    try:
        rpc_response = do_rpc_request(json_request, **args)
    except rpc_error.EPPError as exc:
        logger.error('epp request failed with known error: %s', exc)
        raise exc
    except Exception as exc:
        logger.error('epp request failed, unexpected error: %s', traceback.format_exc())
        raise rpc_error.EPPBadResponse('epp request failed: %r' % exc)

    if not rpc_response:
        logger.error('empty response from epp_gate, connection error')
        raise rpc_error.EPPBadResponse('epp request failed: empty response, connection error')

    try:
        json_output = json.loads(rpc_response)
    except Exception as exc:
        logger.exception('epp request failed, response is not readable')
        raise rpc_error.EPPBadResponse('epp request failed: %s' % exc)

    output_error = json_output.get('error')
    if output_error:
        raise rpc_error.EPPBadResponse('epp request processing finished with error: %s' % output_error)

    if raise_for_result:
        try:
            code = json_output['epp']['response']['result']['@code']
            msg = json_output['epp']['response']['result']['msg'].replace('Command failed;', '')
        except:
            if logs:
                logger.error('bad formatted response: %r', rpc_response)
            raise rpc_error.EPPBadResponse('bad formatted response, response code not found')
        good_response_codes = ['1000', ]
        if True:  # just to be able to debug poll script packets
            good_response_codes.extend(['1300', '1301', ])
        if code not in good_response_codes:
            if logs:
                logger.error('response code failed: %r', json.dumps(json_output, indent=2))
            epp_exc = rpc_error.exception_from_response(response=json_output, message=msg, code=code)
            raise epp_exc

    if logs:
        if DEBUG:
            logger.debug('        <<< EPP: %s', json_output)
        else:
            try:
                code = json_output['epp']['response']['result']['@code']
            except:
                code = 'unknown'
            logger.info('        <<< EPP: %s', code)

    return json_output

#------------------------------------------------------------------------------

def make_epp_id(email):
    rand4bytes = ''.join([random.choice(string.ascii_lowercase + string.digits) for _ in range(4)])
    return email.replace('.', '').split('@')[0][:6] + str(int(time.time() * 100.0))[6:] + rand4bytes.lower()

#------------------------------------------------------------------------------

def cmd_poll_req(**args):
    cmd = {
        'cmd': 'poll_req',
    }
    return run(cmd, logs=False, **args)

def cmd_poll_ack(msg_id, **args):
    cmd = {
        'cmd': 'poll_ack',
        'args': {
            'msg_id': msg_id,
        }
    }
    return run(cmd, logs=False, **args)

#------------------------------------------------------------------------------

def cmd_host_check(hosts_list, **args):
    return run({
        'cmd': 'host_check',
        'args': {
            'hosts': hosts_list,
        },
    }, **args)


def cmd_host_info(hostname, **args):
    return run({
        'cmd': 'host_info',
        'args': {
            'name': hostname,
        },
    }, **args)


def cmd_host_create(hostname, ip_address_list=[], **args):
    """
    ip_address_list item:
        {'ip': '10.0.0.1', 'version': 'v4' }
    """
    return run({
        'cmd': 'host_create',
        'args': {
            'name': hostname,
            'ip_address': ip_address_list,
        },
    }, **args)

#------------------------------------------------------------------------------

def cmd_contact_check(contacts_ids, **args):
    return run({
        'cmd': 'contact_check',
        'args': {
            'contacts': contacts_ids,
        },
    }, **args)


def cmd_contact_info(contact_id, auth_info=None, **args):
    cmd = {
        'cmd': 'contact_info',
        'args': {
            'contact': contact_id,
        },
    }
    if auth_info is not None:
        cmd['args']['auth_info'] = auth_info
    return run(cmd, **args)


def cmd_contact_create(contact_id, email=None, voice=None, fax=None, auth_info=None, contacts_list=[], **args):
    """
    contacts_list item :
    {
        "name": "VeselinTest",
        "org":"whois",
        "address": {
            "street":["Street", "55"],
            "city": "City",
            "sp": "Nord Side",
            "cc": "AI",
            "pc": "1234AB"
        }
    }
    """
    cmd = {
        'cmd': 'contact_create',
        'args': {
            'id': contact_id,
            'contacts': [],
        },
    }
    if voice is not None:
        cmd['args']['voice'] = voice
    if fax is not None:
        cmd['args']['fax'] = fax
    if email is not None:
        cmd['args']['email'] = email
    if auth_info is not None:
        cmd['args']['auth_info'] = auth_info
    for cont in contacts_list[:]:
        international = copy.deepcopy(cont)
        international['type'] = 'int'
        if 'name' in international:
            international['name'] = '%s' % _tr(international['name'])
        if 'org' in international:
            international['org'] = '%s' % _tr(international['org'])
        if 'city' in international['address']:
            international['address']['city'] = '%s' % _tr(international['address']['city'])
        if 'sp' in international['address']:
            international['address']['sp'] = '%s' % _tr(international['address']['sp'])
        if 'pc' in international['address']:
            international['address']['pc'] = '%s' % _tr(international['address']['pc'])
        for i in range(len(international['address']['street'])):
            international['address']['street'][i] = '%s' % _tr(international['address']['street'][i])
        cmd['args']['contacts'].append(international)
    for cont in contacts_list[:]:
        loc = copy.deepcopy(cont)
        loc['type'] = 'loc'
        if 'name' in loc:
            loc['name'] = _enc(loc['name'])
        if 'org' in loc:
            loc['org'] = _enc(loc['org'])
        if 'city' in loc['address']:
            loc['address']['city'] = '%s' % _enc(loc['address']['city'])
        if 'sp' in loc['address']:
            loc['address']['sp'] = '%s' % _enc(loc['address']['sp'])
        if 'pc' in loc['address']:
            loc['address']['pc'] = '%s' % _enc(loc['address']['pc'])
        for i in range(len(loc['address']['street'])):
            loc['address']['street'][i] = '%s' % _enc(loc['address']['street'][i])
        cmd['args']['contacts'].append(loc)
    return run(cmd, **args)


def cmd_contact_update(contact_id, email=None, voice=None, fax=None, auth_info=None, contacts_list=[], **args):
    """
    contacts_list item :
    {
        "name": "VeselinTest",
        "org":"whois",
        "address": {
            "street":["Street", "55"],
            "city": "City",
            "sp": "Nord Side",
            "cc": "AI",
            "pc": "1234AB"
        }
    }
    """
    cmd = {
        'cmd': 'contact_update',
        'args': {
            'id': contact_id,
            'contacts': [],
        },
    }
    if voice is not None:
        cmd['args']['voice'] = voice
    if fax is not None:
        cmd['args']['fax'] = fax
    if email is not None:
        cmd['args']['email'] = email
    if auth_info is not None:
        cmd['args']['auth_info'] = auth_info
    for cont in contacts_list[:]:
        international = copy.deepcopy(cont)
        international['type'] = 'int'
        if 'name' in international:
            international['name'] = '%s' % _tr(international['name'])
        if 'org' in international:
            international['org'] = '%s' % _tr(international['org'])
        if 'city' in international['address']:
            international['address']['city'] = '%s' % _tr(international['address']['city'])
        if 'sp' in international['address']:
            international['address']['sp'] = '%s' % _tr(international['address']['sp'])
        if 'pc' in international['address']:
            international['address']['pc'] = '%s' % _tr(international['address']['pc'])
        for i in range(len(international['address']['street'])):
            international['address']['street'][i] = '%s' % _tr(international['address']['street'][i])
        cmd['args']['contacts'].append(international)
    for cont in contacts_list[:]:
        loc = copy.deepcopy(cont)
        loc['type'] = 'loc'
        if 'name' in loc:
            loc['name'] = _enc(loc['name'])
        if 'org' in loc:
            loc['org'] = _enc(loc['org'])
        if 'city' in loc['address']:
            loc['address']['city'] = '%s' % _enc(loc['address']['city'])
        if 'sp' in loc['address']:
            loc['address']['sp'] = '%s' % _enc(loc['address']['sp'])
        if 'pc' in loc['address']:
            loc['address']['pc'] = '%s' % _enc(loc['address']['pc'])
        for i in range(len(loc['address']['street'])):
            loc['address']['street'][i] = '%s' % _enc(loc['address']['street'][i])
        cmd['args']['contacts'].append(loc)
    return run(cmd, **args)


def cmd_contact_delete(contact_id, **args):
    return run({
        'cmd': 'contact_delete',
        'args': {
            'contact': contact_id,
        },
    }, **args)

#------------------------------------------------------------------------------

def cmd_domain_check(domains, **args):
    return run({
        'cmd': 'domain_check',
        'args': {
            'domains': domains,
        },
    }, **args)

def cmd_domain_info(domain, auth_info=None, **args):
    cmd = {
        'cmd': 'domain_info',
        'args': {
            'name': domain,
        },
    }
    if auth_info is not None:
        cmd['args']['auth_info'] = auth_info
    return run(cmd, **args)

def cmd_domain_create(
        domain, nameservers, contacts_dict, registrant,
        auth_info=None, period='1', period_units='y', **args):
    """
    contacts_dict:
    {
        "admin": "abc123",
        "tech": "def456",
        "billing": "xyz999"
    }
    """
    cmd = {
        'cmd': 'domain_create',
        'args': {
            'name': domain,
            'nameservers': nameservers,
            'contacts': contacts_dict,
            'registrant': registrant,
            'period': period,
            'period_units': period_units,
        },
    }
    if auth_info is not None:
        cmd['args']['auth_info'] = auth_info
    return run(cmd, **args)

def cmd_domain_renew(domain, cur_exp_date, period, period_units='y', **args):
    cmd = {
        'cmd': 'domain_renew',
        'args': {
            'name': domain,
            'cur_exp_date': cur_exp_date,
            'period': period,
            'period_units': period_units,
        },
    }
    return run(cmd, **args)

def cmd_domain_update(domain,
                      add_nameservers_list=[], remove_nameservers_list=[],
                      add_contacts_list=[], remove_contacts_list=[],
                      change_registrant=None, auth_info=None,
                      rgp_restore=None, rgp_restore_report={},
                      **args):
    """
    add_contacts_list and remove_contacts_list item:
    {
        "type": "admin",
        "id": "abc123",
    }
    """
    cmd = {
        'cmd': 'domain_update',
        'args': {
            'name': domain,
            'add_nameservers': add_nameservers_list,
            'remove_nameservers': remove_nameservers_list,
            'add_contacts': add_contacts_list,
            'remove_contacts': remove_contacts_list,
        }
    }
    if change_registrant is not None:
        cmd['args']['change_registrant'] = change_registrant
    if auth_info is not None:
        cmd['args']['auth_info'] = auth_info
    if rgp_restore:
        cmd['args']['rgp_restore'] = '1'
    if rgp_restore_report:
        cmd['args']['rgp_restore_report'] = rgp_restore_report
    return run(cmd, **args)

def cmd_domain_transfer(domain, op='request', auth_info=None, period_years=None, **args):
    cmd = {
        'cmd': 'domain_transfer',
        'args': {
            'name': domain,
            'op': op,
        }
    }
    if auth_info is not None:
        cmd['args']['auth_info'] = auth_info
    if period_years is not None:
        cmd['args']['period_years'] = period_years
        cmd['args']['period'] = period_years
        cmd['args']['period_units'] = 'y'
    return run(cmd, **args)

#------------------------------------------------------------------------------
