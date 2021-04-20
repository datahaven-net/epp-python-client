#!/usr/bin/env python

import sys
import logging
import json
import pika

#------------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------

from epp import epp_client
from epp import xml2json

#------------------------------------------------------------------------------

class XML2JsonOptions(object):
    pretty = True

#------------------------------------------------------------------------------

class EPP_RPC_Server(object):

    def __init__(self, epp_params, rabbitmq_params, queue_name, verbose=False):
        self.epp = None
        self.connection = None
        self.epp_params = epp_params
        self.rabbitmq_params = rabbitmq_params
        self.queue_name = queue_name
        self.verbose = verbose

    def connect_epp(self):
        logger.info('starting new EPP connection at %r:%r', self.epp_params[0], self.epp_params[1])
        self.epp = epp_client.EPPConnection(
            host=self.epp_params[0],
            port=int(self.epp_params[1]),
            user=self.epp_params[2],
            password=self.epp_params[3],
            raise_errors=True,
            verbose=self.verbose,
        )
        if not self.epp.open():
            return False
        return True

    def connect_rabbitmq(self):
        logger.info('starting new connection with the queue service at %r:%r', self.rabbitmq_params[0], self.rabbitmq_params[1])
        logger.info('queue service user ID: %r', self.rabbitmq_params[2])
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=self.rabbitmq_params[0],
                port=int(self.rabbitmq_params[1]),
                virtual_host='/',
                credentials=pika.PlainCredentials(self.rabbitmq_params[2], self.rabbitmq_params[3]),
            ))
        self.channel = self.connection.channel()
        logger.info('queue name is: %r', self.queue_name)
        result = self.channel.queue_declare(queue=self.queue_name)  # , exclusive=True)
        self.channel.basic_qos(prefetch_count=1)
        self.callback_queue = result.method.queue
        self.channel.basic_consume(
            queue=self.callback_queue,
            on_message_callback=self.on_request,
        )
        return True

    def run(self):
        logger.info('awaiting RPC requests')
        try:
            self.channel.start_consuming()
        except KeyboardInterrupt:
            self.epp.close()
            logger.info('server stopped gracefully')
            return True
        except Exception as exc:
            logger.info('finished with an error: %r', exc)
            return False
        return True

    def on_request(self, inp_channel, inp_method, inp_props, request):
        try:
            request_json = json.loads(request)
        except Exception as exc:
            logger.exception('failed processing request %r', request)
            response_error = {'error': str(exc), }
            response_raw = json.dumps(response_error)
            return self.do_send_reply(inp_channel, inp_props, inp_method, response_raw)
        response_json = self.do_process_epp_command(request_json)
        response_raw = json.dumps(response_json)
        return self.do_send_reply(inp_channel, inp_props, inp_method, response_raw)

    def do_send_reply(self, inp_channel, inp_props, inp_method, response_raw):
        inp_channel.basic_publish(
            exchange='',
            routing_key=inp_props.reply_to,
            properties=pika.BasicProperties(correlation_id=inp_props.correlation_id),
            body=response_raw,
        )
        inp_channel.basic_ack(delivery_tag=inp_method.delivery_tag)
        return True

    def do_process_epp_command(self, request_json):
        try:
            cmd = request_json['cmd']
            args = request_json.get('args', {})
        except KeyError as exc:
            logger.exception('failed processing epp command')
            return {'error': 'failed reading epp request: %r' % exc, }

        try:
            if self.verbose:
                logger.debug('request: [%s]  %r', cmd, args)
            response_xml = ''

            if cmd == 'poll_req':
                response_xml = self.epp.poll_req()

            elif cmd == 'poll_ack':
                response_xml = self.epp.poll_ack(
                    msg_id=args['msg_id'],
                )

            elif cmd == 'host_check':
                response_xml = self.epp.host_check(
                    nameservers_list=args['hosts'],
                )

            elif cmd == 'host_info':
                response_xml = self.epp.host_info(
                    nameserver=args['name'],
                )

            elif cmd == 'host_create':
                response_xml = self.epp.host_create(
                    nameserver=args['name'],
                    ip_addresses_list=args['ip_address'],
                )

            elif cmd == 'contact_check':
                response_xml = self.epp.contact_check_multiple(
                    contacts_list=args['contacts'],
                )

            elif cmd == 'contact_info':
                response_xml = self.epp.contact_info(
                    contact_id=args['contact'],
                    auth_info=args.get('auth_info'),
                )

            elif cmd == 'contact_create':
                response_xml = self.epp.contact_create(
                    contact_id=args['id'],
                    voice=args.get('voice'),
                    fax=args.get('fax'),
                    email=args.get('email'),
                    contacts=args.get('contacts', []),
                    auth_info=args.get('auth_info'),
                )

            elif cmd == 'contact_update':
                response_xml = self.epp.contact_update(
                    contact_id=args['id'],
                    voice=args.get('voice'),
                    fax=args.get('fax'),
                    email=args.get('email'),
                    contacts=args.get('contacts', []),
                    auth_info=args.get('auth_info'),
                )

            elif cmd == 'contact_delete':
                response_xml = self.epp.contact_delete(
                    contact_id=args['contact'],
                )

            elif cmd == 'domain_check':
                response_xml = self.epp.domain_check_multiple(
                    domains_list=args['domains'],
                )

            elif cmd == 'domain_info':
                response_xml = self.epp.domain_info(
                    domain_name=args['name'],
                    auth_info=args.get('auth_info'),
                )

            elif cmd == 'domain_create':
                response_xml = self.epp.domain_create(
                    domain_name=args['name'],
                    registrant=args['registrant'],
                    nameservers=args.get('nameservers', []),
                    period=args['period'],
                    period_units=args['period_units'],
                    contact_admin=args.get('contacts', {}).get('admin'),
                    contact_billing=args.get('contacts', {}).get('billing'),
                    contact_tech=args.get('contacts', {}).get('tech'),
                    auth_info=args.get('auth_info'),
                )

            elif cmd == 'domain_renew':
                response_xml = self.epp.domain_renew(
                    domain_name=args['name'],
                    cur_exp_date=args['cur_exp_date'],
                    period=args['period'],
                    period_units=args['period_units'],
                )

            elif cmd == 'domain_update':
                response_xml = self.epp.domain_update(
                    domain_name=args['name'],
                    auth_info=args.get('auth_info'),
                    add_nameservers=args.get('add_nameservers', []),
                    remove_nameservers=args.get('remove_nameservers', []),
                    add_contacts=args.get('add_contacts', []),
                    remove_contacts=args.get('remove_contacts', []),
                    change_registrant=args.get('change_registrant'),
                    rgp_restore=args.get('rgp_restore'),
                    rgp_restore_report=args.get('rgp_restore_report'),
                )

            elif cmd == 'domain_transfer':
                response_xml = self.epp.domain_transfer(
                    domain_name=args['name'],
                    auth_info=args.get('auth_info'),
                    period=args.get('period'),
                    period_units=args.get('period_units'),
                )

        except Exception as exc:
            logger.exception('failed processing epp command')
            return {'error': 'failed processing epp command: %r' % exc, }

        if not response_xml:
            logger.error('UNKNOWN COMMAND: %r', cmd)
            return {'error': 'unknown command: %r' % cmd, }

        try:
            response_json = json.loads(xml2json.xml2json(response_xml, XML2JsonOptions(), strip_ns=1, strip=1))
        except UnicodeEncodeError:
            logger.exception('unicode encode error')
            try:
                response_json = json.loads(xml2json.xml2json(response_xml.encode('ascii', errors='ignore'), XML2JsonOptions(), strip_ns=1, strip=1))
            except Exception as exc:
                logger.exception('xml2json failed')
                return {'error': 'failed reading epp response: %r' % exc, }
        except Exception as exc:
            logger.exception('xml2json failed')
            return {'error': 'failed reading epp response: %r' % exc, }

        try:
            code = response_json['epp']['response']['result']['@code']
            msg = response_json['epp']['response']['result']['msg']
        except Exception as exc:
            code = '????'
            msg = str(exc)

        if self.verbose:
            logger.debug('response: [%s] {%s}\n\n', code, msg)
        return response_json

#------------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.DEBUG,
        stream=sys.stdout,
        format='%(asctime)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    logging.getLogger('pika').setLevel(logging.WARNING)

    srv = EPP_RPC_Server(
        epp_params=open(sys.argv[1], 'r').read().split(' '),
        rabbitmq_params=open(sys.argv[2], 'r').read().split(' '),
        queue_name='epp_messages',
        verbose=True,
    )
    if not srv.connect_epp():
        return False
    if not srv.connect_rabbitmq():
        return False
    return srv.run()

#------------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(int(not main()))
