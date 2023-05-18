#!/usr/bin/env python

import sys
import logging
import json
import optparse
import socket
import time
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

    def __init__(self, epp_params, rabbitmq_params, queue_name, epp_reconnect=False, verbose=False, verbose_poll=False, connect_attempts=100):
        self.epp = None
        self.connection = None
        self.epp_params = epp_params
        self.rabbitmq_params = rabbitmq_params
        self.queue_name = queue_name
        self.epp_reconnect = epp_reconnect
        self.verbose = verbose
        self.verbose_poll = verbose_poll
        self.connect_attempts = connect_attempts

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
        result = None
        try:
            result = self.epp.open()
        except socket.timeout:
            logger.exception('socket SSL timeout')
            if not self.connect_attempts:
                return False
        if result:
            return True
        if not self.connect_attempts:
            return False
        while self.connect_attempts:
            self.connect_attempts -= 1
            logger.critical('retrying establishing connection with EPP host')
            try:
                result = self.epp.open()
            except socket.timeout:
                logger.exception('socket SSL timeout')
                time.sleep(2.0)
                continue
            if result:
                return True
            time.sleep(2.0)
        return False

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
        result = self.channel.queue_declare(queue=self.queue_name)
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

    def do_epp_request(self, cmd, args):
        response_xml = None
        if cmd == 'poll_req':
            response_xml = self.epp.poll_req(
                quite=(not self.verbose_poll),
            )

        elif cmd == 'poll_ack':
            response_xml = self.epp.poll_ack(
                msg_id=args['msg_id'],
                quite=(not self.verbose_poll),
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

        elif cmd == 'contact_delete':
            response_xml = self.epp.contact_delete(
                contact_id=args['contact'],
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
        return response_xml

    def do_process_epp_command(self, request_json):
        try:
            cmd = request_json['cmd']
            args = request_json.get('args', {})
        except KeyError as exc:
            logger.exception('failed processing EPP command')
            return {'error': 'failed reading EPP request: %r' % exc, }

        try:
            if self.verbose:
                if self.verbose_poll or cmd not in ['poll_req', 'poll_ack', ]:
                    logger.debug('request: [%s]  %r', cmd, args)
            response_xml = self.do_epp_request(cmd, args)
        except (
            epp_client.EPPConnectionAlreadyClosedError,
            epp_client.EPPResponseEmptyError,
            epp_client.EPPRequestFailedError,
            epp_client.EPPStreamSequenceBrokenError,
            epp_client.EPPLoginFailedError,
        ) as exc:
            if not self.epp_reconnect:
                if self.verbose:
                    logger.critical('EPP connection closed: %r', exc)
                return {'error': 'failed processing EPP command: %r' % exc, }
            if self.verbose:
                logger.critical('about to restart EPP connection, because of %r', exc)
            try:
                self.epp.socket.close()
            except:
                logger.exception('EPP socket was not properly closed')
            try:
                self.connect_epp()
                response_xml = self.do_epp_request(cmd, args)
            except Exception as exc:
                logger.exception('EPP command retry failed')
                return {'error': 'failed processing EPP command: %r' % exc, }

        except Exception as exc:
            logger.exception('failed processing EPP command')
            return {'error': 'failed processing EPP command: %r' % exc, }

        if not response_xml:
            logger.exception('unknown command or empty response received: %r', cmd)
            return {'error': 'unknown command or empty response received: %r' % cmd, }

        try:
            response_json = json.loads(xml2json.xml2json(response_xml, XML2JsonOptions(), strip_ns=1, strip=1))
        except UnicodeEncodeError:
            logger.exception('unicode encode error')
            try:
                response_json = json.loads(xml2json.xml2json(response_xml.encode('ascii', errors='ignore'), XML2JsonOptions(), strip_ns=1, strip=1))
            except Exception as exc:
                logger.exception('xml2json failed')
                return {'error': 'failed reading EPP response: %r' % exc, }
        except Exception as exc:
            logger.exception('failed reading EPP response')
            return {'error': 'failed reading EPP response: %r' % exc, }

        try:
            code = response_json['epp']['response']['result']['@code']
            msg = response_json['epp']['response']['result']['msg']
        except Exception as exc:
            code = '????'
            msg = str(exc)

        if self.verbose:
            if self.verbose_poll or cmd not in ['poll_req', 'poll_ack', ]:
                logger.debug('response: [%s] {%s}\n\n', code, msg)
        return response_json

#------------------------------------------------------------------------------

def main():
    p = optparse.OptionParser(
        description='Starts the local RPC-server and connects to the EPP back-end system. Connection to this server is carried out through RabbitMQ RPC-client.',
        prog='epp-gate',
        usage='%prog --epp=<EPP credentials file path> --rabbitmq=<RabbitMQ credentials file path> --queue=<queue name>'
    )
    p.add_option(
        '--epp',
        '-e',
        help="path to the local text file that stores EPP connection info, format:\nepp.host.com 700 login password",
        default="./epp_credentials",
    )
    p.add_option(
        '--rabbitmq',
        '-r',
        help="path to the local text file that stores RabbitMQ connection info, format:\nhostname 5672 login password",
        default="./rabbitmq_credentials",
    )
    p.add_option(
        '--queue',
        '-q',
        help="RabbitMQ queue name",
        default="epp_messages",
    )
    p.add_option(
        '--reconnect',
        '-c',
        action="store_true",
        dest="reconnect",
        help="automatically reconnect to the EPP system when connection was closed on server side",
    )
    p.add_option(
        '--verbose',
        '-v',
        action="store_true",
        dest="verbose",
        help="enable verbose logging",
    )
    p.add_option(
        '--verbose_poll',
        '-p',
        action="store_true",
        dest="verbose_poll",
        help="also enable logging for poll requests and responses",
    )
    p.add_option(
        '--sentry_dsn',
        '-s',
        help="Sentry DSN url to enable error reporting to remote system",
        default="",
    )

    options, _ = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if options.verbose else logging.WARNING,
        stream=sys.stdout,
        format='%(asctime)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    logging.getLogger('pika').setLevel(logging.WARNING)

    if options.sentry_dsn:
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration
        sentry_logging = LoggingIntegration(
            level=logging.INFO,
            event_level=logging.ERROR,
        )
        sentry_sdk.init(
            dsn=options.sentry_dsn,
            integrations=[sentry_logging, ],
        )

    srv = EPP_RPC_Server(
        epp_params=open(options.epp, 'r').read().strip().split(' '),
        rabbitmq_params=open(options.rabbitmq, 'r').read().strip().split(' '),
        queue_name=options.queue,
        epp_reconnect=options.reconnect,
        verbose=options.verbose,
        verbose_poll=options.verbose_poll,
    )
    if not srv.connect_epp():
        return False
    if not srv.connect_rabbitmq():
        return False
    return srv.run()

#------------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(int(not main()))
