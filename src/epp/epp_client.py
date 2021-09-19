import logging
import socket
import ssl
import struct
import hashlib
import time

from bs4 import BeautifulSoup

#------------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------

from . import commands

#------------------------------------------------------------------------------

def make_cltrid(tm=None):
    return hashlib.md5(str(int((tm or time.time()) * 100.0)).encode()).hexdigest()


def get_format_32():
    """
    Get the size of C integers. We need 32 bits unsigned.
    http://www.bortzmeyer.org/4934.html
    """
    f32 = ">I"
    if struct.calcsize(f32) < 4:
        f32 = ">L"
        if struct.calcsize(f32) != 4:
            raise Exception("Cannot find a 32 bits integer")
    elif struct.calcsize(f32) > 4:
        f32 = ">H"
        if struct.calcsize(f32) != 4:
            raise Exception("Cannot find a 32 bits integer")
    else:
        pass
    return f32


def int_from_net(data, format_32):
    return struct.unpack(format_32, data)[0]


def int_to_net(value, format_32):
    return struct.pack(format_32, value)

#------------------------------------------------------------------------------

class EPPConnectionAlreadyClosedError(Exception):
    pass


class EPPResponseEmptyError(Exception):
    pass

#------------------------------------------------------------------------------


class EPPConnection:

    def __init__(self, host, port, user, password, verbose=False, raise_errors=False, return_soup=None):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.socket = None
        self.ssl = None
        self.version = None
        self.format_32 = get_format_32()
        self.verbose = verbose
        self.raise_errors = raise_errors
        self.return_soup = return_soup

    def open(self, timeout=15):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        try:
            self.socket.connect((self.host, self.port))
        except ConnectionRefusedError as exc:
            if self.raise_errors:
                raise exc
            if self.verbose:
                logger.exception('connection refused')
            return False
        try:
            self.ssl = ssl.wrap_socket(self.socket)
        except socket.error as exc:
            if self.raise_errors:
                raise exc
            if self.verbose:
                logger.exception("could not setup a secure connection")
            return False
        try:
            self.greeting()
        except Exception as exc:
            if self.raise_errors:
                raise exc
            if self.verbose:
                logger.exception('failed reading greeting command from the server')
            return False
        try:
            login_ok = self.login()
        except Exception as exc:
            if self.raise_errors:
                raise exc
            if self.verbose:
                logger.exception('EPP login failed')
            return False
        if not login_ok:
            if self.raise_errors:
                raise Exception('EPP login failed')
            if self.verbose:
                logger.exception('EPP login failed')
            return False
        if self.verbose:
            logger.debug('EPP connection authenticated')
        return True

    def close(self):
        try:
            self.logout()
            self.socket.close()
        except Exception as exc:
            if self.raise_errors:
                raise exc
            if self.verbose:
                logger.exception('connection was not properly closed')
            return False
        if self.verbose:
            logger.debug('EPP connection closed')
        return True

    def read(self):
        if not self.ssl:
            raise EPPConnectionAlreadyClosedError(Exception('ssl channel disconnected'))
        ret = None
        try:
            length = self.ssl.read(4)
            if length:
                i = int_from_net(length, self.format_32) - 4
                ret = self.ssl.read(i)
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError, BrokenPipeError, socket.timeout, ) as exc:
            if self.verbose:
                logger.exception('EPP connection already closed')
            raise EPPConnectionAlreadyClosedError(exc)
        except Exception as exc:
            if self.raise_errors:
                raise exc
            if self.verbose:
                logger.exception('failed to receive EPP response')
            return None
        if ret is None:
            if self.verbose:
                logger.error('nothing was received from EPP connection')
            raise EPPResponseEmptyError()
        return ret

    def write(self, xml):
        if not self.ssl:
            raise EPPConnectionAlreadyClosedError(Exception('ssl channel disconnected'))
        epp_as_string = xml
        # +4 for the length field itself (section 4 mandates that)
        # +2 for the CRLF at the end
        length = int_to_net(len(epp_as_string) + 4 + 2, self.format_32)
        try:
            self.ssl.send(length)
            ret = self.ssl.send((epp_as_string + "\r\n").encode())
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError, BrokenPipeError, socket.timeout, ) as exc:
            if self.verbose:
                logger.exception('EPP connection already closed')
            raise EPPConnectionAlreadyClosedError(exc)
        except Exception as exc:
            if self.raise_errors:
                raise exc
            if self.verbose:
                logger.exception('failed to send EPP request command')
            return None
        return ret

    def call(self, cmd, soup=None, quite=False):
        if self.write(cmd):
            if self.verbose and not quite:
                logger.debug('sent %d bytes:\n%s\n', len(cmd), cmd)
        raw = self.read()
        if raw:
            if self.verbose and not quite:
                logger.debug('received %d bytes:\n%s', len(raw), raw.decode())
        if soup is True or (self.return_soup is True and soup is not False):
            try:
                soup = BeautifulSoup(raw, "lxml")
                result = soup.find('result')
                code = int(result.get('code'))
                if code < 1000 or code > 9999:
                    raise Exception('bad response code: %r' % code)
            except Exception as exc:
                if self.raise_errors:
                    raise exc
                if self.verbose:
                    logger.exception('failed to read EPP response command')
                return ''
            return soup
        return raw or ''

    #------------------------------------------------------------------------------

    def greeting(self):
        greeting_response = self.read()
        try:
            soup = BeautifulSoup(greeting_response, "lxml")
            svid = soup.find('svid').text
            self.version = soup.find('version').text
        except Exception as exc:
            if self.raise_errors:
                raise exc
            if self.verbose:
                logger.exception('failed to read EPP greeting command')
            return None
        if self.verbose:
            logger.debug('received greeting with %d bytes:\n%s', len(greeting_response), greeting_response.decode())
            logger.debug('connected to %s (v%s)', svid, self.version)
        return greeting_response

    def login(self, **kwargs):
        if self.verbose:
            logger.debug('attempt to login with: %r', self.user)
        kwargs['soup'] = False
        login_response = self.call(cmd=commands.login % dict(
            user=self.user,
            password=self.password,
        ), **kwargs)
        soup = BeautifulSoup(login_response, "lxml")
        result = soup.find('result')
        code = int(result.get('code'))
        if code != 1000:
            raise Exception('login response code: %r' % code)
        return True

    def logout(self, **kwargs):
        kwargs['soup'] = False
        logout_response = self.call(cmd=commands.logout, **kwargs)
        soup = BeautifulSoup(logout_response, "lxml")
        result = soup.find('result')
        code = int(result.get('code'))
        if code not in [1000, 1300, 1500, ]:
            raise Exception('logout response code: %r' % code)
        return True

    def poll_req(self, **kwargs):
        return self.call(cmd=commands.poll % dict(
            cltrid=make_cltrid(),
        ), **kwargs)

    def poll_ack(self, msg_id, **kwargs):
        return self.call(cmd=commands.poll_ack % dict(
            cltrid=make_cltrid(),
            msgid=msg_id,
        ), **kwargs)

    def host_check(self, nameservers_list, **kwargs):
        return self.call(cmd=commands.nameserver.check % dict(
            cltrid=make_cltrid(),
            nameservers='\n'.join([commands.nameserver.single % ns for ns in nameservers_list]),
        ), **kwargs)

    def host_info(self, nameserver, **kwargs):
        return self.call(cmd=commands.nameserver.info % dict(
            cltrid=make_cltrid(),
            nameserver=nameserver,
        ), **kwargs)

    def host_create(self, nameserver, ip_addresses_list, **kwargs):
        return self.call(cmd=commands.nameserver.create % dict(
            cltrid=make_cltrid(),
            nameserver=nameserver,
            ip_addresses='\n'.join([commands.nameserver.ip_address % ipaddr for ipaddr in ip_addresses_list])
        ), **kwargs)

    def contact_check(self, contact, **kwargs):
        return self.call(cmd=commands.contact.check % dict(
            cltrid=make_cltrid(),
            contacts=commands.contact.single % contact,
        ), **kwargs)

    def contact_check_multiple(self, contacts_list, **kwargs):
        return self.call(cmd=commands.contact.check % dict(
            cltrid=make_cltrid(),
            contacts='\n'.join([commands.contact.single % c for c in contacts_list]),
        ), **kwargs)

    def contact_info(self, contact_id, auth_info=None, **kwargs):
        return self.call(cmd=commands.contact.info % dict(
            cltrid=make_cltrid(),
            contact_id=contact_id,
            auth_info='' if not auth_info else commands.contact.auth_info % auth_info,
        ), **kwargs)

    def contact_create(self, contact_id, voice=None, fax=None, email=None, contacts=[], auth_info=None, **kwargs):
        return self.call(cmd=commands.contact.create % dict(
            cltrid=make_cltrid(),
            contact_id=contact_id,
            contact_fields='\n'.join([commands.contact.field1 % f for f in [
                {'field': 'voice', 'value': voice, },
                {'field': 'fax', 'value': fax, },
                {'field': 'email', 'value': email, },
            ] if f.get('value')]),
            postal_infos='\n'.join([
                commands.contact.postal_info1 % dict(
                    type=cont['type'],
                    postal_fields='\n'.join([
                        commands.contact.field2 % pf for pf in [
                            {'field': 'name', 'value': cont.get('name'), },
                            {'field': 'org', 'value': cont.get('org'), },
                        ] if pf.get('value')
                    ]),
                    address_fields='\n'.join([
                        commands.contact.field3 % dict(
                            field=afield,
                            value=', '.join(avalue) if isinstance(avalue, list) else avalue,
                        ) for (afield, avalue) in cont['address'].items() if avalue
                    ])
                ) for cont in contacts
            ]),
            auth_info='' if not auth_info else commands.contact.auth_info % auth_info,
        ), **kwargs)

    def contact_update(self, contact_id, voice=None, fax=None, email=None, contacts=[], auth_info=None, **kwargs):
        return self.call(cmd=commands.contact.update % dict(
            cltrid=make_cltrid(),
            contact_id=contact_id,
            contact_fields='\n'.join([commands.contact.field2 % f for f in [
                {'field': 'voice', 'value': voice, },
                {'field': 'fax', 'value': fax, },
                {'field': 'email', 'value': email, },
            ] if f.get('value')]),
            postal_infos='\n'.join([
                commands.contact.postal_info2 % dict(
                    type=cont['type'],
                    postal_fields='\n'.join([
                        commands.contact.field3 % pf for pf in [
                            {'field': 'name', 'value': cont.get('name'), },
                            {'field': 'org', 'value': cont.get('org'), },
                        ] if pf.get('value')
                    ]),
                    address_fields='\n'.join([
                        commands.contact.field4 % dict(
                            field=afield,
                            value=', '.join(avalue) if isinstance(avalue, list) else avalue,
                        ) for (afield, avalue) in cont['address'].items() if avalue
                    ])
                ) for cont in contacts
            ]),
            auth_info='' if not auth_info else commands.contact.auth_info % auth_info,
        ), **kwargs)

    def contact_delete(self, contact_id, **kwargs):
        return self.call(cmd=commands.contact.delete % dict(
            cltrid=make_cltrid(),
            contact_id=contact_id,
        ), **kwargs)

    def domain_check(self, domain_name, **kwargs):
        return self.call(cmd=commands.domain.check % dict(
            cltrid=make_cltrid(),
            domain_names=commands.domain.single % domain_name,
        ), **kwargs)

    def domain_check_multiple(self, domains_list, **kwargs):
        return self.call(cmd=commands.domain.check % dict(
            cltrid=make_cltrid(),
            domain_names='\n'.join([
                commands.domain.single % d for d in domains_list
            ]),
        ), **kwargs)

    def domain_info(self, domain_name, auth_info=None, **kwargs):
        return self.call(cmd=commands.domain.info % dict(
            cltrid=make_cltrid(),
            domain_name=domain_name,
            auth_info='' if not auth_info else commands.domain.auth_info % auth_info,
        ), **kwargs)

    def domain_create(self, domain_name, registrant, nameservers=[], period=1, period_units='y',
                      contact_admin=None, contact_billing=None, contact_tech=None, auth_info=None, **kwargs):
        return self.call(cmd=commands.domain.create % dict(
            cltrid=make_cltrid(),
            domain_name=domain_name,
            registrant=registrant,
            nameservers='\n'.join([
                commands.domain.single_nameserver % ns for ns in nameservers
            ]),
            period='' if period is None else commands.domain.period % dict(value=period, units=period_units or 'y'),
            contact_admin='' if not contact_admin else commands.domain.single_contact1 % dict(type='admin', id=contact_admin),
            contact_billing='' if not contact_billing else commands.domain.single_contact1 % dict(type='billing', id=contact_billing),
            contact_tech='' if not contact_tech else commands.domain.single_contact1 % dict(type='tech', id=contact_tech),
            auth_info='' if not auth_info else commands.domain.auth_info % auth_info,
        ), **kwargs)

    def domain_renew(self, domain_name, cur_exp_date, period=1, period_units='y', **kwargs):
        return self.call(cmd=commands.domain.renew % dict(
            cltrid=make_cltrid(),
            domain_name=domain_name,
            cur_exp_date=cur_exp_date,
            period='' if period is None else commands.domain.period % dict(value=period, units=period_units or 'y'),
        ), **kwargs)

    def domain_update(self, domain_name, auth_info=None,
                      add_nameservers=[], remove_nameservers=[],
                      add_contacts=[], remove_contacts=[], change_registrant=None,
                      rgp_restore=None, rgp_restore_report=None, **kwargs):
        restore_extension = ''
        if rgp_restore:
            restore_extension = commands.domain.restore_request_extension
        if rgp_restore_report:
            restore_extension = commands.domain.restore_report_extension % rgp_restore_report
        return self.call(cmd=commands.domain.update % dict(
            cltrid=make_cltrid(),
            domain_name=domain_name,
            auth_info='' if not auth_info else commands.domain.auth_info2 % auth_info,
            add_nameservers='\n'.join([
                commands.domain.single_nameserver2 % ns for ns in add_nameservers
            ]),
            remove_nameservers='\n'.join([
                commands.domain.single_nameserver2 % ns for ns in remove_nameservers
            ]),
            add_contacts='\n'.join([
                commands.domain.single_contact2 % c for c in add_contacts
            ]),
            remove_contacts='\n'.join([
                commands.domain.single_contact2 % c for c in remove_contacts
            ]),
            change_registrant='' if not change_registrant else (
                commands.domain.single_registrant % change_registrant
            ),
            restore_extension=restore_extension,
        ), **kwargs)

    def domain_transfer(self, domain_name, auth_info=None, period=None, period_units=None, **kwargs):
        return self.call(cmd=commands.domain.transfer % dict(
            cltrid=make_cltrid(),
            domain_name=domain_name,
            auth_info='' if not auth_info else commands.domain.auth_info % auth_info,
            period='' if period is None else commands.domain.period % dict(value=period, units=period_units or 'y'),
        ), **kwargs)
