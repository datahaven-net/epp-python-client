single = "<domain:name>%s</domain:name>"

single_contact1 = '<domain:contact type="%(type)s">%(id)s</domain:contact>'

single_contact2 = '                    <domain:contact type="%(type)s">%(id)s</domain:contact>'

single_status_add = '                    <domain:status s="%(name)s" lang="en">%(value)s</domain:status>'

single_status_remove = '                    <domain:status s="%(name)s" />'

single_contact_update = '<domain:contact type="%(type)s">%(id)s</domain:contact>'

single_registrant = """
                    <domain:registrant>%s</domain:registrant>"""

multiple_nameservers = """                <domain:ns>
%s
                </domain:ns>"""

single_nameserver = "                    <domain:hostObj>%s</domain:hostObj>"

multiple_nameservers2 = """                    <domain:ns>
%s
                    </domain:ns>"""

single_nameserver2 = "                        <domain:hostObj>%s</domain:hostObj>"

auth_info = """    <domain:authInfo><domain:pw>%s</domain:pw></domain:authInfo>
            """

auth_info2 = """    <domain:authInfo><domain:pw>%s</domain:pw></domain:authInfo>
                """

period = '<domain:period unit="%(units)s">%(value)s</domain:period>'

check = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <check>
            <domain:check xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                %(domain_names)s
            </domain:check>
        </check>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""

info = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <info>
            <domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name hosts="all">%(domain_name)s</domain:name>
            %(auth_info)s</domain:info>
        </info>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""

create = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <create>
            <domain:create xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>%(domain_name)s</domain:name>
                %(period)s
%(nameservers)s
                <domain:registrant>%(registrant)s</domain:registrant>
                %(contact_admin)s
                %(contact_billing)s
                %(contact_tech)s
            %(auth_info)s</domain:create>
        </create>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""

delete = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <delete>
            <domain:delete xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>%(domain_name)s</domain:name>
            </domain:delete>
        </delete>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""

renew = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <renew>
            <domain:renew xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>%(domain_name)s</domain:name>
                <domain:curExpDate>%(cur_exp_date)s</domain:curExpDate>
                %(period)s
            </domain:renew>
        </renew>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""

update = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <update>
            <domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>%(domain_name)s</domain:name>
                <domain:add>
%(add_nameservers)s
%(add_contacts)s
%(add_statuses)s
                </domain:add>
                <domain:rem>
%(remove_nameservers)s
%(remove_contacts)s
%(remove_statuses)s
                </domain:rem>
                <domain:chg>%(change_registrant)s
                %(auth_info)s</domain:chg>
            </domain:update>
        </update>%(extension)s
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""

extension_wrapper = """
        <extension>
%s
        </extension>"""

restore_request_extension = """            <rgp:update xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0">
                <rgp:restore op="request"></rgp:restore>
            </rgp:update>
"""

restore_report_extension = """            <rgp:update xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0">
                <rgp:restore op="report">
                    <rgp:report>
                        <rgp:preData>%(pre_data)s</rgp:preData>
                        <rgp:postData>%(post_data)s</rgp:postData>
                        <rgp:delTime>%(del_time)s</rgp:delTime>
                        <rgp:resTime>%(res_time)s</rgp:resTime>
                        <rgp:resReason>%(res_reason)s</rgp:resReason>
                        <rgp:statement>%(statement1)s</rgp:statement>
                        <rgp:statement>%(statement2)s</rgp:statement>
                        <rgp:other>%(other)s</rgp:other>
                    </rgp:report>
                </rgp:restore>
            </rgp:update>
"""

secdns_extension = """            <secDNS:update xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
%s            </secDNS:update>"""

secdns_add = """                <secDNS:add>
%s
                </secDNS:add>
"""

secdns_rem = """                <secDNS:rem>
%s
                </secDNS:rem>
"""

secdns_chg = """                <secDNS:chg>
%s
                </secDNS:chg>
"""

secdns_dsdata = """                    <secDNS:dsData>
                        <secDNS:keyTag>%(key_tag)s</secDNS:keyTag>
                        <secDNS:alg>%(alg)s</secDNS:alg>
                        <secDNS:digestType>%(digest_type)s</secDNS:digestType>
                        <secDNS:digest>%(digest)s</secDNS:digest>
                    </secDNS:dsData>"""

secdns_dsdata_keydata = """                    <secDNS:dsData>
                        <secDNS:keyTag>%(key_tag)s</secDNS:keyTag>
                        <secDNS:alg>%(alg)s</secDNS:alg>
                        <secDNS:digestType>%(digest_type)s</secDNS:digestType>
                        <secDNS:digest>%(digest)s</secDNS:digest>
                        <secDNS:keyData>
                            <secDNS:flags>%(keydata_flags)s</secDNS:flags>
                            <secDNS:protocol>%(keydata_protocol)s</secDNS:protocol>
                            <secDNS:alg>%(keydata_alg)s</secDNS:alg>
                            <secDNS:pubKey>%(keydata_pubkey)s</secDNS:pubKey>
                        </secDNS:keyData>
                    </secDNS:dsData>"""

secdns_max_sig_life = """                    <secDNS:maxSigLife>%(max_sig_life)s</secDNS:maxSigLife>"""

secdns_all = """                    <secDNS:all>true</secDNS:all>
"""

transfer = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <transfer op="request">
            <domain:transfer xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>%(domain_name)s</domain:name>
                %(period)s
            %(auth_info)s</domain:transfer>
        </transfer>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""
