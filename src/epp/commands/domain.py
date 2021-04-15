single = "<domain:name>%s</domain:name>"


single_contact = '<domain:contact type="%(type)s">%(id)s</domain:contact>'


single_registrant = "<domain:registrant>%s</domain:registrant>"


single_nameserver = "<domain:ns><domain:hostObj>%s</domain:hostObj></domain:ns>"


auth_info = "<domain:authInfo><domain:pw>%s</domain:pw></domain:authInfo>"


period = '<domain:period unit="%(units)s">%(value)s</domain:period>'


check = """<?xml version="1.0" encoding="UTF-8"?>
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
                %(auth_info)s
            </domain:info>
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
                <domain:registrant>%(registrant)s</domain:registrant>
                %(period)s
                %(nameservers)s
                %(contact_admin)s
                %(contact_billing)s
                %(contact_tech)s
                %(auth_info)s
            </domain:create>
        </create>
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
                </domain:add>
                <domain:rem>
                    %(remove_nameservers)s
                    %(remove_contacts)s
                </domain:rem>
                <domain:chg>
                    %(change_registrant)s
                    %(auth_info)s
                </domain:chg>
            </domain:update>
        </update>
        %(restore_extension)s
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""


restore_request_extension = """
        <extension>
            <rgp:update xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0">
                <rgp:restore op="request"></rgp:restore>
            </rgp:update>
        </extension>
"""


restore_report_extension = """
        <extension>
            <rgp:update xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0">
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
        </extension>
"""


transfer = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <transfer op="request">
            <domain:transfer xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                <domain:name>%(domain_name)s</domain:name>
                %(auth_info)s
                %(period)s
            </domain:transfer>
        </transfer>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""


transferstatus = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <transfer op="query">
      <domain:transfer
         xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>%s</domain:name>
      </domain:transfer>
    </transfer>
    <clTRID>CHKTEST1</clTRID>
  </command>
</epp>"""
