single = '                <host:name>%s</host:name>'


ip_address = '                <host:addr ip="%(version)s">%(ip)s</host:addr>'


check = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <check>
            <host:check xmlns:host="urn:ietf:params:xml:ns:host-1.0">
%(nameservers)s
            </host:check>
        </check>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""


info = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <info>
            <host:info xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                <host:name>%(nameserver)s</host:name>
            </host:info>
        </info>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""


create = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <create>
            <host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                <host:name>%(nameserver)s</host:name>
%(ip_addresses)s
            </host:create>
        </create>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""