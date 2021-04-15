from . import domain
from . import contact
from . import nameserver


login = """<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <login>
            <clID>%(user)s</clID>
            <pw>%(password)s</pw>
            <options>
                <version>1.0</version>
                <lang>en</lang>
            </options>
            <svcs>
                <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
                <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
                <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
                <svcExtension>
                    <extURI>urn:ietf:params:xml:ns:sidn-ext-epp-1.0</extURI>
                </svcExtension>
            </svcs>
        </login>
    </command>
</epp>"""


logout = """<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
    <command>
        <logout/>
    </command>
</epp>"""


poll = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <poll op="req"/>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""


poll_ack = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <poll op="ack" msgID="%(msgid)s"/>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""
