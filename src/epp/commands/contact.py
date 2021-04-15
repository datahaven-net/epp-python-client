single = "<contact:id>%s</contact:id>"


field1 = "                <contact:%(field)s>%(value)s</contact:%(field)s>"
field2 = "                    <contact:%(field)s>%(value)s</contact:%(field)s>"
field3 = "                        <contact:%(field)s>%(value)s</contact:%(field)s>"
field4 = "                            <contact:%(field)s>%(value)s</contact:%(field)s>"


postal_info1 = """                <contact:postalInfo type="%(type)s">
%(postal_fields)s
                    <contact:addr>
%(address_fields)s
                    </contact:addr>
                </contact:postalInfo>"""


postal_info2 = """                    <contact:postalInfo type="%(type)s">
%(postal_fields)s
                        <contact:addr>
%(address_fields)s
                        </contact:addr>
                    </contact:postalInfo>"""


auth_info = "<contact:authInfo><contact:pw>%s</contact:pw></contact:authInfo>"


check = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <check>
            <contact:check xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                %(contacts)s
            </contact:check>
        </check>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""


info = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <info>
            <contact:info xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>%(contact_id)s</contact:id>
            </contact:info>
        </info>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""


create = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <create>
            <contact:create xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>%(contact_id)s</contact:id>
%(contact_fields)s
%(postal_infos)s
                %(auth_info)s
            </contact:create>
        </create>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""


update = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <update>
            <contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>%(contact_id)s</contact:id>
                <contact:chg>
%(contact_fields)s
%(postal_infos)s
                    %(auth_info)s
                </contact:chg>
            </contact:update>
        </update>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""


delete = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
        <delete>
            <contact:delete xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>%(contact_id)s</contact:id>
            </contact:delete>
        </delete>
        <clTRID>%(cltrid)s</clTRID>
    </command>
</epp>"""
