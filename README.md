# epp-python-client

[EPP](https://en.wikipedia.org/wiki/Extensible_Provisioning_Protocol) is Extensible Provisioning Protocol used for registrar-registry communication to register and manage domains.

The library provides an interface to the Extensible Provisioning Protocol:

- Python client library for sending/receiving/parsing XML-formatted EPP requests and responses
- RPC server running as intermediate gateway between consumer application and EPP registry
- RPC client library written for Python applications to be able to interact with the RPC server



## Install & Update

	pip install --upgrade --no-cache-dir https://github.com/datahaven-net/epp-python-client/archive/master.zip



## Usage

### Python client

	from epp import epp_client
	conn = epp_client.EPPConnection(
		host='localhost',
		port=700,
		user='epp_user_01',
		password='some_secret',
		verbose=True,
	)
	conn.open()
	print(conn.domain_check(domain_name='domain-may-not-exist.com'))
	conn.close()


The client is using `beautifulsoup4` to parse XML responses into Python objects. It is possible to access each element of the EPP response directly:

	from epp import epp_client
	conn = epp_client.EPPConnection(
		host='localhost',
		port=700,
		user='epp_user_01',
		password='some_secret',
		verbose=True,
		return_soup=True,
	)
	conn.open()
	print(conn.domain_check(domain_name='domain-possibly-exist.com').find('response').resdata.find('domain:name').get('avail') == '0')
	conn.close()



### RPC server

It is also possible to use the library in another way using an intermediate RabbitMQ queue server.
If your application requires stable and reliable connection to the EPP registry system and be able to run many EPP 
requests per minute it is not possible to establish new EPP connection for each request using only the Python client.

There is an RPC server and client library included in that repository:

1. when RPC-server starts it first connects to the EPP back-end system via Python client library and holds the connection open after `greeting` and `login` EPP commands are processed
2. then it connects to the RabbitMQ server to be able to receive and process RPC calls from external applications
3. it also automatically reconnects to the EPP system when connection is closed on server side

To be able to run the server first you must create two text files holding credentials to your EPP registry system and RabbitMQ server separately:

###### epp_params.txt
	
	epp.your-registry.com 700 epp_login epp_password


###### rabbitmq_params.txt

	localhost 5672 rabbitmq_rpc_server_login rabbitmq_rpc_server_password


To start RPC server locally use the command above:

	epp-gate -v --reconnect --epp=epp_params.txt --rabbitmq=rabbitmq_params.txt --queue=epp_messages


Read bellow to learn how to install and configure RabbitMQ service and how to run EPP Gate RPC server as a systemd Unix service.



### RPC client

Connection to the RPC server is carried out through RabbitMQ RPC-client, which is also included in that repo.

The interface between RPC server and RPC client was built using simple JSON-formatted requests and responses.

RPC client requests consists of two tags that defines the name of the EPP command to be sent and list of input parameters:

	{
        "cmd": "domain_info",
        "args": {
            "name": "mydomain.com"
        }
    }

Via RabbitMQ service the request is delivered to the RPC server, which is holding connection to the EPP system and able to
dispatch the command to the domain name rgistry server right away.

The JSON-formatted request is first translated into XML request according to EPP RFC specification by the Python client library.
Python client also receives response back from the EPP system in XML format. More information about the EPP specification can be found in those papers:

+ https://tools.ietf.org/html/rfc5730
+ https://tools.ietf.org/html/rfc5731
+ https://tools.ietf.org/html/rfc5732
+ https://tools.ietf.org/html/rfc5733


RPC server translates XML responses from the back-end EPP system into JSON-formatted messages using `xml2json` library: https://gist.github.com/anonymous/4328681

Here is a sample response from `domain info` EPP command request that RPC server sends back to the RPC client via RabbitMQ service:

    {"epp": {"@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation": "urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd", "response": {"extension": {"infData": {"@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation": "urn:ietf:params:xml:ns:rgp-1.0 rgp-1.0.xsd"} }, "resData": {"infData": {"@{http://www.w3.org/2001/XMLSchema-instance}schemaLocation": "urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd", "authInfo": {"pw": "Authinfo Incorrect"}, "clID": "Redacted", "contact": [{"#text": "billing01", "@type": "billing"}, {"#text": "admin02", "@type": "admin"}, {"#text": "tech03", "@type": "tech"} ], "crDate": "2020-03-11T09:33:38.698Z", "crID": "Redacted", "exDate": "2024-03-11T09:33:38.756Z", "name": "mydomain.com", "ns": {"hostObj": ["ns1.google.com", "ns2.google.com"] }, "registrant": "registrant01", "roid": "registrar_xyz", "status": {"#text": "Active", "@s": "ok"}, "upDate": "2020-03-17T00:00:00.607Z", "upID": "Redacted"} }, "result": {"@code": "1000", "msg": "Command completed successfully"}, "trID": {"clTRID": "c5bc8f94103f1a47019a09049dff5aec", "svTRID": "1618822341053"}}}}


### How to use RPC client

You can pass RabbitMQ connection parameters directly while making RPC request using input parameters:

    from epp import rpc_client
    response = rpc_client.cmd_domain_check(
        domains=["domain-possibly-exist.com", "another-domain.com", ],
        rabbitmq_credentials=('localhost', 5672, 'rabbitmq_rpc_client_login', 'rabbitmq_rpc_client_password', ),
        rabbitmq_queue_name='epp_rpc_messages',
    )
    print(response)


Another way to pass sensitive info to the client is via environment variable `RPC_CLIENT_CONF_PATH`.
Environment variable `RPC_CLIENT_CONF_PATH` must store the local path to a JSON-formatted configuration file:

###### rpc_client_conf.json

    {
        "host": "localhost",
        "port": "5672",
        "username": "rabbitmq_rpc_client_login",
        "password": "rabbitmq_rpc_client_password",
        "timeout": 5,
        "queue_name": "epp_rpc_messages"
    }


This way you can test your RPC connection via command line:

    cd epp-python-client/
    PYTHONPATH=src RPC_CLIENT_CONF_PATH=/home/user/rpc_client_conf.json RPC_CLIENT_HEALTH_FILE=/home/user/health python -c 'import epp.rpc_client; print(epp.rpc_client.cmd_domain_check(["testdomain.com", ]))'


### Install and configure RabbitMQ

RabbitMQ is used to drive a EPP messaging queue between consumer application and EPP registry system using RPC server and client.

Use Apt package manager to install RabbitMQ server on your host:

    echo "deb https://www.rabbitmq.com/debian testing main" | sudo tee /etc/apt/sources.list.d/rabbitmq.list
    wget -O- https://www.rabbitmq.com/rabbitmq-release-signing-key.asc | sudo apt-key add -
    sudo apt-get update
    sudo apt-get install rabbitmq-server
    sudo rabbitmq-plugins enable rabbitmq_management


We need to have secure way to access RabbitMQ administrator panel, so must create a separate user account for that purpose:

    sudo rabbitmqctl add_user rabbitmq_rpc_client_login rabbitmq_rpc_client_password
    sudo rabbitmqctl set_user_tags rabbitmq_rpc_client_login administrator
    sudo rabbitmqctl set_permissions -p / rabbitmq_rpc_client_login ".*" ".*" ".*"


Another user account we will use for EPP message queue between your application and EPP registry:

    sudo rabbitmqctl add_user rabbitmq_rpc_server_login rabbitmq_rpc_server_password
    sudo rabbitmqctl set_permissions -p / rabbitmq_rpc_server_login ".*" ".*" ".*"


Now you can navigate your web browser to RabbitMQ dashboard at `http://www.yourdomain.com:15672` and
login with `rabbitmq_rpc_client_login`:`rabbitmq_rpc_client_password` administrative credentials you have just created.

You can verify permissions of RabbitMQ users - must be 3 users existing:

* guest
* rabbitmq_rpc_client_login
* rabbitmq_rpc_server_login


We advise you to remove "guest" user because of security concerns.

More details about RabbutMQ installation you can find here: https://www.rabbitmq.com/install-debian.html

For local development you might want to run RabbutMQ manually instead of starting it as a system service.
In that case you just run a local server from Makefile and then you can open RabbitMQ dashboard at `http://localhost:15672`:

    make rabbitmq_server_dev



## Configure EPP Gate as a systemd Unix service

To be able to easily manage EPP Gate process on your host system you can add it to your systemd scripts.

EPP Gate service consist of 3 units:

* `epp-gate.service` : service which executes RPC server and keep it running non-stop
* `epp-gate-watcher.service` : background service which is able to "restart" `epp-gate.service` when required
* `epp-gate-health.path` : systemd trigger which is monitoring `/home/user/health` file for any modifications and notify `epp-gate-watcher.service`

Those three units are required to have EPP Gate auto-healing mechanism running all the time.
When EPP back-end registry system drops connection on server-side EPP Gate needs to be "restarted" and be reconnected to the back-end.
It must re-login to be able to send EPP messages again - this is done inside RPC server and login flow will be initiated automatically.

All of the requred systemd files are also inclided in this repository, see example files in `etc/` sub-folder.

You can configure systemd EPP Gate service this way:

        cd epp-python-client
        mkdir -p /home/user/.config/systemd/user/
        cp etc/systemd/system/epp-gate.service.example /home/user/.config/systemd/user/epp-gate.service
        cp etc/systemd/system/epp-gate-watcher.service.example /home/user/.config/systemd/user/epp-gate-watcher.service
        cp etc/systemd/system/epp-gate-health.path.example /home/user/.config/systemd/user/epp-gate-health.path
        systemctl --user enable epp-gate.service
        systemctl --user enable epp-gate-watcher.service
        systemctl --user enable epp-gate-health.path


Then you just need to start all services at once:

        systemctl --user start epp-gate.service
        systemctl --user start epp-gate-watcher.service
        systemctl --user start epp-gate-health.path


You can always check current situation with:

        systemctl --user status epp-gate.service


Also you can check services logs to see full history:

        journalctl -f -u user@`id -u`.service


Now if you have access to EPP backend you can test auto-healing mechanism by simply dropping EPP session on server side and keep monitoring `/home/user/logs/gate.log` output file.

Also you can perform manual test locally - just modify `/home/user/health` file and EPP Gate process suppose to be restarted automatically.



### Contributing

Please go to [epp-client-python GitHub repository](https://github.com/datahaven-net/epp-python-client), click "Fork", and clone your fork repository via git+ssh link:

        git clone git@github.com:< your GitHub username here >/epp-python-client.git


Then you need to add main repo as "upstream" source via HTTPS link (in read-only mode):

        cd epp-python-client
        git remote add upstream https://github.com/datahaven-net/epp-python-client.git


Your currently forked repository remains as "origin", and you should always commiting and pushing to your own code base:

        # after you made some modifications, for example in README.md
        git add README.md
        git commit -m "updated documentation"
        git push origin master


Then you start a [new Pull Request](https://github.com/datahaven-net/epp-python-client/compare) towards main repository, you can click "compare across forks" link to select your own repository source in "head fork" drop down list. Then you will see the changes you are going to introduce to epp-python-client code and will be able to start a Pull Request.

As soon as your Pull Request was merged, you can refresh your local files and "origin" repository:

        git pull upstream master
        git push origin master


Please cooperate with the maintainers to make your changes Approved and Merged into the main repository.
