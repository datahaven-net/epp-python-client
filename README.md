# epp-python-client

[EPP](https://en.wikipedia.org/wiki/Extensible_Provisioning_Protocol) is Extensible Provisioning Protocol used for registrar-registry communication to register and manage domains.

The library provides an interface to the Extensible Provisioning Protocol:

- Python client library for sending/receiving/parsing XML-formatted EPP requests and responses
- RPC server running as intermediate gateway between consumer application and EPP registry
- RPC client library written for Python applications to be able to interract with the RPC server



## Install

	pip install --upgrade https://github.com/datahaven-net/epp-python-client/archive/master.zip



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



### RPC server & client

It is also possible to use the library in another way using intermediate RabbitMQ queue server.
If your application requires stable and reliable connection to the EPP registry system and be able to run many EPP requests per minute it is not possible to establish new EPP connection for each request using the only Python client.

There is an RPC server included in that library:

1. when RPC-server starts it first connects to the EPP back-end system via Python client library and holds the connection open after "greeting" and "login" command are processed
2. then it connects to the RabbitMQ server to be able to receive and process RPC calls from external applications
3. it also automatically reconnects to the EPP system when connection is closed on server side

To be able to run the server first you must create two text files holding credentials to your EPP registry system and RabbitMQ server:

###### epp_params.txt
	
	epp.your-registry.com 700 epp_login epp_password


###### rabbitmq_params.txt

	localhost 5672 rabbitmq_rpc_server_login rabbitmq_rpc_server_password


To start RPC server use the command above:

	epp-gate -v --reconnect --epp=epp_params.txt --rabbitmq=rabbitmq_params.txt --queue=epp_messages


Connection to the RPC server is carried out through RabbitMQ RPC-client also included in that library:

	from epp import rpc_client
	rpc_client.make_client(
		rabbitmq_credentials=('localhost', 5672, 'rabbitmq_rpc_client_login', 'rabbitmq_rpc_client_password', ),
		rabbitmq_queue_name='epp_messages',
	)
	print(rpc_client.cmd_domain_check(domains=["domain-possibly-exist.com", "another-domain.com", ]))
