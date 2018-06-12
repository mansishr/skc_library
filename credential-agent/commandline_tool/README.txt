
For starting the script please use bellow command:

./cred_init.sh <SCOPE_NAME> 

cred_init.sh do the following things:
	- Read the scope name as part of commandline-argument
	- Create scope and token batch ( token count = 1 ) batch for that scope
	- read token value 
	- Generetates Credential Agent URL and call cred_agent.sh ( It has CECS IP variable ( as of now need to move config ./config/main.conf ))

cred_agent.sh do the following things:
	- Read Cred URL and token as part of commandline-argument
	- Create csr and private key
	- sign and genrate cert
	- renew certificate
