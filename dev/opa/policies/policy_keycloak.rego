package keycloak.realms.opademo.access


import rego.v1
import data.keycloak.utils.kc



# Access Policy: Authentication
allow if{
	kc.isClient("DataProductManager")
	kc.isProtocol("openid-connect")
	kc.isRealm("opademo")
	kc.isGrantType("password")
	kc.hasRealmRole("admin")
}

allow if{
	kc.isClient("6G-CHRONOS-API")
	kc.isProtocol("openid-connect")
	kc.isRealm("opademo")
	kc.isGrantType("password")
}

# Access Policy: Onboard
allow if {
	kc.isRealm("opademo")
	kc.isClient("DataProductManager")
  	kc.hasRealmRole("admin")
	input.subject.username == "data_product_owner"
}

# Access Policy: ContextBroker
allow if {
	kc.isClient("ContextBroker")
	kc.isRealm("opademo")
	kc.isProtocol("openid-connect")
	kc.isGrantType("password")
  	kc.hasRealmRole("admin")
}

# Access Policy: Consume
allow if {
	kc.isClient("ContextBroker")
	kc.isRealm("opademo")
  	kc.hasRealmRole("admin")
}





# Access Policy: App2
# Allow access to client-id:app2 if client-role:access
allow if {
	kc.isClient("app2")
	kc.hasCurrentClientRole("access")
}

# Access Policy: App3
# Allow access to client-id:app3 if member of group
allow if {
	kc.isClient("app3")
	kc.isGroupMember("Users")
}


# Access Policy: "app6-check-network"
# Allow access to client based on remote network address (Forwarded header)
allow if {
	kc.isClient("app6-check-network")

	# "172.18.0.1/16"
	# 172.20.0.1/16
	kc.isFromNetwork("172.99.0.1/16")
}

# client ends with "-foo" or "-bar"
is_special_client(clientId) if endswith(clientId, "-foo")

is_special_client(clientId) if endswith(clientId, "-bar")

# use with is_account_client(input.resource.clientId)
is_account_client(clientId) if clientId in ["account", "account-console"]

# https://www.styra.com/blog/how-to-express-or-in-rego/
