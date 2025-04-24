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

allow if{
	kc.isClient("CCIPS")
	kc.isProtocol("openid-connect")
	kc.isRealm("opademo")
	kc.isGrantType("password")
}


