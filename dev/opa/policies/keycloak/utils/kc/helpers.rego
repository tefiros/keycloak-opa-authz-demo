package keycloak.utils.kc

import rego.v1

isRealm(realmName) if input.resource.realm == realmName

isClient(clientId) if input.resource.clientId == clientId

hasRealmRole(roleName) if roleName in input.subject.realmRoles

hasClientRole(clientId, roleName) := result if {
	# clientId:client-role
	client_role := concat(":", [clientId, roleName])
	result := client_role in input.subject.clientRoles
}

hasCurrentClientRole(roleName) := result if {
	# clientId:client-role
	client_role := concat(":", [input.resource.clientId, roleName])
	result := client_role in input.subject.clientRoles
}

hasUserAttribute(attributes, attribute) if attributes[attribute]

hasUserAttributeValue(attributes, attribute, value) if attributes[attribute] == value

isGroupMember(group) if group in input.subject.groups

# see https://www.openpolicyagent.org/docs/latest/policy-reference/#net
isFromNetwork(cidr) if net.cidr_contains(cidr, input.context.attributes.remoteAddress)

isProtocol(protocol) if protocol = input.context.attributes.protocol

isGrantType(grantType) if grantType = input.context.attributes.grantType
