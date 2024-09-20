package apisix


import rego.v1

# Access Policy: Default
# Default allow rule: deny all
default allow = false


allow if {
	is_get
	is_entities
	claims.preferred_username == "maintainer"
	is_Store
}

is_get if input.request.method == "GET"

is_entities if input.request.path == "/ngsi-ld/v1/entities"
is_Store if input.request.query.q == "storeName==\"Luxury Store\""

claims := payload if {
	# Verify the signature on the Bearer token. In this example the secret is
	# hardcoded into the policy however it could also be loaded via data or
	# an environment variable. Environment variables can be accessed using
	# the `opa.runtime()` built-in function.
	io.jwt.verify_rs256(bearer_token, "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhAj9OCZd0XjzOIad2VbUPSMoVK1X8hdD2Ad+jUXCzhZJf0RaN6B+79AW5jSgceAgyAtLXiBayLlaqSjZM6oyti9gc2M2BXzoDKLye+Tgpftd72Zreb4HpwKGpVrJ3H3Ip5DNLSD4a1ovAJ6Sahjb8z34T8c1OCnf5j70Y7i9t3y/j076XIUU4vWpAhI9LRAOkSLqDUE5L/ZdPmwTgK91Dy1fxUQ4d02Ly4MTwV2+4OaEHhIfDSvakLBeg4jLGOSxLY0y38DocYzMXe0exJXkLxqHKMznpgGrbps0TPfSK0c3q2PxQLczCD3n63HxbN8U9FPyGeMrz59PPpkwIDAQAB
-----END PUBLIC KEY-----")

	# This statement invokes the built-in function `io.jwt.decode` passing the
	# parsed bearer_token as a parameter. The `io.jwt.decode` function returns an
	# array:
	#
	#	[header, payload, signature]
	#
	# In Rego, you can pattern match values using the `=` and `:=` operators. This
	# example pattern matches on the result to obtain the JWT payload.
	[_, payload, _] := io.jwt.decode(bearer_token)
}

bearer_token := t if {
	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v = input.request.headers.authorization
	startswith(v, "Bearer ")
	t = substring(v, count("Bearer "), -1)
}

status_code := 200 if {
	allow
} else := 403

