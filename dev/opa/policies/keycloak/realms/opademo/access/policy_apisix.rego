package apisix


import rego.v1

# Access Policy: Default
# Default allow rule: deny all
default allow = false


allow if {
	is_get
	is_entities
	claims.preferred_username == "maintainer"

}

is_get if input.request.method == "GET"

is_entities if input.request.path == "/ngsi-ld/v1/entities"

claims := payload if {
	# Verify the signature on the Bearer token. In this example the secret is
	# hardcoded into the policy however it could also be loaded via data or
	# an environment variable. Environment variables can be accessed using
	# the `opa.runtime()` built-in function.
	# io.jwt.verify_rs256(bearer_token, "/")

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

