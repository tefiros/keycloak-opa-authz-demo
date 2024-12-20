package itrust6g


import rego.v1

# Access Policy: Default
# Default allow rule: deny all
default allow = false

is_post if input.request.method == "POST"
is_maintainer if claims.preferred_username == "maintainer"
is_admin if claims.realm_access.roles[_] == "admin"
allow if {
    is_post
    is_maintainer
    is_admin
	input.request.path == "/ccips"
}

claims := payload if {
	# Verify the signature on the Bearer token. In this example the secret is
	# hardcoded into the policy however it could also be loaded via data or
	# an environment variable. Environment variables can be accessed using
	# the `opa.runtime()` built-in function.
	io.jwt.verify_rs256(bearer_token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyHlybc7qW3DKk9YQdpzsO5MRNQhi8R/1ag1iSWfoCX2Qy2Ul4hqKtxNizOZgrwZ2zfjzl4tSvp3vln1gXnVIk59X1Vw/0mz5mJFC1wJaa3+mpErEzx5h4bKyce7b1lV5RRq3pKvRtVEZGNS9r77RTSD/mENE6i1b2hiD7gSO1FkGXYx3HYUm5Xjr1C9sRnn1zJWMlqrlnBH/+Le4BmtiXZQITX+WeXkG+Tz5Nlhci4O70OHcWR/adzf7811Kk9jHNMyxe6k9CbPQkbDffqv18vcVanCZs6S9kbuJokpYVduZnI/M7mtGublK/HpDq7rfD54ipVWvUsLmXJKYSIEtlwIDAQAB\n-----END PUBLIC KEY-----")

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

