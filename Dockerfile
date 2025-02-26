FROM quay.io/keycloak/keycloak:24.0.2


COPY ./target/keycloak-opa.jar /opt/keycloak/providers/keycloak-opa.jar
COPY ./dev/keycloak/providers/keycloak-restrict-client-auth.jar /opt/keycloak/providers/keycloak-restrict-client-auth.jar


ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev", "--verbose", "--metrics-enabled=true", "--health-enabled=true", "--features=preview", "--spi-events-listener-jboss-logging-success-level=info", "--spi-events-listener-jboss-logging-error-level=warn", "--log-level=INFO,com.thomasdarimont.keycloak:DEBUG,org.keycloak.services.clientpolicy:DEBUG", "--spi-access-policy-opa-url=http://access-control-opa:8181/v1/data", "--spi-access-policy-opa-policy-path=/keycloak/realms/{realm}/{action}/allow", "--spi-access-policy-opa-context-attributes=remoteAddress,protocol,grantType", "--spi-access-policy-opa-user-attributes=email,emailVerified", "--spi-access-policy-opa-request-headers=Authorization,Content-Type,Custom-Header"]
