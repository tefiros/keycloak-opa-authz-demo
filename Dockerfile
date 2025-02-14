FROM quay.io/keycloak/keycloak:24.0.2

# Copiar los JARs necesarios
COPY ./target/keycloak-opa.jar /opt/keycloak/providers/keycloak-opa.jar
COPY ./dev/keycloak/providers/keycloak-restrict-client-auth.jar /opt/keycloak/providers/keycloak-restrict-client-auth.jar

# Definir el ENTRYPOINT con los parámetros adicionales
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev", "--verbose", "--http-enabled=true", "--http-port=8080",  "--metrics-enabled=true", "--health-enabled=true", "--cache=local", "--proxy=edge", "--features=preview", "--spi-events-listener-jboss-logging-success-level=info", "--spi-events-listener-jboss-logging-error-level=warn", "--log-level=INFO,com.thomasdarimont.keycloak:DEBUG,org.keycloak.services.clientpolicy:DEBUG", "--spi-access-policy-opa-url=http://keycloak-opa:8181/v1/data", "--spi-access-policy-opa-policy-path=/keycloak/realms/{realm}/{action}/allow", "--spi-access-policy-opa-context-attributes=remoteAddress,protocol,grantType", "--spi-access-policy-opa-user-attributes=email,emailVerified", "--spi-access-policy-opa-request-headers=Authorization,Content-Type,Custom-Header"]
