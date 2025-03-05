FROM quay.io/keycloak/keycloak:26.0.7


COPY ./target/keycloak-opa.jar /opt/keycloak/providers/keycloak-opa.jar
COPY ./dev/keycloak/providers/keycloak-restrict-client-auth.jar /opt/keycloak/providers/keycloak-restrict-client-auth.jar


ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev"]
