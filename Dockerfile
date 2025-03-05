FROM quay.io/keycloak/keycloak:24.0.2


COPY ./target/keycloak-opa.jar /opt/keycloak/providers/keycloak-opa.jar
COPY ./dev/keycloak/providers/keycloak-restrict-client-auth.jar /opt/keycloak/providers/keycloak-restrict-client-auth.jar

EXPOSE 8080
EXPOSE 8443
EXPOSE 9000

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
