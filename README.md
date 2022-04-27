# artemis-oauth2

## Building the code

```
cd $PROJECT_ROOT
mvn clean install
```

## Testing

This project includes a mock Layer7 OAuth2 server. To run it, use the following command.

```
cd $PROJECT_ROOT/artemis-oauth2-loginmodule
mvn exec:java
```

Valid password/client_secret values are as listed:

  - "bosco" : Returns a valid authorization with a single scope.
  - "bosco2" : Returns a valid authorization with multiple scopes.
  - "ovaltine" : Returns and invalid authorization.

## Configuration the Artemis Server

Export the public key from the Layer7 server.

```
keytool -export -rfc -keystore $LAYER7_KEYSTORE -alias $LAYER7_SERVER_KEY -file $PROJECT_ROOT/oauth2-server.crt
```

Create/import public key into a trust store.

```
keytool -import -file $PROJECT_ROOT/oauth2-server.crt -keystore $ARTEMIS_INSTANCE/etc/broker.ts
```

Modify the `$ARTEMIS_INSTANCE/etc/login.config` file to match the following.

```
  org.apache.activemq.artemis.spi.core.security.jaas.PropertiesLoginModule sufficient
    debug=true
    org.apache.activemq.jaas.properties.user="artemis-users.properties"
    org.apache.activemq.jaas.properties.role="artemis-roles.properties"
  ;

  org.apache.activemq.artemis.spi.core.security.jaas.Layer7OAuth2LoginModule requisite
    debug=true
    org.apache.activemq.jaas.oauth2.validUsernames="oauth2"
    org.apache.activemq.jaas.oauth2.tokenAuthorizationUrl="https://localhost:9001/oauth/validation/validate/v2/token/json"
    org.apache.activemq.jaas.oauth2.trustStore="${artemis.instance}/etc/broker.ts"
    org.apache.activemq.jaas.oauth2.trustStorePassword="abcd1234"
  ;
```

** ___Replace the values to match your env.___

Modify the `$ARTEMIS_INSTANCE/etc/broker.xml` file to include the appropriate `<security-setting .../>` elements. For example:

```
<security-setting match="foo.#">
  <permission type="createNonDurableQueue" roles="amq,foo"/>
  <permission type="deleteNonDurableQueue" roles="amq,foo"/>
  <permission type="createDurableQueue" roles="amq,foo"/>
  <permission type="deleteDurableQueue" roles="amq,foo"/>
  <permission type="createAddress" roles="amq,foo"/>
  <permission type="deleteAddress" roles="amq,foo"/>
  <permission type="consume" roles="amq,foo"/>
  <permission type="browse" roles="amq,foo"/>
  <permission type="send" roles="amq,foo"/>
  <permission type="manage" roles="amq,foo"/>
</security-setting>
```
