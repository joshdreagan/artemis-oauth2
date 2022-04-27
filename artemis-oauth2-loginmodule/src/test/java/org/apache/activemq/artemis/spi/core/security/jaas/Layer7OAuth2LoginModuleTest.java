/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.activemq.artemis.spi.core.security.jaas;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Objects;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.jboss.logging.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

public class Layer7OAuth2LoginModuleTest {

  private static HttpServer httpServer;
  private static HttpsServer httpsServer;

  @Rule
  public TestRule watcher = new TestWatcher() {
    @Override
    protected void starting(Description description) {
      Logger log = Logger.getLogger(Layer7OAuth2LoginModuleTest.class);
      log.debugv("Starting test: ''{0}''", description.getMethodName());
    }
  };

  @BeforeClass
  public static void init() throws Exception {
    String path = System.getProperty("java.security.auth.login.config");
    if (path == null) {
      URL resource = Layer7OAuth2LoginModuleTest.class.getClassLoader().getResource("login.config");
      if (resource != null) {
        path = URLDecoder.decode(resource.getFile(), StandardCharsets.UTF_8);
        System.setProperty("java.security.auth.login.config", path);
      }
    }

    startServers();
  }

  @AfterClass
  public static void destroy() throws Exception {
    stopServers();
  }

  @Test(expected = LoginException.class)
  public void invalidUsername() throws Exception {
    LoginContext context = new LoginContext("Layer7OAuth2Login", new UserPassHandler("gcostanza", "bosco"));

    context.login();
  }

  @Test
  public void validToken() throws Exception {
    LoginContext context = new LoginContext("Layer7OAuth2Login", new UserPassHandler("oauth2", "bosco"));

    context.login();

    Subject subject = context.getSubject();

    assertEquals("Should have two principals", 2, subject.getPrincipals().size());
    assertEquals("Should have one user principal", 1, subject.getPrincipals(UserPrincipal.class).size());
    assertEquals("Should have one role principal", 1, subject.getPrincipals(RolePrincipal.class).size());

    context.logout();

    assertEquals("Should have zero principals", 0, subject.getPrincipals().size());
  }

  @Test
  public void validTokenMultipleScopes() throws Exception {
    LoginContext context = new LoginContext("Layer7OAuth2Login", new UserPassHandler("oauth2", "bosco2"));

    context.login();

    Subject subject = context.getSubject();

    assertEquals("Should have three principals", 3, subject.getPrincipals().size());
    assertEquals("Should have one user principal", 1, subject.getPrincipals(UserPrincipal.class).size());
    assertEquals("Should have two role principals", 2, subject.getPrincipals(RolePrincipal.class).size());

    context.logout();

    assertEquals("Should have zero principals", 0, subject.getPrincipals().size());
  }

  @Test(expected = LoginException.class)
  public void invalidToken() throws Exception {
    LoginContext context = new LoginContext("Layer7OAuth2Login", new UserPassHandler("oauth2", "ovaltine"));

    context.login();
  }

  @Test
  public void tlsSuccess() throws Exception {
    LoginContext context = new LoginContext("Layer7OAuth2LoginTLS", new UserPassHandler("oauth2", "bosco"));

    context.login();

    Subject subject = context.getSubject();

    assertEquals("Should have two principals", 2, subject.getPrincipals().size());
    assertEquals("Should have one user principal", 1, subject.getPrincipals(UserPrincipal.class).size());
    assertEquals("Should have one role principal", 1, subject.getPrincipals(RolePrincipal.class).size());

    context.logout();

    assertEquals("Should have zero principals", 0, subject.getPrincipals().size());
  }

  @Test(expected = LoginException.class)
  public void tlsInvalidCert() throws Exception {
    LoginContext context = new LoginContext("Layer7OAuth2LoginTLSBadCert", new UserPassHandler("oauth2", null));

    context.login();
  }

  @Test(expected = LoginException.class)
  public void tlsNonExistentTrustStorePath() throws Exception {
    LoginContext context = new LoginContext("Layer7OAuth2LoginNonExistentTrustStorePath", new UserPassHandler("oauth2", null));

    context.login();
  }

  private static class UserPassHandler implements CallbackHandler {

    private final String user;
    private final String pass;

    private UserPassHandler(final String user, final String pass) {
      this.user = user;
      this.pass = pass;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback) {
          ((NameCallback) callback).setName(user);
        } else if (callback instanceof PasswordCallback) {
          ((PasswordCallback) callback).setPassword(pass.toCharArray());
        } else {
          throw new UnsupportedCallbackException(callback);
        }
      }
    }
  }

  private static void startServers() throws Exception {
    String httpContext = "/oauth/validation/validate/v2/token/json";

    HttpHandler httpHandler = (HttpExchange httpExchange) -> {
      String password = httpExchange.getRequestHeaders().getFirst("Authorization");
      if (password == null) {
        password = "ovaltine";
      }
      password = password.replaceFirst("(?i)Bearer ", "");

      int responseCode = HttpURLConnection.HTTP_OK;
      String responseBodyType = "application/json";
      String responseBody = null;
      switch (password) {
        case "bosco":
          responseBody = "{\"resourceOwner\": \"gcostanza\", \"scope\": \"foo\"}";
          break;
        case "bosco2":
          responseBody = "{\"resourceOwner\": \"gcostanza\", \"scope\": \"foo bar\"}";
          break;
        case "ovaltine":
        default:
          responseCode = HttpURLConnection.HTTP_INTERNAL_ERROR;
          responseBodyType = "text/xml";
          responseBody = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body><soapenv:Fault><faultcode>soapenv:Server</faultcode><faultstring>Policy Falsified</faultstring><faultactor>https://qaesb.nscorp.com/oauth/validation/validate/v2/token/json</faultactor><detail><l7:policyResult xmlns:l7=\"http://www.layer7tech.com/ws/policy/fault\" status=\"Assertion Falsified\" /></detail></soapenv:Fault></soapenv:Body></soapenv:Envelope>";
      }

      httpExchange.getResponseHeaders().add("Content-Type", responseBodyType);
      byte[] responseBodyData = responseBody.getBytes(StandardCharsets.UTF_8);
      httpExchange.sendResponseHeaders(responseCode, responseBodyData.length);
      httpExchange.getResponseBody().write(responseBodyData);
      httpExchange.close();
    };

    httpServer = HttpServer.create(new InetSocketAddress("localhost", 9000), 0);
    httpServer.createContext(httpContext, httpHandler);
    httpServer.start();

    httpsServer = HttpsServer.create(new InetSocketAddress("localhost", 9001), 0);
    String keystoreFile = "server.ks";
    char[] keystorePassword = "changeit".toCharArray();
    SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
    KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
    try (InputStream in = Layer7OAuth2LoginModuleTest.class.getClassLoader().getResourceAsStream(keystoreFile)) {
      Objects.requireNonNull(in, String.format("Unable to locate keystore [%s].", keystoreFile));
      keystore.load(in, keystorePassword);
    }
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keystore, keystorePassword);
    sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
    httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
    httpsServer.createContext(httpContext, httpHandler);
    httpsServer.start();
  }

  private static void stopServers() throws Exception {
    if (httpServer != null) {
      httpServer.stop(0);
    }

    if (httpsServer != null) {
      httpsServer.stop(0);
    }

  }

  public static void main(String[] args) throws Exception {
    startServers();
    while (true) {
      Thread.sleep(5000L);
    }
  }
}
