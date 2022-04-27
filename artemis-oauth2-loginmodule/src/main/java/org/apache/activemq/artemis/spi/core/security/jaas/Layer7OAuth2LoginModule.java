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

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import org.jboss.logging.Logger;

import static org.apache.activemq.artemis.spi.core.security.jaas.Layer7OAuth2LoginModuleProperties.*;

/**
 * Layer7 OAuth2 LoginModule
 * https://docs.oracle.com/en/java/javase/11/security/java-authentication-and-authorization-service-jaas-loginmodule-developers-guide1.html#GUID-EE1C4BBE-289F-4419-A233-43F2D897765B
 */
public class Layer7OAuth2LoginModule implements AuditLoginModule {

  private static final Logger log = Logger.getLogger(Layer7OAuth2LoginModule.class);

  private Subject subject;
  private CallbackHandler callbackHandler;

  private Layer7OAuth2LoginModuleProperties properties;

  private boolean debug;
  private boolean debugMaskPasswords;

  private SSLContext sslContext;

  private URL tokenAuthenticationUrl;

  private Set<String> validUsernames;

  private String username;
  private final Set<String> roles = new HashSet<>();
  private final Set<Principal> principals = new HashSet<>();
  private boolean loginSucceeded;
  private boolean commitSucceeded;
  private boolean abortSucceeded;

  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
    this.subject = subject;
    this.callbackHandler = callbackHandler;

    this.username = null;
    this.roles.clear();
    this.principals.clear();
    this.loginSucceeded = false;
    this.commitSucceeded = false;
    this.abortSucceeded = false;

    properties = new Layer7OAuth2LoginModuleProperties(options);

    debug = properties.getOptionalOrDefault(DEBUG_ENABLED_PROPERTY, Boolean.class, false);
    debugMaskPasswords = properties.getOptionalOrDefault(DEBUG_MASK_PASSWORD_PROPERTY, Boolean.class, true);

    tokenAuthenticationUrl = properties.getRequired(TOKEN_AUTHORIZATION_URL_PROPERTY, URL.class);
    log("{0}={1}", TOKEN_AUTHORIZATION_URL_PROPERTY, tokenAuthenticationUrl);

    validUsernames = properties.getOptionalOrDefault(VALID_USERNAMES_PROPERTY, Set.class, Collections.singleton("oauth2"));
    log("{0}={1}", VALID_USERNAMES_PROPERTY, validUsernames);

    if ("https".equals(this.tokenAuthenticationUrl.getProtocol())) {
      try {
        String sslAlgorithm = properties.getOptionalOrDefault(SSL_ALGORITHM_PROPERTY, String.class, "TLSv1.2");
        log("{0}={1}", SSL_ALGORITHM_PROPERTY, sslAlgorithm);
        Path keyStore = properties.getOptional(KEY_STORE_PROPERTY, Path.class);
        log("{0}={1}", KEY_STORE_PROPERTY, keyStore);
        char[] keyStorePassword = properties.getOptional(KEY_STORE_PASSWORD_PROPERTY, char[].class);
        log("{0}={1}", KEY_STORE_PASSWORD_PROPERTY, (debugMaskPasswords) ? "******" : (keyStorePassword != null) ? String.valueOf(keyStorePassword) : "null");
        String keyStoreType = properties.getOptionalOrDefault(KEY_STORE_TYPE_PROPERTY, String.class, KeyStore.getDefaultType());
        log("{0}={1}", KEY_STORE_TYPE_PROPERTY, keyStoreType);
        Path trustStore = properties.getOptional(TRUST_STORE_PROPERTY, Path.class);
        log("{0}={1}", TRUST_STORE_PROPERTY, trustStore);
        char[] trustStorePassword = properties.getOptional(TRUST_STORE_PASSWORD_PROPERTY, char[].class);
        log("{0}={1}", TRUST_STORE_PASSWORD_PROPERTY, (debugMaskPasswords) ? "******" : (trustStorePassword != null) ? String.valueOf(trustStorePassword) : "null");
        String trustStoreType = properties.getOptionalOrDefault(TRUST_STORE_TYPE_PROPERTY, String.class, KeyStore.getDefaultType());
        log("{0}={1}", TRUST_STORE_TYPE_PROPERTY, trustStoreType);

        sslContext = SSLContext.getInstance(sslAlgorithm);

        KeyManager[] keyManagers = null;
        if (keyStore != null) {
          KeyStore ks = KeyStore.getInstance(keyStoreType);
          try (InputStream ksin = Files.newInputStream(keyStore)) {
            ks.load(ksin, keyStorePassword);
          }
          KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
          kmf.init(ks, keyStorePassword);
          keyManagers = kmf.getKeyManagers();
        }

        TrustManager[] trustManagers = null;
        if (trustStore != null) {
          KeyStore ts = KeyStore.getInstance(trustStoreType);
          try (InputStream tsin = Files.newInputStream(trustStore)) {
            ts.load(tsin, trustStorePassword);
          }
          TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
          tmf.init(ts);
          trustManagers = tmf.getTrustManagers();
        }

        sslContext.init(keyManagers, trustManagers, new SecureRandom());
      } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyManagementException | KeyStoreException | IOException | CertificateException e) {
        throw new RuntimeException(String.format("Unable to create SSL context: ", e.getMessage()));
      }
    }
  }

  @Override
  public boolean login() throws LoginException {
    Callback[] callbacks = new Callback[2];

    callbacks[0] = new NameCallback("Username: ");
    callbacks[1] = new PasswordCallback("Password: ", false);
    try {
      callbackHandler.handle(callbacks);
    } catch (IOException | UnsupportedCallbackException e) {
      throw new LoginException(e.getMessage());
    }
    username = ((NameCallback) callbacks[0]).getName();
    String password = String.valueOf(((PasswordCallback) callbacks[1]).getPassword());
    log("Login called for ''{0}''/''{1}''.", username, (debugMaskPasswords) ? "******" : password);

    if (!validUsernames.contains(username)) {
      loginSucceeded = false;
    } else {
      HttpURLConnection urlConnection = null;
      try {
        urlConnection = (HttpURLConnection) tokenAuthenticationUrl.openConnection();
        if (urlConnection instanceof HttpsURLConnection) {
          HttpsURLConnection sslUrlConnection = (HttpsURLConnection) urlConnection;
          sslUrlConnection.setSSLSocketFactory(sslContext.getSocketFactory());
        }
        urlConnection.setRequestMethod("GET");
        urlConnection.setDoOutput(true);
        urlConnection.setRequestProperty("Accept", "*/*");
        urlConnection.setRequestProperty("Authorization", "Bearer " + password);
        log("Making http request to url ''{0}''.", tokenAuthenticationUrl);
        int httpResponseCode = urlConnection.getResponseCode();
        log("Got an http response code of ''{0}'' from url ''{1}''.", httpResponseCode, tokenAuthenticationUrl);
        if (httpResponseCode >= 200 && httpResponseCode <= 299) {
          try (InputStream httpResponseBodyStream = urlConnection.getInputStream()) {
            DocumentContext httpResponseBodyContext = JsonPath.parse(httpResponseBodyStream);
            log("The raw json http response content for user ''{0}'' is ''{1}''.", username, httpResponseBodyContext.jsonString());
            String scopeContent = httpResponseBodyContext.read("$.scope", String.class);
            log("The raw scope content for user ''{0}'' is ''{1}''.", username, scopeContent);
            if (scopeContent != null && !scopeContent.isBlank()) {
              for (String scope : scopeContent.split("\\s")) {
                roles.add(scope);
              }
            }
          }
        } else {
          throw new FailedLoginException(String.format("Unable to validate token authorization. HTTP response code: [%s].", httpResponseCode));
        }
      } catch (IOException e) {
        throw new FailedLoginException(String.format("Unable to validate token authorization: %s.", e.getMessage()));
      } finally {
        if (urlConnection != null) {
          urlConnection.disconnect();
        }
      }
      loginSucceeded = true;
    }

    return loginSucceeded;
  }

  @Override
  public boolean commit() throws LoginException {
    log("Commit called for ''{0}''.", username);
    if (loginSucceeded) {
      log("Adding user principal for ''{0}''.", username);
      principals.add(new UserPrincipal(username));
      for (String role : roles) {
        log("Adding role principal for user ''{0}'', role ''{1}''.", username, role);
        principals.add(new RolePrincipal(role));
      }
      subject.getPrincipals().addAll(principals);
      commitSucceeded = true;
    } else {
      commitSucceeded = false;
    }
    clear();
    return commitSucceeded;
  }

  @Override
  public boolean abort() throws LoginException {
    log("Abort called for ''{0}''.", username);
    if (loginSucceeded) {
      registerFailureForAudit(username);
      abortSucceeded = true;
    } else {
      abortSucceeded = false;
    }
    clear();
    return abortSucceeded;
  }

  @Override
  public boolean logout() throws LoginException {
    log("Logout called for ''{0}''.", username);
    subject.getPrincipals().removeAll(principals);
    clearAll();
    return true;
  }

  private void clear() {
    roles.clear();
  }

  private void clearAll() {
    clear();
    username = null;
    loginSucceeded = false;
    commitSucceeded = false;
    abortSucceeded = false;
    principals.clear();
  }

  private void log(String format, Object... params) {
    if (debug && log.isDebugEnabled()) {
      log.debugv(format, params);
    }
  }
}
