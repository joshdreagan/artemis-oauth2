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

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jboss.logging.Logger;

public final class Layer7OAuth2LoginModuleProperties {

  private static final Logger log = Logger.getLogger(Layer7OAuth2LoginModuleProperties.class);

  private static final String DEBUG_PROPERTIES_PREFIX = "debug";
  
  public static final String DEBUG_ENABLED_PROPERTY = DEBUG_PROPERTIES_PREFIX;
  public static final String DEBUG_MASK_PASSWORD_PROPERTY = DEBUG_PROPERTIES_PREFIX + ".maskPasswords";
  
  private static final String PROPERTIES_PREFIX = "org.apache.activemq.jaas.oauth2";

  public static final String TOKEN_AUTHORIZATION_URL_PROPERTY = PROPERTIES_PREFIX + ".tokenAuthorizationUrl";

  public static final String VALID_USERNAMES_PROPERTY = PROPERTIES_PREFIX + ".validUsernames";

  public static final String SSL_ALGORITHM_PROPERTY = PROPERTIES_PREFIX + ".sslAlgorithm";
  public static final String KEY_STORE_PROPERTY = PROPERTIES_PREFIX + ".keyStore";
  public static final String KEY_STORE_PASSWORD_PROPERTY = PROPERTIES_PREFIX + ".keyStorePassword";
  public static final String KEY_STORE_TYPE_PROPERTY = PROPERTIES_PREFIX + ".keyStoreType";
  public static final String TRUST_STORE_PROPERTY = PROPERTIES_PREFIX + ".trustStore";
  public static final String TRUST_STORE_PASSWORD_PROPERTY = PROPERTIES_PREFIX + ".trustStorePassword";
  public static final String TRUST_STORE_TYPE_PROPERTY = PROPERTIES_PREFIX + ".trustStoreType";

  private final Map<String, ?> properties;

  public Layer7OAuth2LoginModuleProperties(Map<String, ?> properties) {
    this.properties = properties;
  }

  public Map<String, ?> getProperties() {
    return properties;
  }

  public String getRequired(String key) {
    return getRequired(key, String.class);
  }

  public <T> T getRequired(String key, Class<T> type) {
    return Objects.requireNonNull(getOptional(key, type), String.format("The %s property must not be null.", key));
  }

  public String getOptional(String key) {
    return getOptional(key, String.class);
  }

  public <T> T getOptional(String key, Class<T> type) {
    return getOptionalOrDefault(key, type, null);
  }

  public String getOptionalOrDefault(String key, String defaultValue) {
    return getOptionalOrDefault(key, String.class, defaultValue);
  }

  public <T> T getOptionalOrDefault(String key, Class<T> type, T defaultValue) {
    Objects.requireNonNull(key, "The key argument must not be null.");
    Objects.requireNonNull(type, "The type argument must not be null.");

    T result = null;
    String value = (String) properties.get(key);
    if (value == null) {
      return defaultValue;
    }

    if (type.isAssignableFrom(String.class)) {
      result = type.cast(value);
    } else if (type.isAssignableFrom(Boolean.class)) {
      result = type.cast(Boolean.parseBoolean(value));
    } else if (type.isAssignableFrom(char[].class)) {
      result = type.cast(value.toCharArray());
    } else if (type.isAssignableFrom(Path.class)) {
      result = type.cast(new File(value).toPath());
    } else if (type.isAssignableFrom(Set.class)) {
      result = type.cast(new HashSet<>(Arrays.asList(value.split("[\\s,]"))));
    } else if (type.isAssignableFrom(List.class)) {
      result = type.cast(Arrays.asList(value.split("[\\s,]")));
    } else if (type.isAssignableFrom(URL.class)) {
      try {
        result = type.cast(new URL(value));
      } catch (MalformedURLException e) {
        throw new IllegalArgumentException(String.format("Invalid value [%s] for property [%s].", value, key), e);
      }
    } else {
      throw new IllegalArgumentException(String.format("Unknown type [%s].", type));
    }
    
    return result;
  }
}
